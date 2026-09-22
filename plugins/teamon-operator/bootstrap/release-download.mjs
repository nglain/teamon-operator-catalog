import {verifyReleaseMetadata} from './release-trust.mjs';
import {MASTER_ORIGIN} from '../src/account-session.mjs';
import {gunzipSync} from 'node:zlib';
import {setTimeout as delay} from 'node:timers/promises';

// Each bounded request is authenticated on the same official origin. Small,
// responses tolerate paths that stall large transfers; reuse TLS connections
// instead of paying for a new handshake for every range. Compressed
// bytes are untrusted until decompression and signed archive verification.
export async function downloadRelease({pin,publicKey,accessToken,fetchImpl=fetch}) {
  if(!/^[A-Za-z0-9_-]{43}$/.test(accessToken) || !/^\d+\.\d+\.\d+$/.test(pin.expectedVersion)
    || !['darwin','linux','win32'].includes(pin.platform) || !['arm64','x64'].includes(pin.arch))throw Error('invalid_delivery_request');
  const base=`${MASTER_ORIGIN}/api/operator/distribution/${pin.expectedVersion}/${pin.platform}-${pin.arch}/`;
  const deadline=Date.now()+300000;
  async function get(file,limit,range) {
    for(let attempt=0;attempt<3;attempt++) {
      if(Date.now()>=deadline)throw Error('operator_download_timeout');
      let retryAfterMs=0;
      try {
        const response=await fetchImpl(base+file,{redirect:'error',headers:{Authorization:`Bearer ${accessToken}`,Connection:'keep-alive','Accept-Encoding':'identity',...(range?{Range:range}:{})},signal:AbortSignal.timeout(Math.max(1,Math.min(10000,deadline-Date.now())))});
        if(response.status===401 || response.status===403){await response.body?.cancel();throw Error('account_login_required');}
        if(response.status===429 || response.status===503){
          const seconds=Number(response.headers.get('retry-after'));
          if(Number.isFinite(seconds)&&seconds>0)retryAfterMs=Math.min(5000,seconds*1000);
          await response.body?.cancel();throw Error('operator_release_busy');
        }
        if(response.status!==(range?206:200)){await response.body?.cancel();throw Error('operator_release_unavailable');}
        if(Number(response.headers.get('content-length'))>limit){await response.body?.cancel();throw Error('operator_release_too_large');}
        let bytes=0;const parts=[];
        for await(const chunk of response.body||[]){bytes+=chunk.length;if(bytes>limit)throw Error('operator_release_too_large');parts.push(chunk);}
        return {body:Buffer.concat(parts),contentRange:response.headers.get('content-range')};
      } catch(error) {
        const transient=error.message==='operator_release_busy' || ['TimeoutError','AbortError','TypeError'].includes(error.name);
        if(!transient)throw error;
        if(attempt===2)throw Error(error.message==='operator_release_busy'?'operator_release_busy':error.name==='TypeError'?'operator_download_network_error':'operator_download_timeout');
        await delay(Math.min(Math.max(250*(attempt+1),retryAfterMs),Math.max(0,deadline-Date.now())));
      }
    }
  }
  const metadata=(await get('manifest.json',8192)).body,signature=(await get('manifest.sig',64)).body;
  const value=verifyReleaseMetadata(metadata,signature,publicKey,pin);
  if(value.sha256!==pin.sha256 || value.catalogHash!==pin.catalogHash)throw Error('release_pin_mismatch');
  const size=8192;
  const first=await get('runtime.json.gz',size,`bytes=0-${size-1}`);
  const match=/^bytes 0-(\d+)\/(\d+)$/.exec(first.contentRange||'');
  const total=Number(match?.[2]);
  if(!match || !Number.isSafeInteger(total) || total<1 || total>value.bytes+65536 || Number(match[1])!==Math.min(size,total)-1 || first.body.length!==Math.min(size,total))throw Error('invalid_release_range');
  const chunks=new Array(Math.ceil(total/size));chunks[0]=first.body;
  let next=1,stopped=false;
  async function worker(){
    for(;!stopped;){const index=next++;if(index>=chunks.length)return;
      const start=index*size,end=Math.min(start+size,total)-1;
      const part=await get('runtime.json.gz',end-start+1,`bytes=${start}-${end}`);
      if(part.contentRange!==`bytes ${start}-${end}/${total}` || part.body.length!==end-start+1)throw Error('invalid_release_range');
      chunks[index]=part.body;
    }
  }
  const results=await Promise.allSettled(Array.from({length:2},()=>worker().catch(error=>{stopped=true;throw error;})));
  for(const result of results)if(result.status==='rejected')throw result.reason;
  let archive;
  try{archive=gunzipSync(Buffer.concat(chunks),{maxOutputLength:value.bytes});}catch{throw Error('invalid_operator_release');}
  if(archive.length!==value.bytes)throw Error('invalid_operator_release');
  return {metadata,signature,archive}; // Store verifies SHA/signature before execution.
}
