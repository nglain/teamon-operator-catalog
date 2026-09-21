import {verifyReleaseMetadata} from './release-trust.mjs';
import {MASTER_ORIGIN} from '../src/account-session.mjs';

// Existing account authorization is checked by Master for EACH request. No PAT,
// bearer in a URL, redirects, arbitrary mirror or second delivery credential.
export async function downloadRelease({pin,publicKey,accessToken,fetchImpl=fetch}) {
  if(!/^[A-Za-z0-9_-]{43}$/.test(accessToken) || !/^\d+\.\d+\.\d+$/.test(pin.expectedVersion)
    || !['darwin','linux','win32'].includes(pin.platform) || !['arm64','x64'].includes(pin.arch))throw Error('invalid_delivery_request');
  const base=`${MASTER_ORIGIN}/api/operator/distribution/${pin.expectedVersion}/${pin.platform}-${pin.arch}/`;
  async function get(file,limit) {
    const response=await fetchImpl(base+file,{redirect:'error',headers:{Authorization:`Bearer ${accessToken}`},signal:AbortSignal.timeout(60000)});
    if(!response.ok)throw Error(response.status===401||response.status===403?'account_login_required':'operator_release_unavailable');
    if(Number(response.headers.get('content-length'))>limit)throw Error('operator_release_too_large');
    let bytes=0;const parts=[];
    for await(const chunk of response.body||[]){bytes+=chunk.length;if(bytes>limit)throw Error('operator_release_too_large');parts.push(chunk);}
    return Buffer.concat(parts);
  }
  const metadata=await get('manifest.json',8192),signature=await get('manifest.sig',64);
  const value=verifyReleaseMetadata(metadata,signature,publicKey,pin);
  if(value.sha256!==pin.sha256 || value.catalogHash!==pin.catalogHash)throw Error('release_pin_mismatch');
  const archive=await get('runtime.json',value.bytes);
  return {metadata,signature,archive}; // Caller verifies complete archive before stage/execute.
}
