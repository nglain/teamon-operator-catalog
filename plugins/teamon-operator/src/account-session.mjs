import { open, mkdir, rename, unlink, lstat } from 'node:fs/promises';
import { constants } from 'node:fs';
import { randomUUID } from 'node:crypto';
import path from 'node:path';

export const MASTER_ORIGIN = 'https://master.nglain.com';
export const accountPath = configPath => `${configPath}.account.json`;

export function validateAccount(value) {
  if (value?.schemaVersion !== 1 || value.origin !== MASTER_ORIGIN
    || typeof value.accessToken !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value.accessToken)
    || !Number.isFinite(Date.parse(value.expiresAt))) throw new Error('invalid_account_session');
  return value;
}
export async function readAccountSession(file) {
  let handle;
  try {
    handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > 4096 || (stat.mode & 0o077) !== 0
      || typeof process.getuid === 'function' && stat.uid !== process.getuid()) throw new Error('unsafe_account_session');
    return validateAccount(JSON.parse(await handle.readFile('utf8')));
  } finally { await handle?.close(); }
}
export async function saveAccountSession(file, session) {
  validateAccount(session);
  await mkdir(path.dirname(file), {recursive:true,mode:0o700});
  try { const stat=await lstat(file); if(!stat.isFile() || stat.isSymbolicLink() || stat.mode & 0o077 || typeof process.getuid==='function' && stat.uid!==process.getuid()) throw new Error('unsafe_account_session'); }
  catch(error) { if(error.code !== 'ENOENT') throw error; }
  const temporary = `${file}.${randomUUID()}.tmp`;
  let handle;
  try {
    handle = await open(temporary, constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL,0o600);
    await handle.writeFile(JSON.stringify(session)); await handle.sync(); await handle.close(); handle=undefined;
    await rename(temporary,file);
  } finally { await handle?.close(); await unlink(temporary).catch(error=>{if(error.code!=='ENOENT')throw error;}); }
}

export async function accountJson(url, options={}, fetchImpl=fetch) {
  const response=await fetchImpl(url,{...options,redirect:'error',signal:AbortSignal.timeout(15_000)});
  if(!response.ok) throw new Error(response.status===401?'account_login_required':'account_service_unavailable');
  let bytes=0; const chunks=[];
  for await(const chunk of response.body || []) {bytes+=chunk.length;if(bytes>256*1024)throw new Error('account_response_too_large');chunks.push(chunk);}
  try{return JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw new Error('invalid_account_response');}
}
