import { DatabaseSync } from 'node:sqlite';
import { open, mkdir } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { MASTER_ORIGIN, accountPath, saveAccountSession } from './account-session.mjs';

const grantType='urn:ietf:params:oauth:grant-type:device_code';
const opaque=value=>typeof value==='string' && /^[A-Za-z0-9_-]{43}$/.test(value);
const pendingMessage='Подтвердите подключение в браузере. Проверка продолжится в начатом процессе входа; если ожидание остановлено, попросите продолжить. Пароль и секретные коды в чат не отправляйте.';

// A tiny durable transaction protects this one pending grant across MCP processes.
// SQLite (Node built-in) releases its lock on process death; no orphan lock files.
async function transaction(configPath, work) {
  const file=`${configPath}.device.sqlite`;
  await mkdir(path.dirname(file),{recursive:true,mode:0o700});
  const handle=await open(file,constants.O_RDWR|constants.O_CREAT|constants.O_NOFOLLOW,0o600);
  try {
    const stat=await handle.stat();
    if(!stat.isFile() || stat.nlink!==1 || stat.mode & 0o077 || typeof process.getuid==='function' && stat.uid!==process.getuid())
      throw Error('unsafe_device_session');
  } finally {await handle.close();}
  const db=new DatabaseSync(file);
  try {
    db.exec('PRAGMA busy_timeout=0; CREATE TABLE IF NOT EXISTS pending (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL); BEGIN IMMEDIATE');
    const read=()=>{const row=db.prepare('SELECT payload FROM pending WHERE id=1').get();return row?JSON.parse(row.payload):null;};
    const write=value=>db.prepare('INSERT INTO pending VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload').run(JSON.stringify(value));
    const result=await work({read,write,clear:()=>db.exec('DELETE FROM pending')});
    db.exec('COMMIT');return result;
  } catch(error) {
    try{db.exec('ROLLBACK');}catch{}
    if(error.code?.includes('SQLITE') && /locked|busy/i.test(error.message))throw Error('account_login_busy');
    throw error;
  } finally {db.close();}
}
async function request(endpoint,fields,fetchImpl) {
  let response;
  try {response=await fetchImpl(`${MASTER_ORIGIN}${endpoint}`,{method:'POST',redirect:'error',
    signal:AbortSignal.timeout(15000),headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(fields)});}
  catch {throw Error('account_service_unavailable');}
  if(response.status===404)throw Error('account_device_unsupported');
  const chunks=[];let size=0;
  for await(const chunk of response.body || []){size+=chunk.length;if(size>16384)throw Error('invalid_device_response');chunks.push(chunk);}
  let value;try{value=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw Error('account_service_unavailable');}
  if(!response.ok && !['authorization_pending','slow_down','access_denied','expired_token'].includes(value.error))
    throw Error('account_service_unavailable');
  return value;
}
function validatePending(p) {
  if(!p || !opaque(p.device_code) || !/^[A-F0-9]{5}-[A-F0-9]{5}$/.test(p.user_code)
    || !Number.isFinite(p.expiresAt) || !Number.isFinite(p.nextPoll) || !Number.isInteger(p.interval) || p.interval<5 || p.interval>60)
    throw Error('invalid_device_session');
  return p;
}
function publicAttempt(p) {
  return {url:`${MASTER_ORIGIN}/operator/device?user_code=${encodeURIComponent(p.user_code)}`,
    userCode:p.user_code,expiresAt:new Date(p.expiresAt).toISOString(),message:`Сверьте код ${p.user_code} на странице Master. ${pendingMessage}`};
}
export async function beginAccountDevice(configPath,{fetchImpl=fetch,now=Date.now,resource=null}={}) {
  return transaction(configPath,async store=>{
    const old=store.read();
    if(old && (old.resource || null)!==resource)throw Error('device_resource_changed');
    if(old && validatePending(old).expiresAt>now())return publicAttempt(old);
    const value=await request('/api/operator/device',{client_id:'teamon-operator',...(resource?{resource}:{})},fetchImpl);
    if(value.error)throw Error(value.error==='slow_down'?'account_login_rate_limited':'account_service_unavailable');
    if(!opaque(value.device_code) || !/^[A-F0-9]{5}-[A-F0-9]{5}$/.test(value.user_code)
      || value.verification_uri!==`${MASTER_ORIGIN}/operator/device`
      || !Number.isInteger(value.expires_in) || value.expires_in<1 || value.expires_in>600
      || !Number.isInteger(value.interval) || value.interval<5 || value.interval>60)throw Error('invalid_device_response');
    const pending={device_code:value.device_code,user_code:value.user_code,expiresAt:now()+value.expires_in*1000,interval:value.interval,nextPoll:0,resource};
    store.write(pending);return publicAttempt(pending);
  });
}
// One explicit status refresh = at most one poll. No daemon or localhost server.
export async function finishAccountDevice(configPath,{fetchImpl=fetch,now=Date.now,save=saveAccountSession,resource=null,saveResource}={}) {
  return transaction(configPath,async store=>{
    const value=store.read();if(!value)return null;
    const p=validatePending(value);
    if((p.resource || null)!==resource)throw Error('device_resource_changed');
    if(p.expiresAt<=now()){store.clear();return {state:'account_login_expired',message:'Время входа истекло. Попросите начать новый вход.'};}
    if(p.nextPoll>now())return {state:'account_authorization_pending',retryAfter:Math.ceil((p.nextPoll-now())/1000),message:pendingMessage};
    p.nextPoll=now()+p.interval*1000;
    let result;
    try {result=await request('/api/operator/token',{client_id:'teamon-operator',grant_type:grantType,device_code:p.device_code,...(resource?{resource}:{})},fetchImpl);}
    catch(error){store.write(p);return {state:'account_service_unavailable',message:'Ответ Master не получен. Повторите проверку статуса; попытка входа сохранена.'};}
    if(['authorization_pending','slow_down'].includes(result.error)) {
      if(result.error==='slow_down'){p.interval=Math.min(60,Math.max(p.interval+5,Number(result.interval)||0));p.nextPoll=now()+p.interval*1000;}
      store.write(p);return {state:'account_authorization_pending',retryAfter:p.interval,message:pendingMessage};
    }
    if(['access_denied','expired_token'].includes(result.error)) {
      store.clear();return {state:result.error==='access_denied'?'account_login_denied':'account_login_expired',message:'Вход отменён, истёк или уже использован. Попросите начать новый вход.'};
    }
    if(resource) {
      if(typeof saveResource!=='function')throw Error('missing_resource_writer');
      await saveResource(result);store.clear();return {state:'account_token_received'};
    }
    if(result.token_type!=='Bearer' || !opaque(result.access_token) || !Number.isInteger(result.expires_in)
      || result.expires_in<=0 || result.expires_in>7*86400)throw Error('invalid_token_response');
    await save(accountPath(configPath),{schemaVersion:1,origin:MASTER_ORIGIN,accessToken:result.access_token,
      expiresAt:new Date(now()+result.expires_in*1000).toISOString()});
    store.clear();return {state:'account_token_received'};
  });
}
