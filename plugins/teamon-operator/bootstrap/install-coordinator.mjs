import {DatabaseSync} from 'node:sqlite';
import {constants} from 'node:fs';
import {lstat,open} from 'node:fs/promises';
import path from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {privateRoot} from './release-store.mjs';

const busy=error=>error?.code?.includes('SQLITE') && /locked|busy/i.test(error.message);

// One OS-owned lock for delivery across every release in this local profile.
// SQLite releases it even on process death. No PID/TTL takeover can accidentally
// steal a live install. This database contains no account or company data.
export function createInstallCoordinator({root,version,load,install,pollMs=1000}) {
  const file=path.join(root,'.install.sqlite');
  async function connect(create) {
    if(create)await privateRoot(root);
    let handle;
    try{handle=await open(file,constants.O_NOFOLLOW|(create?constants.O_RDWR|constants.O_CREAT:constants.O_RDONLY),0o600);}
    catch(error){if(!create && error.code==='ENOENT')return null;throw error;}
    try{
      if(!create)await privateRoot(root);
      const stat=await handle.stat();
      if(!stat.isFile() || stat.nlink!==1 || stat.mode&0o077 || process.getuid && stat.uid!==process.getuid())throw Error('unsafe_runtime_file');
    }finally{await handle.close();}
    return new DatabaseSync(file,{readOnly:!create});
  }
  async function acquire() {
    const db=await connect(true);
    try{
      db.exec('PRAGMA busy_timeout=0; CREATE TABLE IF NOT EXISTS coordinator (id INTEGER PRIMARY KEY); BEGIN EXCLUSIVE');
      return ()=>{try{db.exec('ROLLBACK');}finally{db.close();}};
    }catch(error){db.close();if(busy(error))return null;throw error;}
  }
  async function status() {
    try{await lstat(file);}catch(error){if(error.code==='ENOENT')return false;throw error;}
    const db=await connect(true);
    try{db.exec('PRAGMA busy_timeout=0; BEGIN IMMEDIATE; ROLLBACK');return false;}
    catch(error){if(busy(error))return true;throw error;}
    finally{db.close();}
  }
  async function run({waitSeconds=0,installArgs}={}) {
    const deadline=Date.now()+waitSeconds*1000;
    for(;;){
      if(await load())return {state:'installed',version};
      const unlock=await acquire();
      if(unlock){
        try{
          if(!await load())await install(installArgs);
          if(!await load())throw Error('runtime_activation_failed');
          return {state:'installed',version};
        }finally{unlock();}
      }
      if(Date.now()>=deadline)return {state:'operator_installing',version,retryAfter:2,next:'operator_setup'};
      await delay(Math.min(pollMs,Math.max(1,deadline-Date.now())));
    }
  }
  return {run,status};
}
