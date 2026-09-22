import {DatabaseSync} from 'node:sqlite';
import {constants} from 'node:fs';
import {open,lstat} from 'node:fs/promises';
import path from 'node:path';
import {privateRoot} from './release-store.mjs';

// Untrusted transfer bytes only. The shared install coordinator owns writes;
// no byte from this database may execute before signature/archive verification.
// A single bounded transfer avoids accumulating partial copies of old releases.
export async function openDownloadCache(root,identity,total) {
  if(!/^[a-f0-9]{64}$/.test(identity) || !Number.isSafeInteger(total) || total<1 || total>128*1024*1024+65536)throw Error('invalid_release_range');
  await privateRoot(root);
  const file=path.join(root,'.download.sqlite');
  for(const suffix of ['', '-journal', '-wal', '-shm']) {
    try {
      const s=await lstat(file+suffix);
      if(!s.isFile() || s.isSymbolicLink() || s.nlink!==1 || s.mode&0o077 || s.size>192*1024*1024 || process.getuid && s.uid!==process.getuid())throw Error('unsafe_runtime_file');
    }catch(e){if(e.code!=='ENOENT')throw e;}
  }
  const h=await open(file,constants.O_RDWR|constants.O_CREAT|constants.O_NOFOLLOW,0o600);
  await h.close();
  const db=new DatabaseSync(file);
  try {
    db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS transfer (id INTEGER PRIMARY KEY, identity TEXT, total INTEGER); CREATE TABLE IF NOT EXISTS chunks (offset INTEGER PRIMARY KEY, body BLOB NOT NULL)');
    const prior=db.prepare('SELECT identity,total FROM transfer WHERE id=1').get();
    if(prior?.identity!==identity || prior?.total!==total) {
      db.exec('BEGIN; DELETE FROM chunks; DELETE FROM transfer');
      db.prepare('INSERT INTO transfer VALUES (1,?,?)').run(identity,total);
      db.exec('COMMIT');
    }
    let offset=0;
    const chunks=[];
    for(const row of db.prepare('SELECT offset,body FROM chunks ORDER BY offset').iterate()) {
      if(row.offset!==offset || !row.body?.length || row.body.length>8192 || offset+row.body.length>total)break;
      chunks.push(Buffer.from(row.body));offset+=row.body.length;
    }
    // A torn/gapped tail is disposable, never an installed runtime.
    db.prepare('DELETE FROM chunks WHERE offset>=?').run(offset);
    return {
      chunks,offset,
      append(start,body) {
        if(start!==offset || !body.length || body.length>8192 || offset+body.length>total)throw Error('invalid_release_range');
        db.prepare('INSERT INTO chunks VALUES (?,?)').run(start,body);offset+=body.length;
      },
      clear(){db.exec('BEGIN; DELETE FROM chunks; DELETE FROM transfer; COMMIT');},
      close(){db.close();},
    };
  }catch(e){db.close();throw e;}
}
