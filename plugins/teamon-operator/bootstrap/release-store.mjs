import {constants} from 'node:fs';
import {mkdir,mkdtemp,lstat,open,rename,rm,readdir,realpath} from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {verifyReleaseMetadata,verifyReleaseArchive} from './release-trust.mjs';

const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const safe=stat=>!stat.isSymbolicLink() && !(stat.mode&0o077) && (!process.getuid || stat.uid===process.getuid());
async function privateRead(file,max) {
  const h=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{const s=await h.stat();if(!s.isFile() || s.nlink!==1 || !safe(s) || s.size>max)throw Error('unsafe_runtime_file');return await h.readFile();}
  finally{await h.close();}
}
async function writeNew(file,bytes) {
  const h=await open(file,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL,0o600);
  try{await h.writeFile(bytes);await h.sync();}finally{await h.close();}
}
async function privateRoot(root) {
  await mkdir(root,{recursive:true,mode:0o700});
  if(!safe(await lstat(root)) || !(await lstat(root)).isDirectory() || await realpath(root)!==path.resolve(root))throw Error('unsafe_runtime_directory');
}

// A pinned release gets its own immutable directory. No mutable current pointer,
// no install hooks, no shell, and no removal of the previous working release.
export function createReleaseStore({root,publicKey,pin}) {
  if(!/^[a-f0-9]{64}$/.test(pin.sha256))throw Error('invalid_release_pin');
  const target=path.join(root,pin.sha256);
  const verify=(metadata,signature,archive)=>{
    const value=verifyReleaseMetadata(metadata,signature,publicKey,pin);
    if(value.sha256!==pin.sha256 || value.catalogHash!==pin.catalogHash)throw Error('release_pin_mismatch');
    return {metadata:value,entries:verifyReleaseArchive(archive,value)};
  };
  async function load() {
    try{await lstat(target);}catch(e){if(e.code==='ENOENT')return null;throw e;}
    await privateRoot(root);
    if(!safe(await lstat(target)) || !(await lstat(target)).isDirectory())throw Error('unsafe_runtime_directory');
    const metadata=await privateRead(path.join(target,'manifest.json'),8192);
    const signature=await privateRead(path.join(target,'manifest.sig'),64);
    const archive=await privateRead(path.join(target,'runtime.json'),128*1024*1024);
    const verified=verify(metadata,signature,archive);
    const runtime=path.join(target,'runtime'),expected=new Set(verified.entries.map(e=>e.path));
    // Extra executable files and symlinks are rejected as well as modified bytes.
    async function walk(directory,relative='') {
      const stat=await lstat(directory);if(!stat.isDirectory() || !safe(stat))throw Error('unsafe_runtime_directory');
      for(const name of await readdir(directory)) {
        const child=path.join(directory,name),p=relative?relative+'/'+name:name,s=await lstat(child);
        if(s.isDirectory()){await walk(child,p);continue;}
        if(!expected.has(p))throw Error('unexpected_runtime_file');
      }
    }
    await walk(runtime);
    for(const entry of verified.entries) {
      const bytes=await privateRead(path.join(runtime,entry.path),entry.content.length);
      if(digest(bytes)!==digest(entry.content))throw Error('runtime_integrity_failed');
    }
    return {directory:runtime,metadata:verified.metadata};
  }
  async function install({metadata,signature,archive}) {
    const verified=verify(metadata,signature,archive); // No filesystem change before verification.
    await privateRoot(root);
    const existing=await load();if(existing)return existing;
    const stage=await mkdtemp(path.join(root,'.stage-'));
    try {
      await writeNew(path.join(stage,'manifest.json'),metadata);
      await writeNew(path.join(stage,'manifest.sig'),signature);
      await writeNew(path.join(stage,'runtime.json'),archive);
      for(const entry of verified.entries) {
        const file=path.join(stage,'runtime',entry.path);
        await mkdir(path.dirname(file),{recursive:true,mode:0o700});await writeNew(file,entry.content);
      }
      try{await rename(stage,target);}catch(error){
        if(!['EEXIST','ENOTEMPTY'].includes(error.code))throw error;
        // Another process may have won. Accept only the same fully verified bytes.
      }
      return await load();
    }finally{await rm(stage,{recursive:true,force:true});}
  }
  return {load,install};
}
