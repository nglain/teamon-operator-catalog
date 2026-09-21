// Public bootstrap trust boundary. No I/O, credentials or executable code here.
import {createHash, verify} from 'node:crypto';

const MAX_METADATA = 8192;
const MAX_ARCHIVE = 128 * 1024 * 1024;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = () => { throw new Error('invalid_operator_release'); };
const exactKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const version = value => {
  if (typeof value !== 'string' || !/^(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})$/.test(value)) fail();
  return value.split('.').map(Number);
};

// Signature covers original bytes, not a reserialized JSON interpretation.
export function verifyReleaseMetadata(bytes, signature, publicKey, {expectedVersion, platform, arch, minimumVersion}) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_METADATA || !Buffer.isBuffer(signature)
    || signature.length !== 64 || publicKey?.asymmetricKeyType !== 'ed25519') fail();
  if (!verify(null, bytes, publicKey, signature)) fail();
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); } catch { fail(); }
  if (!exactKeys(value, ['schemaVersion','version','platform','arch','bytes','sha256','sourceCommit','catalogHash'])
    || value.schemaVersion !== 1 || value.platform !== platform || value.arch !== arch
    || !Number.isSafeInteger(value.bytes) || value.bytes < 1 || value.bytes > MAX_ARCHIVE
    || !/^[a-f0-9]{64}$/.test(value.sha256) || !/^[a-f0-9]{64}$/.test(value.catalogHash)
    || !/^[a-f0-9]{40}$/.test(value.sourceCommit) || value.version !== expectedVersion) fail();
  const candidate = version(value.version), floor = version(minimumVersion);
  for (let i=0; i<3; i++) {
    if (candidate[i] < floor[i]) fail();
    if (candidate[i] > floor[i]) break;
  }
  return Object.freeze(value);
}

// A deliberately simple data-only archive avoids platform-specific tar/link semantics.
// Returned entries are only a verified plan; caller stages/promotes without executing it.
export function verifyReleaseArchive(bytes, metadata) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_ARCHIVE || bytes.length !== metadata.bytes
    || digest(bytes) !== metadata.sha256) fail();
  let archive;
  try { archive = JSON.parse(bytes.toString('utf8')); } catch { fail(); }
  if (!exactKeys(archive, ['schemaVersion','files']) || archive.schemaVersion !== 1
    || !Array.isArray(archive.files) || !archive.files.length || archive.files.length > 12000) fail();
  const names = new Set(), entries = [];
  let expanded = 0;
  for (const item of archive.files) {
    if (!exactKeys(item, ['path','content','sha256']) || typeof item.path !== 'string'
      || item.path.length > 240 || !/^[a-zA-Z0-9_@.+/-]+$/.test(item.path)
      || item.path.startsWith('/') || item.path.split('/').some(p => !p || p === '.' || p === '..' || p.toLowerCase() === '.git')
      || typeof item.content !== 'string' || item.content.length%4!==0 || /[^A-Za-z0-9+/=]/.test(item.content)
      || !/^[a-f0-9]{64}$/.test(item.sha256)) fail();
    // Reject case-fold aliases on case-insensitive recipient filesystems.
    const folded = item.path.toLowerCase();
    if (names.has(folded)) fail();
    names.add(folded);
    const content = Buffer.from(item.content, 'base64');
    expanded += content.length;
    if (expanded > MAX_ARCHIVE || content.toString('base64')!==item.content || digest(content) !== item.sha256) fail();
    entries.push({path:item.path, content});
  }
  for (const name of names) {
    const parts = name.split('/');
    for (let i=1; i<parts.length; i++) if (names.has(parts.slice(0,i).join('/'))) fail();
  }
  if (!names.has('src/cli.mjs') || !names.has('package.json')) fail();
  return entries;
}
