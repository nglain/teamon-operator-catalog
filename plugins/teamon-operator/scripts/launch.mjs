const [major,minor,patch]=process.versions.node.split('.').map(Number);
if(major!==24 || minor<14 || minor===14 && patch<1)throw Error('TeamON Operator requires Node 24.14.1+ in branch 24');
if(process.argv[2] && process.argv[2]!=='serve')throw Error('Expected serve');
const {servePrivateBootstrap}=await import('../bootstrap/server.mjs');
await servePrivateBootstrap();
