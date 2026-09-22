import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {StdioServerTransport} from '@modelcontextprotocol/sdk/server/stdio.js';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {ListToolsRequestSchema,CallToolRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {readFile} from 'node:fs/promises';
import {createPublicKey,createHash,randomUUID} from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import {setTimeout as delay} from 'node:timers/promises';
import {accountPath,readAccountSession,accountJson,MASTER_ORIGIN} from '../src/account-session.mjs';
import {beginAccountDevice,finishAccountDevice} from '../src/account-device.mjs';
import {createReleaseStore} from './release-store.mjs';
import {downloadRelease} from './release-download.mjs';
import {createInstallCoordinator} from './install-coordinator.mjs';

const hash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const result=value=>({content:[{type:'text',text:JSON.stringify(value)}],structuredContent:value});
const fail=message=>({isError:true,content:[{type:'text',text:message}]});
const setupTool={name:'operator_setup',description:'On explicit installation request, finish browser login, download the signed private runtime and activate it. Never changes company data. Call after opening account_login_open URL. Status alone never installs.',
  inputSchema:{type:'object',properties:{wait_seconds:{type:'integer',minimum:0,maximum:45}},additionalProperties:false},
  annotations:{readOnlyHint:false,destructiveHint:false,openWorldHint:true}};

export async function createPrivateBootstrap({release,catalog,configPath,fetchImpl=fetch}) {
  const pin=release.targets[`${process.platform}-${process.arch}`];
  if(!pin || hash(catalog)!==pin.catalogHash)throw Error('unsupported_operator_release');
  const store=createReleaseStore({root:path.join(path.dirname(configPath),'runtimes'),publicKey:createPublicKey(release.publicKey),pin});
  const runtimeRoot=path.join(path.dirname(configPath),'runtimes');
  let runtime,loading,installing,download,closed=false;
  const processInstanceId=randomUUID(),processStartedAt=new Date(Date.now()-process.uptime()*1000).toISOString();
  const server=new Server({name:'teamon-operator',version:release.version},{capabilities:{tools:{}},
    instructions:'TeamON Operator. For installation: account_login_open, then explicit operator_setup. Diagnostics never install. After setup, installation_status refresh and operator_workspace_open. Preserve human approval for business writes; never retry an uncertain effect.'});
  async function load() {
    if(closed)throw Error('operator_closed');
    if(runtime)return runtime;
    loading ||= (async()=>{
      const installed=await store.load();if(!installed)return null;
      const client=new Client({name:'teamon-public-bootstrap',version:release.version});
      try {
        await client.connect(new StdioClientTransport({command:process.execPath,args:[path.join(installed.directory,'src/cli.mjs'),'serve','--config',configPath],stderr:'ignore'}));
        const tools=(await client.listTools()).tools;
        if(hash(tools)!==pin.catalogHash || closed)throw Error('runtime_catalog_mismatch');
        runtime=client;return client;
      }catch(error){await client.close();throw error;}
    })().finally(()=>{loading=undefined;});
    return loading;
  }
  async function account() {
    let session;
    try {session=await readAccountSession(accountPath(configPath));}
    catch(error){if(error.code==='ENOENT')throw Error('account_login_required');throw error;}
    if(Date.parse(session.expiresAt)<=Date.now())throw Error('account_login_required');
    const data=await accountJson(MASTER_ORIGIN+'/api/operator/instances',{headers:{Authorization:`Bearer ${session.accessToken}`,'X-TeamON-Operator-Transport':'direct-mcp-v1'}},fetchImpl);
    if(!data.operator?.id || !Array.isArray(data.instances))throw Error('invalid_account_response');
    return {session,count:data.instances.length};
  }
  function validateSetup(args) {
    if(Object.keys(args).some(k=>k!=='wait_seconds') || args.wait_seconds!==undefined && (!Number.isInteger(args.wait_seconds)||args.wait_seconds<0||args.wait_seconds>45))throw Error('invalid_setup_request');
  }
  const coordinator=createInstallCoordinator({root:runtimeRoot,version:release.version,load:()=>store.load(),install:async authorized=>{
    const bytes=await downloadRelease({pin,publicKey:createPublicKey(release.publicKey),accessToken:authorized.session.accessToken,fetchImpl,
      checkpointRoot:runtimeRoot,onProgress:value=>{download=value;}});
    const current=await readAccountSession(accountPath(configPath));
    if(current.accessToken!==authorized.session.accessToken)throw Error('account_changed');
    await store.install(bytes);
  }});
  async function setup(args) {
    const until=Date.now()+(args.wait_seconds||0)*1000;
    for(;;) {
      const pending=await finishAccountDevice(configPath,{fetchImpl});
      if(!pending || pending.state==='account_token_received')break;
      if(pending.state!=='account_authorization_pending' || Date.now()>=until)return result(pending);
      const wait=Math.min(Math.max(5,pending.retryAfter||5)*1000,until-Date.now());
      if(wait<=0)return result(pending);await delay(wait);
      if(closed)throw Error('operator_closed');
    }
    const authorized=await account();
    // The coordinator is shared by all bootstrap processes through the
    // private runtime directory. Only its lock owner can download/install.
    const outcome=await coordinator.run({waitSeconds:Math.max(0,(until-Date.now())/1000),installArgs:authorized});
    if(outcome.state!=='installed')return result(outcome);
    // Cache presence is not activation. Every follower must start and verify
    // its own child before reporting successful installation.
    if(!await load())throw Error('runtime_activation_failed');
    return result({state:'installed',version:release.version,accountLogin:true,assignedCompanies:authorized.count,next:'operator_workspace_open'});
  }
  server.setRequestHandler(ListToolsRequestSchema,async()=>({tools:[...structuredClone(catalog),structuredClone(setupTool)]}));
  server.setRequestHandler(CallToolRequestSchema,async request=>{
    const {name,arguments:args={}}=request.params;
    try {
      if(name==='operator_setup'){
        validateSetup(args);
        // Keep one job alive between bounded tool calls. Preserve its outcome
        // until a caller observes it, including failures between polls.
        installing ||= setup(args).then(value=>({value}),error=>({error}));
        let timer;
        try {
          const outcome=await Promise.race([installing,new Promise(resolve=>{
            timer=setTimeout(()=>resolve(null),(args.wait_seconds ?? 45)*1000);
          })]);
          if(!outcome)return result({state:'operator_installing',version:release.version,retryAfter:2,next:'operator_setup',...(download?{download}:{})});
          installing=undefined;
          if(outcome.error){
            if(download && ['operator_download_timeout','operator_download_network_error','operator_release_busy'].includes(outcome.error.message))
              return result({state:'operator_download_paused',version:release.version,reason:outcome.error.message,download,retryable:true,next:'operator_setup'});
            throw outcome.error;
          }
          return outcome.value;
        } finally {clearTimeout(timer);}
      }
      if(!catalog.some(t=>t.name===name))return fail('unknown_operator_tool');
      const active=await load();
      // Delegate without catching and retrying a business action. Child owns its
      // existing session/identity-change guards and exact input validation.
      if(active)return await active.callTool({name,arguments:args});
      if(name==='account_login_open'){
        if(Object.keys(args).length)throw Error('invalid_login_request');
        return result(await beginAccountDevice(configPath,{fetchImpl}));
      }
      if(name==='installation_status') {
        if(Object.keys(args).some(k=>k!=='refresh_account') || args.refresh_account!==undefined && typeof args.refresh_account!=='boolean')throw Error('invalid_status_request');
        if(args.refresh_account){
          const pending=await finishAccountDevice(configPath,{fetchImpl});if(pending && pending.state!=='account_token_received')return result({version:release.version,...pending});
          const authorized=await account();return result({version:release.version,state:await coordinator.status()?'operator_installing':'operator_runtime_required',accountLogin:true,assignedCompanies:authorized.count});
        }
        const lock=await coordinator.status();
        return result(lock?{version:release.version,state:'operator_installing',retryAfter:2,next:'operator_setup'}:{version:release.version,state:'operator_runtime_required',liveChecked:false});
      }
      if(name==='operator_runtime_info') {
        const toolNames=[...catalog.map(t=>t.name),'operator_setup'].sort();
        return result({schemaVersion:1,serverName:'teamon-operator-bootstrap',version:release.version,sourceCommit:null,
          buildDirty:null,provenance:'unknown',processInstanceId,processStartedAt,toolCount:toolNames.length,toolNames,
          toolNamesHash:'sha256:'+hash(toolNames),inventoryScope:'server_registered_names_not_host_visibility'});
      }
      return fail('operator_runtime_required: complete explicit operator_setup first');
    }catch(error){
      const allowed=['account_login_required','account_changed','account_service_unavailable','operator_release_unavailable','operator_release_busy','operator_download_timeout','operator_download_network_error','operator_release_too_large','invalid_release_range','operator_closed','operator_runtime_required','runtime_catalog_mismatch','invalid_operator_release','release_pin_mismatch','runtime_integrity_failed','unsafe_runtime_file','unsafe_runtime_directory','unexpected_runtime_file','invalid_setup_request','invalid_status_request','invalid_login_request'];
      return fail(allowed.includes(error.message)?error.message:runtimeFailureCode(error));
    }
  });
  const close=server.close.bind(server);
  server.close=async()=>{closed=true;await installing?.catch(()=>{});await loading?.catch(()=>{});await runtime?.close();await close();};
  return server;
}

export async function servePrivateBootstrap() {
  const release=JSON.parse(await readFile(new URL('./release.json',import.meta.url),'utf8'));
  const catalog=JSON.parse(await readFile(new URL('./catalog.json',import.meta.url),'utf8'));
  const configPath=path.resolve(process.env.TEAMON_OPERATOR_CONFIG||path.join(os.homedir(),'.config/teamon-operator/operator.json'));
  const server=await createPrivateBootstrap({release,catalog,configPath});await server.connect(new StdioServerTransport());
}

// Do not expose validation payloads or retry a possibly completed operation.
export function runtimeFailureCode(error) {
  return error?.code===-32602 && typeof error.message==='string' && error.message.includes("Structured content does not match the tool's output schema:")
    ? 'operator_runtime_response_invalid' : 'operator_request_failed';
}
