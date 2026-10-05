// Reconnect on the next explicit call. Never replay a call with an unknown effect.
export function runtimeConnection(connect) {
  let current,loading,closed=false;
  return {
    async load() {
      if(closed)throw Error('operator_closed');
      if(current)return current;
      loading ||= (async()=>{
        let disconnected=false,client;
        const onclose=()=>{disconnected=true;if(current===client)current=undefined;};
        client=await connect(onclose);
        if(!client)return null;
        if(closed || disconnected){await client.close();throw Error('runtime_activation_failed');}
        current=client;return client;
      })().finally(()=>{loading=undefined;});
      return loading;
    },
    async close(){closed=true;await loading?.catch(()=>{});const client=current;current=undefined;await client?.close();}
  };
}
