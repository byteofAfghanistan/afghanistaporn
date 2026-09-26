'use strict';
                                                                              
                                                                               
const fs=require('node:fs'),http=require('node:http'),https=require('node:https'),crypto=require('node:crypto');
                                                                             
                                                                           
function validateServerList(value) {
  if(!Array.isArray(value)||value.length<1||value.length>16||value.some(group=>
    !Number.isSafeInteger(group?.SGrp?.Id)||typeof group.SGrp.GNa!=='string'||!Array.isArray(group.SLst)||!group.SLst.length||group.SLst.length>64||
    group.SLst.some(server=>!Number.isSafeInteger(server.Id)||typeof server.SNa!=='string'||
      server.AssignedServer!=='apitest.zulaoyun.com/'||server.IsMaintenanceMode!==0)))throw Error('GetServerList yaniti beklenen Zula semasi degil');
}
function serverAddress(value) {
  if(typeof value!=='string'||/[\u0000-\u0020\u007f]/.test(value)||! /^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(value))throw Error('Sunucu adresi IPv4 olmali');
  const parts=value.split('.').map(Number);if(parts.some(n=>n>255)||parts[0]===0||parts[0]>=224)throw Error('Gecersiz IPv4 sunucu adresi');return value;
}
function validateStatus(value,server) {
  if(value?.version!==1||value.serverHost!==server||!Number.isInteger(value.port)||value.port<1||
    !Number.isInteger(value.portCount)||value.portCount<1||value.portCount>64||value.port+value.portCount-1>65535)throw Error('Sunucunun ilan ettigi adres/UDP havuzu hedefle uyusmuyor; host ZULA_GAME_HOST ayarini kontrol edin');
  if(value.ready!==true||!Array.isArray(value.readyPorts)||value.readyPorts.length!==value.portCount||new Set(value.readyPorts).size!==value.portCount||
    value.readyPorts.some(port=>!Number.isInteger(port)||port<value.port||port>=value.port+value.portCount))throw Error('Uzak ENet havuzu henuz hazir degil');
  return {serverHost:value.serverHost,port:value.port,portCount:value.portCount};
}
function requestJson({server,port,tls=false,certificate,route,timeoutMs=1000}) {
  return new Promise((resolve,reject)=>{
    const req=(tls?https:http).get({hostname:server,port,path:route,agent:false,headers:{Host:'apitest.zulaoyun.com',Connection:'close'},
      ...(tls?{servername:'apitest.zulaoyun.com',rejectUnauthorized:false}:{})},res=>{
      try {
        if(res.statusCode!==200)throw Error(`Uzak HTTP durum ${res.statusCode}`);
        if(tls&&!res.socket.getPeerCertificate().raw?.equals(certificate))throw Error('Uzak TLS sertifikasi bu kurulumdaki certs/server.crt ile ayni degil');
      } catch(e){res.destroy();req.destroy();reject(e);return;}
      const chunks=[];let size=0;res.on('data',data=>{size+=data.length;if(size>65536)req.destroy(Error('Uzak hazirlik yaniti siniri asti'));else chunks.push(data);});
      res.on('error',reject);res.on('end',()=>{try{resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));}catch(e){reject(e);}});
    });
    const timer=setTimeout(()=>req.destroy(Error('Uzak HTTP zaman asimi')),timeoutMs);req.on('error',reject);req.on('close',()=>clearTimeout(timer));
  });
}
async function checkRemoteReady({server,certificateFile,httpPort=80,httpsPort=443,timeoutMs=1000}) {
  serverAddress(server);for(const p of [httpPort,httpsPort])if(!Number.isInteger(p)||p<1||p>65535)throw Error('Gecersiz HTTP portu');
  const certificate=new crypto.X509Certificate(fs.readFileSync(certificateFile)).raw;
  const results=await Promise.allSettled([
    requestJson({server,port:httpPort,route:'/server/GetServerList',timeoutMs}),
    requestJson({server,port:httpsPort,tls:true,certificate,route:'/server/GetServerList',timeoutMs}),
    requestJson({server,port:httpsPort,tls:true,certificate,route:'/local/LauncherStatus',timeoutMs})]);
  const failure=results.find(row=>row.status==='rejected');if(failure)throw failure.reason;
  validateServerList(results[0].value);validateServerList(results[1].value);
  return {ready:true,...validateStatus(results[2].value,server)};
}
async function waitRemoteReady(options,{timeoutMs=60000,retryMs=250}={}) {
  if(!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>120000)throw Error('Gecersiz bekleme suresi');
  const deadline=Date.now()+timeoutMs;let last;
  do {
    try{return await checkRemoteReady({...options,timeoutMs:Math.max(1,Math.min(1000,deadline-Date.now()))});}catch(e){last=e;}
    const remaining=deadline-Date.now();if(remaining>0)await new Promise(resolve=>setTimeout(resolve,Math.min(retryMs,remaining)));
  }while(Date.now()<deadline);
  throw Error('Uzak sunucu hazir olmadi: '+last.message);
}
if(require.main===module){
  const [server,certificateFile,seconds='60']=process.argv.slice(2);
  waitRemoteReady({server,certificateFile},{timeoutMs:Number(seconds)*1000}).then(status=>console.log(`[hazir] Uzak HTTP/HTTPS, sertifika ve ilan edilen ENet ${status.serverHost}:${status.port}-${status.port+status.portCount-1} dogrulandi.`),error=>{console.error('[HATA] '+error.message);process.exitCode=1;});
}
module.exports={serverAddress,validateServerList,validateStatus,requestJson,checkRemoteReady,waitRemoteReady};
