'use strict';
                                                                             
                                                                                  
                                                                                  
                                                                            
                                                                               
function makeZulaRemoteURL(server) {
  if(typeof server!=='string'||/[\u0000-\u0020\u007f]/.test(server)||! /^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(server))throw Error('Invalid remote IPv4 address');
  const parts=server.split('.').map(Number);if(parts.some(n=>n>255)||parts[0]===0||parts[0]>=224)throw Error('Invalid remote IPv4 address');
  const hosts=new Set(['127.0.0.1','localhost','apitest.zulaoyun.com','api.zulaoyun.com','scs.zulaoyun.com','zulaoyun.com','www.zulaoyun.com']);
  return function rewrite(value) {
    if(typeof value!=='string'||value.length>16384||/[\u0000-\u0020\u007f]/.test(value))return null;
    const m=/^(https?):\/\/([^/?#]+)(.*)$/i.exec(value);if(!m)return null;
    const authority=/^([^:@]+)(?::([0-9]+))?$/.exec(m[2]);if(!authority||!hosts.has(authority[1].toLowerCase()))return null;
    const scheme=m[1].toLowerCase(),port=authority[2];
    if(port&&port!==(scheme==='https'?'443':'80')&&!(scheme==='http'&&['127.0.0.1','localhost'].includes(authority[1].toLowerCase())&&port==='30000'))return null;
                                                                                
                                                   
    return 'https://apitest.zulaoyun.com'+m[3];
  };
}
if(typeof module!=='undefined'&&module.exports)module.exports={makeZulaRemoteURL};
