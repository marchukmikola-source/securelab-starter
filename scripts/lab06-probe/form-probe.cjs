const MARKER='FAKE-CSP-1';
const POLICY="default-src 'self'; connect-src 'self'; frame-ancestors 'none'";
const escape=v=>String(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const shell=(title,body,script='')=>'<!doctype html><html lang="uk"><meta charset="utf-8"><title>'+escape(title)+'</title><link rel="stylesheet" href="/probe.css"><body>'+body+(script?'<script src="'+script+'"></script>':'')+'</body></html>';
const style='body{font:18px system-ui;margin:30px;max-width:1200px}button,input{font:inherit;margin:6px;padding:10px}pre{background:#eee;padding:20px;white-space:pre-wrap;overflow-wrap:anywhere}a{margin-right:20px}code{overflow-wrap:anywhere}';
function demoPage(receiverPort) {
  const target='http://localhost:'+receiverPort;
  return shell('LR06 CSP Fetch та HTML форма','<h1>CSP Fetch та HTML форма</h1><p id="origin"></p><p>Enforcing policy:</p><pre>'+escape(POLICY)+
    '</pre><p>Зовнішній приймач: <code id="receiver">'+target+'</code>. Поле форми містить лише <b>'+MARKER+'</b>.</p>'+
    '<button id="reset">1. Очистити події</button><button id="fetch">2. Зовнішній fetch</button>'+
    '<form method="post" action="'+target+'/collect?via=form" target="_blank" rel="noopener">'+
    '<input type="hidden" name="marker" value="'+MARKER+'"><button type="submit">3. Надіслати зовнішню форму</button></form>'+
    '<form method="post" action="/collect?via=same-origin" target="_blank" rel="noopener">'+
    '<input type="hidden" name="marker" value="'+MARKER+'"><button type="submit">4. Штатна same-origin форма</button></form>'+
    '<button id="refresh">Оновити серверні лічильники</button><pre id="result">Спочатку очисти події.</pre>'+
    '<p><a href="'+target+'/events.html" target="_blank" rel="noopener">Події зовнішнього приймача</a></p>','/csp-ui.js');
}
const cspScript=[
 "const receiver=document.querySelector('#receiver').textContent;const result=document.querySelector('#result');let violations=[];let fetchOutcome='not attempted';",
 "document.querySelector('#origin').textContent='Document origin: '+location.origin;",
 "document.addEventListener('securitypolicyviolation',e=>{if(e.effectiveDirective==='connect-src')violations.push({directive:e.effectiveDirective,disposition:e.disposition});});",
 "async function refresh(){const r=await fetch('/probe-status',{cache:'no-store'});const state=await r.json();result.textContent=JSON.stringify({fetchOutcome,cspViolations:violations,...state},null,2);}",
 "document.querySelector('#reset').onclick=async()=>{await fetch('/reset',{method:'POST'});violations=[];fetchOutcome='not attempted';await refresh();};",
 "document.querySelector('#fetch').onclick=async()=>{try{const r=await fetch(receiver+'/collect?via=fetch',{method:'POST',credentials:'omit',body:new URLSearchParams({marker:'FAKE-CSP-1'})});fetchOutcome='response '+r.status;}catch{fetchOutcome='rejected by browser; inspect CSP violation and receiver count';}await new Promise(r=>setTimeout(r,100));await refresh();};",
 "document.querySelector('#refresh').onclick=refresh;refresh();"
].join('\n');
const eventsScript="async function refresh(){const r=await fetch('/events',{cache:'no-store'});document.querySelector('#events').textContent=JSON.stringify(await r.json(),null,2);}document.querySelector('#refresh').onclick=refresh;refresh();";
function createProbeHandler({state=new Map(),receiverPort=4173,legacyPage='<h1>LR06 probe</h1>'}={}) {
 const eventsFor=port=>{if(!state.has(port))state.set(port,[]);return state.get(port);};
 return async(req,res)=>{
  const port=req.socket.localPort,url=new URL(req.url,'http://localhost:'+port);
  const send=(status,type,body,csp=false)=>{
   res.writeHead(status,{'Content-Type':type,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',...(csp?{'Content-Security-Policy':POLICY}:{})});res.end(body);
  };
  const json=(status,obj)=>send(status,'application/json; charset=utf-8',JSON.stringify(obj));
  if(req.method==='GET'&&url.pathname==='/events')return json(200,{port,events:eventsFor(port)});
  if(req.method==='GET'&&url.pathname==='/probe-status'){
   const events=eventsFor(receiverPort);
   return json(200,{receiverOrigin:'http://localhost:'+receiverPort,
    receivedFetchPosts:events.filter(e=>e.via==='fetch').length,
    receivedFormPosts:events.filter(e=>e.via==='form'&&e.accepted).length,
    sameOriginFormPosts:eventsFor(port).filter(e=>e.via==='same-origin'&&e.accepted).length});
  }
  if(req.method==='POST'&&url.pathname==='/reset'){for(const list of state.values())list.length=0;return json(200,{cleared:true});}
  if(req.method==='POST'&&url.pathname==='/collect'){
   // Discard all headers/cookies and arbitrary input; persist only the fixed marker.
   let body='',bytes=0,oversized=false;
   try{for await(const chunk of req){bytes+=chunk.length;if(bytes>1024)oversized=true;else body+=chunk.toString('utf8');}}
   catch{return json(400,{accepted:false,error:'Incomplete request.'});}
   const type=(req.headers['content-type']||'').split(';')[0].trim().toLowerCase(),fields=new URLSearchParams(body);
   const accepted=!oversized&&type==='application/x-www-form-urlencoded'&&[...fields].length===1&&fields.get('marker')===MARKER;
   const via=['fetch','form','same-origin','manual'].includes(url.searchParams.get('via'))?url.searchParams.get('via'):'manual';
   const origin=/^http:\/\/localhost:\d{1,5}$/.test(req.headers.origin||'')?req.headers.origin:'omitted';
   const event={time:new Date().toISOString(),method:'POST',path:'/collect',via,origin,accepted,
    ...(accepted?{marker:MARKER}:{reason:'Only the fixed synthetic marker is accepted.'})};
   const list=eventsFor(port);list.push(event);if(list.length>100)list.shift();
   const status=oversized?413:accepted?200:400;
   console.log(JSON.stringify({probePort:port,...event}));
   return send(status,'text/html; charset=utf-8',shell('LR06 POST receipt','<h1>POST отримано</h1><pre>'+escape(JSON.stringify({port,...event},null,2))+'</pre><a href="/events.html">Усі події приймача</a>'));
  }
  if(req.method!=='GET')return json(405,{error:'Method not allowed.'});
  if(url.pathname==='/probe.css')return send(200,'text/css; charset=utf-8',style);
  if(url.pathname==='/csp-ui.js')return send(200,'text/javascript; charset=utf-8',cspScript);
  if(url.pathname==='/events-ui.js')return send(200,'text/javascript; charset=utf-8',eventsScript);
  if(url.pathname==='/csp-demo')return send(200,'text/html; charset=utf-8',demoPage(receiverPort),true);
  if(url.pathname==='/events.html')return send(200,'text/html; charset=utf-8',shell('LR06 received POST','<h1>Отримані POST</h1><button id="refresh">Оновити</button><pre id="events"></pre>','/events-ui.js'));
  if(url.pathname==='/')return send(200,'text/html; charset=utf-8',legacyPage.replace('<script>','<section><h2>Приймач POST</h2><a href="/events.html">Події приймача</a> <a href="http://localhost:4174/csp-demo">CSP fetch та форма</a></section><script>'));
  return json(404,{error:'Not found.'});
 };
}
module.exports={createProbeHandler,MARKER,POLICY};
