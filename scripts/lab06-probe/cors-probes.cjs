const http = require('node:http');
const { createProbeHandler } = require('./form-probe.cjs');
const page = `<!doctype html><html lang="uk"><meta charset="utf-8">
<title>LR06 Browser Security Probe</title>
<style>body{font:18px system-ui;margin:30px}button,input{font:inherit;margin:6px;padding:10px}pre{background:#eee;padding:20px;white-space:pre-wrap}iframe{width:90%;height:300px}</style>
<h1>LR06: CORS та frame-ancestors</h1><p id="origin"></p>
<p>API: http://localhost:5080. Використовуй профіль браузера, де виконано login.</p>
<button id="read">1. CORS GET /api/incidents</button>
<button id="token">2. CORS token endpoint (value omitted)</button><br>
<label>Disposable incident ID <input id="resource" size="40"></label>
<button id="put">3. Cross-origin PUT</button>
<button id="frame">4. Embed API client in iframe</button>
<pre id="result">Натисни потрібну перевірку.</pre><div id="frames"></div>
<script>
const target = 'http://localhost:5080';
document.querySelector('#origin').textContent = 'Origin: ' + location.origin;
const display = obj => { document.querySelector('#result').textContent = JSON.stringify(obj,null,2); console.table([obj]); };
document.querySelector('#read').onclick = async () => {
 try { const r = await fetch(target+'/api/incidents',{credentials:'include',headers:{'X-Lab-Cors-Probe':'1'}});
 display({origin:location.origin, readable:true, status:r.status}); }
 catch { display({origin:location.origin, readable:false, browserBlocked:true}); }
};
document.querySelector('#token').onclick = async () => {
 try { const r = await fetch(target+'/api/auth/csrf',{credentials:'include'});
 display({origin:location.origin, tokenEndpointReadable:true, status:r.status, values:'omitted'}); }
 catch { display({origin:location.origin, tokenEndpointReadable:false, browserBlocked:true, values:'omitted'}); }
};
document.querySelector('#put').onclick = async () => {
 const id=document.querySelector('#resource').value.trim();
 if(!/^[0-9a-f-]{36}$/i.test(id)) return display({error:'Встав GUID disposable інциденту з lr6.fixture()'});
 try { const r = await fetch(target+'/api/incidents/'+id,{method:'PUT',credentials:'include',
 headers:{'Content-Type':'application/json','X-CSRF-TOKEN':'invalid-study-token'},
 body:JSON.stringify({title:'CORS probe should be blocked',description:'Local synthetic preflight test.'})});
 display({origin:location.origin, readable:true, status:r.status}); }
 catch { display({origin:location.origin, browserBlocked:true, readable:false}); }
};
document.querySelector('#frame').onclick = () => {
 const frame=document.createElement('iframe'); frame.src=target+'/'; frame.title='Frame ancestors denial probe';
 document.querySelector('#frames').replaceChildren(frame);
 display({attempt:'iframe embedding', expected:'blocked by frame-ancestors; inspect Console'});
};
</script></html>`;
const servers = [];
const state = new Map();
for (const port of [4173,4174]) {
  const server = http.createServer(createProbeHandler({state, receiverPort:4173, legacyPage:page}));
  servers.push(server);
  server.on('error',err => {
    console.error('Port '+port+': '+err.code); process.exitCode=1; servers.forEach(s=>s.close());
  });
  server.listen(port,'127.0.0.1',()=>console.log('LR06 probe: http://localhost:'+port));
}
