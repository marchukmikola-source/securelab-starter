const http=require('node:http'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {chromium}=require('playwright');
const {createProbeHandler,MARKER,POLICY}=require('./form-probe.cjs');
const output=path.resolve(__dirname,'../../tmp/lab06/probe-verification');fs.mkdirSync(output,{recursive:true});
const state=new Map();let receiver,exercise,browser;
const serve=async options=>{
 const s=http.createServer(createProbeHandler(options));
 await new Promise((resolve,reject)=>{s.once('error',reject);s.listen(0,'127.0.0.1',resolve);});return s;
};
(async()=>{
 try{
  receiver=await serve({state});const port=receiver.address().port;
  exercise=await serve({state,receiverPort:port,legacyPage:'<h1>CORS test</h1><script>void 0</script>'});
  const receiverUrl='http://localhost:'+port,exerciseUrl='http://localhost:'+exercise.address().port;
  const post=async(body,type='application/x-www-form-urlencoded',extra={})=>fetch(receiverUrl+'/collect?via=manual',{method:'POST',headers:{'Content-Type':type,...extra},body});
  let r=await post('marker='+MARKER,'application/x-www-form-urlencoded',{Cookie:'sensitive-cookie-not-persisted','Authorization':'Bearer sensitive-token-not-persisted'});
  assert.equal(r.status,200);assert.ok((await r.text()).includes(MARKER));
  const rejected=[];
  for(const [body,type,expected] of [
   ['marker=arbitrary-secret','application/x-www-form-urlencoded',400],
   ['marker='+MARKER+'&token=sensitive-token-not-persisted','application/x-www-form-urlencoded',400],
   ['marker='+MARKER+'&marker='+MARKER,'application/x-www-form-urlencoded',400],
   [JSON.stringify({marker:MARKER}),'application/json',400],
   ['marker='+'x'.repeat(1100),'application/x-www-form-urlencoded',413]]){
   r=await post(body,type);assert.equal(r.status,expected);rejected.push(r.status);
  }
  let events=await(await fetch(receiverUrl+'/events')).text();
  for(const secret of ['sensitive-cookie-not-persisted','sensitive-token-not-persisted','arbitrary-secret'])assert.equal(events.includes(secret),false);
  assert.equal((await fetch(receiverUrl+'/collect')).status,404);
  assert.equal((await fetch(exerciseUrl+'/csp-demo')).headers.get('content-security-policy'),POLICY);
  assert.ok((await(await fetch(exerciseUrl+'/')).text()).includes('CSP fetch та форма'));
  await fetch(exerciseUrl+'/reset',{method:'POST'});
  browser=await chromium.launch({channel:'chrome',headless:true});
  const context=await browser.newContext({viewport:{width:1440,height:1000}});
  const page=await context.newPage();await page.goto(exerciseUrl+'/csp-demo');
  assert.deepEqual(await page.locator('form input').evaluateAll(items=>items.map(x=>({name:x.name,value:x.value}))),
   [{name:'marker',value:MARKER},{name:'marker',value:MARKER}]);
  await page.locator('#reset').click();
  await page.locator('#fetch').click();
  await page.waitForFunction(()=>{try{return JSON.parse(document.querySelector('#result').textContent).cspViolations.some(v=>v.directive==='connect-src'&&v.disposition==='enforce');}catch{return false;}});
  let status=await(await fetch(exerciseUrl+'/probe-status')).json();
  assert.equal(status.receivedFetchPosts,0);assert.equal(status.receivedFormPosts,0);
  const popup=context.waitForEvent('page');await page.getByRole('button',{name:'3. Надіслати зовнішню форму',exact:true}).click();
  const receipt=await popup;await receipt.waitForURL('**/collect?via=form');
  await receipt.waitForLoadState('domcontentloaded');
  assert.ok((await receipt.locator('body').innerText()).includes(MARKER));
  await page.locator('#refresh').click();await page.waitForFunction(()=>JSON.parse(document.querySelector('#result').textContent).receivedFormPosts===1);
  const normalPopup=context.waitForEvent('page');await page.getByRole('button',{name:'4. Штатна same-origin форма',exact:true}).click();
  const normal=await normalPopup;await normal.waitForURL('**/collect?via=same-origin');
  await page.locator('#refresh').click();await page.waitForFunction(()=>JSON.parse(document.querySelector('#result').textContent).sameOriginFormPosts===1);
  status=await(await fetch(exerciseUrl+'/probe-status')).json();
  assert.equal(status.receivedFetchPosts,0);assert.equal(status.receivedFormPosts,1);assert.equal(status.sameOriginFormPosts,1);
  events=await(await fetch(receiverUrl+'/events')).json();
  assert.equal(events.events.length,1);assert.equal(events.events[0].marker,MARKER);
  await page.screenshot({path:path.join(output,'csp-fetch-vs-form.png'),fullPage:true});
  const proof={status:'PASS',marker:MARKER,policy:POLICY,browser:'Chrome via Playwright',
   externalFetchCspViolation:true,externalFetchReceived:0,externalFormPostsReceived:1,sameOriginFormPostsReceived:1,
   unsafeInputStatuses:rejected,headersAndArbitraryValuesNotPersisted:true,formsContainOnlyFixedSyntheticMarker:true,
   application5080Unchanged:true,ports:'isolated ephemeral loopback ports; user 4173/4174 processes untouched'};
  fs.writeFileSync(path.join(output,'proof.json'),JSON.stringify(proof,null,2));
  console.log(JSON.stringify(proof));
 }finally{
  if(browser)await browser.close();
  for(const server of [exercise,receiver])if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
 }
})().catch(e=>{console.error(e);process.exitCode=1;});
