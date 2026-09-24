import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM, snapshot} from './dom-test-support.mjs';

// v20.3 (PR-5): Store 계층(설계 2.1·2.2) — client 재시도, 어댑터 행 단위 오류, Store 폴링, UI 경계.
const js=file=>pathToFileURL(path.join(ROOT,'static/js',file)).href+'?v=local-2';
const {adaptEvents}=await import(js('store/adapters/events.js'));
const {adaptVulnerabilities}=await import(js('store/adapters/vulnerabilities.js'));
const {adaptHistory}=await import(js('store/adapters/history.js'));
const client=await import(js('store/api/client.js'));
const {createPoller}=await import(js('store/polling.js'));
client.setTimers({sleep:async()=>{}});

const iso=new Date().toISOString();
const dto=(id,extra={})=>({id,title:'t-'+id,resource:'i-1',actionState:'PENDING_APPROVAL',observedAt:iso,severity:'HIGH',allowedActions:[],...extra});

test('event adapter drops only malformed rows and maps unknown severity to UNKNOWN with warnings',()=>{
 const {rows,warnings}=adaptEvents([dto('ok'),dto('odd',{severity:'SEVERE'}),{id:'broken'},dto('bad-state',{actionState:'DONE'}),dto('bad-time',{observedAt:'x'})]);
 assert.deepEqual(rows.map(r=>[r.id,r.severity]),[['ok','High'],['odd','Unknown']]);
 assert.equal(rows[0].status,'승인 대기');assert.equal(rows[0].at,Date.parse(iso));
 assert.deepEqual(warnings,['탐지 3건이 형식 오류로 목록에서 제외되었습니다.','탐지 1건의 위험도를 알 수 없어 Unknown으로 표시합니다.']);
 assert.equal(adaptEvents([dto('n',{actionable:false})]).rows[0].status,'탐지됨');
});

test('vulnerability and history adapters keep valid rows and report the rest',()=>{
 const v=adaptVulnerabilities([{id:'a',resource:'i-1',severity:'UNTRIAGED'},{id:'b',resource:'i-1',severity:'WEIRD'},{resource:'i-1'}]);
 assert.deepEqual(v.rows.map(r=>r.severity),['UNTRIAGED','UNKNOWN']);
 assert.equal(v.warnings.length,2);
 const h=adaptHistory([{id:'x'},{nope:1}],null);
 assert.deepEqual(h.rows.map(r=>r.id),['x']);assert.deepEqual(h.jobs,[]);assert.equal(h.warnings.length,1);
});

function fetchSequence(t,responses){
 const calls=[];
 t.mock.method(globalThis,'fetch',async(url,options)=>{calls.push(options.method||'GET');const next=responses.shift();if(next instanceof Error)throw next;
  return new Response(JSON.stringify(next.body??{}),{status:next.status??200,headers:{'Content-Type':'application/json'}});});
 return calls;
}

test('GET retries transient failures with bounded backoff, then succeeds',async t=>{
 const calls=fetchSequence(t,[{status:503},new TypeError('network'),{status:429},{body:{ok:true}}]);
 assert.deepEqual(await client.request('/api/events'),{ok:true});
 assert.equal(calls.length,4);
 for(let attempt=0;attempt<6;attempt++){const wait=client.backoff(attempt);assert(wait>0&&wait<=client.RETRY.maxMs,String(wait));}
});

test('GET gives up after the retry limit with a readable error',async t=>{
 const calls=fetchSequence(t,[{status:503},{status:503},{status:503},{status:503,body:{title:'잠시 후 다시'}}]);
 await assert.rejects(client.request('/api/events'),/잠시 후 다시/);
 assert.equal(calls.length,1+client.RETRY.retries);
});

test('changes and client errors are never retried',async t=>{
 const post=fetchSequence(t,[{status:503,body:{title:'실패'}}]);
 await assert.rejects(client.request('/api/events/a/approve',{method:'POST',body:'{}'}),/실패/);
 assert.equal(post.length,1);
 t.mock.restoreAll();
 const bad=fetchSequence(t,[{status:400,body:{title:'잘못된 필터'}}]);
 await assert.rejects(client.request('/api/events'),/잘못된 필터/);assert.equal(bad.length,1);
 t.mock.restoreAll();
 const aborted=fetchSequence(t,[new DOMException('stop','AbortError')]);
 const controller=new AbortController();controller.abort();
 await assert.rejects(client.request('/api/events',{signal:controller.signal}));assert(aborted.length<=1);
});

test('poller keeps one timer, pauses while hidden and catches up when visible again',async()=>{
 const doc=new EventTarget();doc.visibilityState='visible';
 let ticks=0,allow=true;const poller=createPoller({intervalMs:20,doc});
 poller.start(()=>ticks++,()=>allow);poller.start(()=>ticks++,()=>allow); // 두 번 켜도 타이머는 하나
 await new Promise(r=>setTimeout(r,70));const visibleTicks=ticks;assert(visibleTicks>=1&&visibleTicks<=6,String(visibleTicks));
 doc.visibilityState='hidden';doc.dispatchEvent(new Event('visibilitychange'));assert.equal(poller.armed,false);
 const hiddenStart=ticks;await new Promise(r=>setTimeout(r,60));assert.equal(ticks,hiddenStart,'no requests while hidden');
 doc.visibilityState='visible';doc.dispatchEvent(new Event('visibilitychange'));assert.equal(poller.armed,true);
 assert.equal(ticks,hiddenStart+1,'overdue refresh runs once on return');
 allow=false;const blocked=ticks;await new Promise(r=>setTimeout(r,50));assert.equal(ticks,blocked,'screen can veto a tick');
 poller.stop();assert.equal(poller.running,false);assert.equal(poller.armed,false);
});

test('Store modules never touch the DOM; event CSV is built by the screen',async()=>{
 const dir=path.join(ROOT,'static/js/store');
 const files=fs.readdirSync(dir,{recursive:true}).filter(f=>f.endsWith('.js'));
 for(const file of files)assert.doesNotMatch(fs.readFileSync(path.join(dir,file),'utf8'),/\bdocument\.(createElement|body|querySelector)|\.click\(\)|createObjectURL/,file);
 const {eventCsv}=await import(pathToFileURL(path.join(ROOT,'static/js/downloads.js')).href+'?v=local-5');
 const csv=eventCsv([{id:'E1',observedAt:iso,title:'=cmd()',severity:'HIGH',region:'ap-northeast-2',resource:'i-1',source:'GuardDuty',actionState:'PENDING_APPROVAL'}]);
 assert(csv.startsWith('\uFEFF"ID","발생 시각"'));
 assert(csv.includes('"\'=cmd()"'),'formula-looking cells are neutralised');
 assert.equal(csv.split('\r\n').length,2);
});

test('UI talks to the Store only through actions and selectors',()=>{
 const app=fs.readFileSync(path.join(ROOT,'static/js/app.js'),'utf8');
 assert.doesNotMatch(app,/\bstate\.[a-zA-Z]+\s*(\+|-)?=(?!=)/,'app.js must not assign filter state directly');
 assert.doesNotMatch(app,/Object\.assign\(state/);
 assert.doesNotMatch(app,/setInterval\(/,'polling belongs to the Store');
 const fetches=app.match(/\bfetch\(/g)||[];assert.equal(fetches.length,1,'only the static map geometry is fetched by the UI');
 assert.match(app,/import \{store\} from '\.\/store\.js/);
});

test('screen shows valid rows, reports skipped rows and uses accurate labels',async t=>{
 const network=makeFetchMock();
 network.respond('/api/events',()=>{const payload=snapshot();payload.data.items.push({id:'broken'},{...payload.data.items[0],id:'EVT-ODD',title:'Odd severity',severity:'SEVERE'});return payload;});
 const {dom,$,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content').textContent.includes('Contract test event'),'valid rows must still render');
 await until(()=>$('#worker-state').textContent.includes('1건이 형식 오류로 목록에서 제외'),'skipped row count must be visible');
 assert($('#worker-state').textContent.startsWith('조치 실행 비활성 · 조회 전용'));
 assert([...$('#source').options].some(o=>o.value==='IAM Access Analyzer'));
 assert.doesNotMatch($('.map-legend').textContent,/제공되지 않음/);
 assert.deepEqual(errors,[]);
});

