import assert from 'node:assert/strict';
import test from 'node:test';

const storeUrl=new URL('../../frontend/static/js/store.js',import.meta.url);
let serial=0;
// store/ 하위 모듈(상태)은 한 번만 로드된다 — 테스트마다 처음 상태로 되돌린다.
const fresh=async()=>{const store=await import(`${storeUrl.href}?test=${serial++}`);store.resetStore();return store;};
const at=new Date(Date.now()-60000).toISOString();
const event=(id='a')=>({id,title:'Observed '+id,resource:'i-1',region:'ap-northeast-2',
 source:'Security Hub',scenario:'SECURITY_HUB',severity:'HIGH',actionState:'PENDING_APPROVAL',
 observedAt:at,updatedAt:at,version:1,allowedActions:[],beforeState:null,afterState:null,verification:'NOT_RUN'});
const envelope=data=>({data,meta:{schemaVersion:'1',asOf:new Date().toISOString(),requestId:'test'}});
const json=data=>new Response(JSON.stringify(data),{status:200,headers:{'Content-Type':'application/json'}});

function fixture(t,override=()=>undefined){
 const calls=[];const oldLocation=Object.getOwnPropertyDescriptor(globalThis,'location');
 Object.defineProperty(globalThis,'location',{configurable:true,value:{assign(){}}});
 t.after(()=>oldLocation?Object.defineProperty(globalThis,'location',oldLocation):delete globalThis.location);
 t.mock.method(globalThis,'fetch',async(url,options={})=>{
  calls.push({url,options});const custom=override(url,options);if(custom!==undefined)return custom;
  const path=url.split('?')[0];
  if(path==='/api/auth/session')return json({user:{name:'viewer',role:'viewer'},csrfToken:'csrf'});
  if(path==='/api/auth/logout')return json({ok:true});
  if(path==='/api/events')return json(envelope({items:[event()],nextCursor:null}));
  if(path==='/api/summary')return json(envelope({totalEvents:1}));
  if(path==='/api/metrics')return json(envelope({series:[],thresholds:{cpu:80,memory:80},periodSeconds:300}));
  if(path==='/api/infra/status')return json(envelope({components:[],dependencies:[]}));
  if(path==='/api/vulnerabilities')return json(envelope({items:[],nextCursor:null}));
  if(path==='/api/history')return json(envelope({items:[],jobs:[],nextCursor:null}));
  if(path==='/health')return json(envelope({status:'ok',dataSourceConnected:true}));
  throw Error('Unexpected '+url);
 });
 return calls;
}

test('all screen reads use schema-v1 routes, envelope, ISO time and read-only mode',async t=>{
 const calls=fixture(t);const store=await fresh();store.state.view='infrastructure';
 await store.api.load();await store.api.vulnerabilities();await store.api.history();
 assert(calls.some(call=>call.url.startsWith('/api/events?')));
 assert(calls.some(call=>call.url.startsWith('/api/summary?')));
 assert(calls.some(call=>call.url.startsWith('/api/metrics?')));
 assert(calls.some(call=>call.url.startsWith('/api/infra/status?')));
 assert(calls.some(call=>call.url.startsWith('/api/history?')));
 assert(calls.every(call=>!call.url.startsWith('/api/legacy/')));
 assert.equal(store.selectEvents()[0].at,Date.parse(at));
 assert.equal(store.selectEvents()[0].status,'승인 대기');
 assert.equal(store.config.writeEnabled,false);
});

test('cursor pages are collected without treating first page as complete',async t=>{
 const calls=fixture(t,url=>{
  if(url.startsWith('/api/events?')){
   const cursor=new URL(url,'http://local').searchParams.get('cursor');
   return json(envelope({items:[event(cursor?'b':'a')],nextCursor:cursor?null:'next'}));
  }
 });
 const store=await fresh();await store.api.load();
 assert.deepEqual(store.selectEvents().map(row=>row.id),['a','b']);
 assert(calls.some(call=>call.url.includes('cursor=next')));
});

test('missing or malformed standard envelope is a visible error',async t=>{
 fixture(t,url=>url.startsWith('/api/summary?')?json({totalEvents:1}):undefined);
 const store=await fresh();await assert.rejects(store.api.load(),/형식/);
 assert.deepEqual(store.selectEvents(),[]);
});

test('actions remain unavailable while provider is read-only',async t=>{
 const calls=fixture(t);const store=await fresh();await store.api.load();
 const count=calls.length;await assert.rejects(store.api.change('a','approve'),/읽기 전용/);
 assert.equal(calls.length,count);
});
