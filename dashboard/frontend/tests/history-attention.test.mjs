import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';

// 요약은 '지금 봐야 할 것'을 알려 준다: 이벤트마다 마지막 시도가 실패했거나 재검증을 통과하지 못한 것. 나중에 성공한 이벤트는 뺀다.
const at=min=>new Date(Date.now()-min*60000).toISOString();
const run=(id,eventId,state,min)=>({id,eventId,actor:'op',state,playbookId:'ASR-X',title:'t',eventTitle:'이벤트 '+eventId,reason:'r',resource:'r-'+eventId,executionId:null,
 before:null,verification:null,error:state==='EXEC_FAILED'?'권한 부족':null,createdAt:at(min),updatedAt:at(min)});

test('history summary flags events whose latest attempt failed or did not verify, and ignores ones fixed later',async t=>{
 const network=makeFetchMock();
 network.respond('/api/history',{data:{items:[],jobs:[],nextCursor:null,external:[],remediations:[
  run('a1','EV-A','EXEC_FAILED',50),run('a2','EV-A','VERIFIED',10),      // 실패 뒤 성공 → 주의 아님
  run('b1','EV-B','EXEC_FAILED',5),                                         // 마지막 시도 실패 → 주의
  run('c1','EV-C','NOT_RESOLVED',20)]},                                     // 재검증 미통과 → 주의(다른 색)
  meta:{schemaVersion:'1',asOf:at(0),warnings:[]}});
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 click('nav [data-view="responses"]');
 await until(()=>$('#audit-log .history-summary'),'요약이 나타나야 한다');
 const box=$('#audit-log .history-summary');
 assert(box.classList.contains('bad'));
 assert(box.textContent.includes('마지막 시도가 실패한 이벤트 1건')&&!box.textContent.includes('재검증'),'재검증 표현은 이력에 쓰지 않는다');
 assert(box.textContent.includes('시도 4건(이벤트 3개)'));
 assert.equal($('#audit-log tbody').querySelectorAll('tr.attn-bad').length,1);
 assert.equal($('#audit-log tbody').querySelectorAll('tr.attn-warn').length,0);
 assert.deepEqual(errors,[]);
});
