import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {envelope, iso, detailedEvents} from './detail-fixtures.mjs';

// 수동 대응 팝업: 실행 가능한 것만 고르고, 사유 하나로 건마다 따로 실행한다. 접수를 해결로 표시하지 않는다.
const ids=['EVT-0003','EVT-0004','EVT-0005'];
const plan=(id,extra={})=>({eventId:id,supported:true,eligible:true,reason:null,playbookId:'ASR-RevokeSecurityGroupIngress',title:'보안그룹 전체 공개 규칙 회수',
 change:`${id} 규칙 회수`,criterion:'기준',parameters:{},category:'manual',target:{resource:'r-'+id,region:'ap-northeast-2',accountId:'000000000000'},
 canExecute:true,canWrite:true,blockedReason:null,accountId:'000000000000',mode:'aws',latest:[],...extra});
const run=id=>({id:'rem-'+id,eventId:id,actor:'op',state:'RUNNING',playbookId:'ASR-RevokeSecurityGroupIngress',title:'t',reason:'r',executionId:'e',before:null,verification:null,error:null,createdAt:iso(),updatedAt:iso()});

test('bulk popup runs only selected executable items, one idempotent request each, and reports partial failure honestly',async t=>{
 const network=makeFetchMock();
 network.respond('/api/events',()=>{
  const p=detailedEvents(),base=p.data.items[0];
  p.data.items=ids.map((id,i)=>({...base,id,resource:'arn:aws:ec2:::security-group/sg-000'+i,dashboardAction:{playbookId:'ASR-RevokeSecurityGroupIngress',title:'회수',category:'manual'}}));
  return p;
 });
 network.respond('/api/history',envelope({items:[],jobs:[],nextCursor:null}));
 network.respond('/api/events/EVT-0003/remediation',envelope(plan('EVT-0003')));
 network.respond('/api/events/EVT-0004/remediation',envelope(plan('EVT-0004')));
 network.respond('/api/events/EVT-0005/remediation',envelope(plan('EVT-0005',{canExecute:false,blockedReason:'AutoRemediation=enabled 태그가 없습니다.'})));
 network.respond('/api/events/EVT-0003/remediate',envelope(run('EVT-0003')));
 network.respond('/api/events/EVT-0004/remediate',()=>{throw new Error('서버가 거부했습니다');});
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 click('nav [data-view="events"]');
 await until(()=>$('#content .manual-toggle'),'토글이 없다');
 assert($('#content .manual-toggle').textContent.includes('수동 대응 3건'));
 click('#content .manual-toggle');
 await until(()=>$('#bulk-dialog').open&&$('#bulk-dialog').querySelectorAll('.bulk-item').length===3&&!$('#bulk-dialog').textContent.includes('확인 중'),'팝업 목록이 그려져야 한다');
 const boxes=[...$('#bulk-dialog').querySelectorAll('input[data-bulk-check]')];
 assert.deepEqual(boxes.map(b=>b.disabled),[false,false,true],'막힌 건은 고를 수 없다');
 assert($('#bulk-dialog').textContent.includes('AutoRemediation=enabled 태그가 없습니다.'),'막힌 사유를 보여준다');
 assert.equal($('#bulk-run').disabled,true,'선택·사유 없이는 실행할 수 없다');
 click('#bulk-dialog [data-bulk="all"]');
 assert($('#bulk-run').textContent.includes('선택 2건'));
 const reason=$('#bulk-reason');reason.value='서비스 영향 없음';reason.dispatchEvent(new dom.window.Event('input',{bubbles:true}));
 assert.equal($('#bulk-run').disabled,false);
 click('#bulk-run');
 await until(()=>$('#bulk-dialog').textContent.includes('1건 실패'),'부분 실패가 표시돼야 한다');
 assert.equal(network.count('/api/events/EVT-0003/remediate'),1);
 assert.equal(network.count('/api/events/EVT-0004/remediate'),1);
 assert.equal(network.count('/api/events/EVT-0005/remediate'),0,'막힌 건은 보내지 않는다');
 const key=id=>{const h=network.calls.find(c=>c.pathname===`/api/events/${id}/remediate`).options.headers;return typeof h?.get==='function'?h.get('Idempotency-Key'):h['Idempotency-Key'];};
 assert(key('EVT-0003')&&key('EVT-0004')&&key('EVT-0003')!==key('EVT-0004'),'건마다 다른 Idempotency-Key');
 const text=$('#bulk-dialog').textContent;
 assert(text.includes('실행 접수 · 재검증 대기')&&text.includes('접수는 해결이 아닙니다'));
 assert(!text.includes('해결 확인'),'접수를 해결로 표시하지 않는다');
 assert.equal($('#bulk-dialog').querySelector('input[data-bulk-check="EVT-0003"]').disabled,true,'접수된 건은 다시 실행할 수 없다');
 assert.equal($('#bulk-dialog').querySelector('input[data-bulk-check="EVT-0004"]').disabled,false,'실패한 건은 다시 고를 수 있다');
 assert.deepEqual(errors.filter(e=>!String(e).includes('서버가 거부')),[]);
});
