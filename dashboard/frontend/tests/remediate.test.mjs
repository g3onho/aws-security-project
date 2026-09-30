import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {envelope, iso, detailedEvents} from './detail-fixtures.mjs';

// v29: 탐지 상세의 '대시보드 조치' — 확인창에서 사유를 적고 바로 실행. 실행 성공을 해결로 표시하지 않는다.
const plan={eventId:'EVT-0003',supported:true,eligible:true,reason:null,playbookId:'ASR-RevokeSecurityGroupIngress',title:'보안그룹 전체 공개 규칙 회수',
 change:'0.0.0.0/0 인바운드 규칙을 회수합니다.',criterion:'전체 공개 인바운드 규칙이 없음',parameters:{SecurityGroupId:'sg-0abc12345'},category:'manual',
 target:{resource:'arn:aws:ec2:::security-group/sg-0abc12345',region:'ap-northeast-2',accountId:'000000000000'},canExecute:true,canWrite:true,blockedReason:null,
 accountId:'000000000000',mode:'aws',current:{compliant:false,text:'전체 공개 인바운드 규칙 1개'},latest:[]};
const running={id:'rem-1',eventId:'EVT-0003',actor:'operator',state:'RUNNING',playbookId:plan.playbookId,title:plan.title,reason:'서비스 영향 없음',executionId:'exec-1',
 before:{text:'전체 공개 인바운드 규칙 1개'},verification:null,error:null,createdAt:iso(),updatedAt:iso()};

test('remediation confirm dialog requires a reason, sends one idempotent request and shows running, not resolved',async t=>{
 const network=makeFetchMock();
 network.respond('/api/events',detailedEvents);
 network.respond('/api/history',envelope({items:[],jobs:[],nextCursor:null}));
 network.respond('/api/events/EVT-0003/remediation',envelope(plan));
 network.respond('/api/events/EVT-0003/remediate',call=>{
  const body=JSON.parse(call.options.body);
  assert.deepEqual(Object.keys(body).sort(),['playbookId','reason'],'브라우저는 사유와 playbookId 만 보낸다');
  return envelope(running);
 });
 network.respond('/api/remediations',envelope({items:[running]}));
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 click('nav [data-view="events"]');
 await until(()=>$('#content .event-link'),'event list did not render');
 click('#content .event-link');
 await until(()=>$('#event-remediation [data-rem="open"]'),'조치 영역이 나타나지 않았다');
 const box=$('#event-remediation').textContent;
 assert(box.includes('보안그룹 전체 공개 규칙 회수')&&box.includes('재검증 기준')&&box.includes('현재 상태'));
 assert.equal($('#event-remediation [data-rem="open"]').disabled,false);
 click('#event-remediation [data-rem="open"]');
 await until(()=>$('#remediate-dialog').open,'확인창이 열리지 않았다');
 assert.equal($('#rem-run').disabled,true,'사유 없이는 실행할 수 없다');
 const reason=$('#rem-reason');reason.value='서비스 영향 없음';reason.dispatchEvent(new dom.window.Event('input',{bubbles:true}));
 assert.equal($('#rem-run').disabled,false);
 click('#rem-run');
 await until(()=>network.count('/api/events/EVT-0003/remediate')===1,'실행 요청이 한 번 나가야 한다');
 const call=network.calls.find(c=>c.pathname==='/api/events/EVT-0003/remediate');
 const key=call.options.headers instanceof dom.window.Headers||typeof call.options.headers?.get==='function'?call.options.headers.get('Idempotency-Key'):call.options.headers['Idempotency-Key'];
 assert(key&&key.length>=16,'Idempotency-Key 가 있다');
 await until(()=>$('#event-remediation').textContent.includes('실행 중'),'실행 중 상태가 표시되지 않았다');
 assert(!$('#event-remediation').textContent.includes('해결 확인'),'실행 접수를 해결로 표시하지 않는다');
 assert.equal($('#event-remediation [data-rem="open"]').disabled,true,'실행 중에는 다시 실행할 수 없다');
 assert.deepEqual(errors,[]);
});
