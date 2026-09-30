import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {envelope, iso, detailedEvents} from './detail-fixtures.mjs';

// 보안 이벤트 '대응 현황': 수동 대응(수동 대상 + 자동 조치 실패·후에도 열려 있음) / 직접 조치(대시보드 조치 없음). 진행 중인 것은 뺀다.
test('event response card splits open events into dashboard-actionable and direct-action ones',async t=>{
 const network=makeFetchMock();
 const cat=(category)=>({playbookId:'ASR-RevokeSecurityGroupIngress',title:'회수',category});
 network.respond('/api/events',()=>{
  const p=detailedEvents(),base=p.data.items[0];
  p.data.items=[
   {...base,id:'EVT-A',resource:'arn:aws:ec2:::security-group/sg-a',dashboardAction:cat('manual')},
   {...base,id:'EVT-B',resource:'arn:aws:ec2:::security-group/sg-b',dashboardAction:cat('auto-eligible')},
   {...base,id:'EVT-C',resource:'arn:aws:ec2:::security-group/sg-c',dashboardAction:cat('auto-eligible')},
   {...base,id:'EVT-D',resource:'arn:aws:ec2:::security-group/sg-d',dashboardAction:null},
  ];
  return p;
 });
 network.respond('/api/history',envelope({items:[
  {id:'auto:b',source:'automatic',decision:'auto-executed',automationStatus:'FAILED',actionState:'EXECUTION_FAILED',eventId:'EVT-B',createdAt:iso(),lastSeenAt:iso(),findingType:'x',resource:'r'},
  {id:'auto:c',source:'automatic',decision:'auto-executed',automationStatus:'IN_PROGRESS',actionState:'EXECUTING',eventId:'EVT-C',createdAt:iso(),lastSeenAt:iso(),findingType:'x',resource:'r'}],jobs:[],remediations:[],nextCursor:null}));
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 click('nav [data-view="events"]');
 await until(()=>$('#content .manual-toggle')&&/수동 대응 2건/.test($('#content .manual-toggle').textContent),'보안 이벤트에는 카드 없이 수동 대응 버튼만 있다');
 assert.equal($('#content .event-response'),null,'보안 이벤트 화면에는 대응 현황 카드를 두지 않는다');
 // 대응 현황 카드는 조치 이력 화면의 기간 막대와 조치 이력 카드 사이에 있다.
 click('nav [data-view="responses"]');
 await until(()=>$('#content .event-response'),'조치 이력 화면에 대응 현황 카드가 보여야 한다');
 assert.equal($('#content').firstElementChild.querySelector('.event-response')!==null||$('#content').firstElementChild.id==='event-response-box',true,'카드가 조치 이력 카드보다 먼저 온다');
 // 자동 조치 이력을 읽고 나면 진행 중인 EVT-C 는 빠지고 실패한 EVT-B 는 수동 대응에 든다.
 await until(()=>$('#content .er-manual b').textContent==='2건','수동 대응 2건(수동 대상 + 자동 실패)');
 assert.equal($('#content .er-direct b').textContent,'1건');
 assert($('#content .er-manual').title.includes('자동 조치 실패 1')&&$('#content .er-manual').title.includes('진행 중 1건은 제외'));
 assert($('#content .er-foot')===null&&!$('#content .er-direct').textContent.includes('목록 보기'),'확인 기준은 재검증이 아니라 이벤트가 사라지는지');
 click('#content .er-direct');
 await until(()=>$('#bulk-dialog').open&&$('#bulk-dialog').textContent.includes('직접 조치 1건'),'직접 조치 목록이 열려야 한다');
 assert.equal($('#bulk-dialog').querySelectorAll('input[type=checkbox]').length,0,'직접 조치는 고르거나 실행하지 않는다');
 click('#bulk-dialog [data-bulk="close"]');
 click('#content .er-manual');
 await until(()=>$('#bulk-dialog').open&&$('#bulk-dialog').querySelectorAll('.bulk-item').length===2,'수동 대응 팝업');
 const text=$('#bulk-dialog').textContent;
 assert(text.includes('자동 조치 실패')&&text.includes('수동 대응 필요'));
 assert.deepEqual(errors.filter(e=>!/plan|remediation/i.test(String(e))),[]);
});
