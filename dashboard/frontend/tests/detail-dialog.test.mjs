import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {envelope, iso, detailedEvents, SUMMARY} from './detail-fixtures.mjs';

// v23 화면 개편: 문제 → 왜 위험 → 고치는 법 → 고쳐졌나(조치 기록). 앱 모듈은 파일당 한 번만 뜨므로 화면마다 파일을 나눈다.
test('event detail explains the problem, links AWS docs, predicts automation and shows the remediation record',async t=>{
 const network=makeFetchMock();
 network.respond('/api/events',detailedEvents);
 network.respond('/api/history',call=>call.url.searchParams.get('eventId')==='EVT-0003'?envelope({items:[
  {id:'auto:ssm-1',source:'automatic',decision:'auto-executed',automationStatus:'SUCCESS',actionState:'EXECUTED',eventId:'EVT-0003',
   createdAt:iso(),lastSeenAt:iso(),occurrenceCount:1,reason:'보안그룹 전체 공개 규칙 회수(화이트리스트 + 태그)',
   execution:{status:'Success',removed:['TCP 3306 ← 0.0.0.0/0'],added:[],changed:true,source:'ssm-output',verification:'NOT_RUN'}}],jobs:[],nextCursor:null})
  :envelope({items:[],jobs:[],nextCursor:null}));
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 click('nav [data-view="events"]');
 await until(()=>$('#content .event-link'),'event list did not render');
 assert($('#content .event-link .auto-chip').textContent.includes('조건부 자동'),'목록에서 자동 조치 대상을 구분한다');
 click('#content .event-link');
 await until(()=>$('#event-dialog').open&&$('#dialog-content').textContent.includes('무엇이 문제인가'));
 const text=$('#dialog-content').textContent;
 assert.equal($('#dialog-title').textContent,'보안그룹이 위험 포트를 인터넷에 공개','팀 설명 제목을 먼저 보여준다');
 assert(text.includes('왜 위험한가')&&text.includes('어떻게 고치나')&&text.includes('고치는 곳'));
 assert(text.includes('AWS 원문')&&text.includes('unrestricted incoming traffic'),'AWS 원문을 따로 보여준다');
 const link=$('#dialog-content a.doc-link');
 assert.equal(link.getAttribute('href'),'https://docs.aws.amazon.com/console/securityhub/EC2.19/remediation');
 assert.equal(link.getAttribute('rel'),'noreferrer');assert.equal(link.getAttribute('target'),'_blank');
 assert(text.includes('조건부 자동')&&text.includes('AutoRemediation=enabled'));
 assert(!$('#event-history'),'보안 이벤트 상세에는 조치 이력을 넣지 않는다');
 assert(!text.includes('조치 기록'));
 assert(!text.includes('측정값 없음'),'늘 비던 Before/After 칸은 없다');
 assert.deepEqual(errors,[]);
});
