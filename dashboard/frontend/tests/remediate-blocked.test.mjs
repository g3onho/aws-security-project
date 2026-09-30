import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {envelope, detailedEvents} from './detail-fixtures.mjs';

// 실행할 수 없는 이유(권한·설정·대상)는 버튼을 잠그고 그 이유를 그대로 보여준다. 미지원 탐지는 사유만 표시한다.
test('blocked remediation locks the button and shows why',async t=>{
 const network=makeFetchMock();
 network.respond('/api/events',detailedEvents);
 network.respond('/api/history',envelope({items:[],jobs:[],nextCursor:null}));
 network.respond('/api/events/EVT-0003/remediation',envelope({eventId:'EVT-0003',supported:true,eligible:true,playbookId:'ASR-RevokeSecurityGroupIngress',
  title:'보안그룹 전체 공개 규칙 회수',change:'회수',criterion:'없음',parameters:{},category:'manual',target:{},canExecute:false,canWrite:false,
  blockedReason:'조치 실행은 조치 담당자(operator) 역할만 할 수 있습니다.',mode:'aws',latest:[]}));
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 click('nav [data-view="events"]');
 await until(()=>$('#content .event-link'),'event list did not render');
 click('#content .event-link');
 await until(()=>$('#event-remediation [data-rem="open"]'),'조치 영역이 나타나지 않았다');
 assert.equal($('#event-remediation [data-rem="open"]').disabled,true);
 assert($('#event-remediation').textContent.includes('operator'),'막힌 이유를 보여준다');
 assert.deepEqual(errors,[]);
});
