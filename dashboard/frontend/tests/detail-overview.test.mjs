import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {envelope, iso, detailedEvents, SUMMARY} from './detail-fixtures.mjs';

// v23 화면 개편: 문제 → 왜 위험 → 고치는 법 → 고쳐졌나(조치 기록). 앱 모듈은 파일당 한 번만 뜨므로 화면마다 파일을 나눈다.
test('overview shows detection summary, only real sources and the automation card; shortcuts count real work',async t=>{
 const network=makeFetchMock();
 network.respond('/api/events',detailedEvents);network.respond('/api/summary',SUMMARY);
 const {dom,$,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content').textContent.includes('자동 대응 현황'),'automation card did not render');
 const text=$('#content').textContent;
 assert(!text.includes('재검증 완료율')&&!text.includes('CPU·메모리는 인프라 모니터링'),'늘 0 인 게이지·안내 문구는 없다');
 assert(!text.includes('승인 대기 상태'),'모든 탐지를 승인 대기로 세던 카드는 없다');
 assert(text.includes('자동 실행')&&text.includes('완료 1 · 실패 1')&&text.includes('VPC 기본 보안그룹에 규칙이 남아 있음'));
 assert(text.includes('열린 취약점(CVE)')&&text.includes('7건')&&text.includes('1건 발생'));
 assert(text.includes('Security Hub')&&!text.includes('Trivy'),'탐지가 없는 소스 막대는 그리지 않는다');
 assert.match(text,/자동 조치 대상\s*1건/,'조건부 자동도 자동 조치 대상으로 센다');
 assert.equal($('#notification-count').textContent,'4','자동 조치 실패 1 + 수동 대응 2 + 경보 1');
 assert.equal($('#worker-state').textContent,'','고정 상태 문구가 없다');
 assert(!$('#notification-panel').textContent.includes('승인 대기'));
 assert.deepEqual(errors,[]);
});
