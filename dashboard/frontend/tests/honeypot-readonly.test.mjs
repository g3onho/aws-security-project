import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {install, loadD3Force} from './honeypot-fixtures.mjs';

// 팀장(approver)·일반 팀원(viewer) 계정: 변경 버튼이 없고 이유를 알려 주며, 그 안내가 서버 응답(canWrite=false)을 따른다.
test('read-only accounts get no change buttons and no password reveal',async t=>{
 const network=makeFetchMock();install(network,{role:'approver'});
 network.respond('/api/auth/session',()=>({user:{name:'leader',role:'approver'},csrfToken:'fixture-csrf'}));
 const {dom,w,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 loadD3Force(w);
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'));
 click('nav [data-view="honeypot"]');
 await until(()=>$('[data-block]')&&$('.hp-steps'),'honeypot did not render');
 assert.equal($('#session-user').textContent,'leader · 승인 담당');
 assert.equal(document.querySelectorAll('[data-hp-release],[data-hp-period],[data-hp-allow]').length,0);
 assert(document.querySelector('[data-block]').textContent.includes('권한 없음'));
 assert($('#hp-blocklist').textContent.includes('조치 담당 계정만 해제·기간 변경·예외 등록을 할 수 있습니다'));
 click('[data-hp-session="a00000000001"]');
 await until(()=>$('.hp-terminal'),'detail did not render');
 assert.equal($('[data-hp-reveal]'),null);
 assert($('.hp-detail').textContent.includes('조치 담당 계정만 볼 수 있습니다'));
 assert(document.querySelector('[data-hp-export="csv"]'),'reports can still be exported by read-only accounts');
 assert.deepEqual(errors,[]);
});
