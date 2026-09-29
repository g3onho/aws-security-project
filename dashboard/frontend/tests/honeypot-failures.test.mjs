import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {ok, install, loadD3Force, blocklist, blockItem, status, card} from './honeypot-fixtures.mjs';

// 한 원천을 못 읽어도 나머지는 보이고, 못 읽은 구역은 빈 값·정상이 아니라 '읽지 못함'이다. 경고·부분 결과도 숨기지 않는다.
test('a failing source only marks its own section as unreadable and warnings stay visible',async t=>{
 const network=makeFetchMock();install(network);
 network.respond('/api/honeypot/stats',()=>{throw Error('fixture unavailable');});
 network.respond('/api/blocklist',()=>ok(blocklist([blockItem('10.0.2.55')],{}),{partial:true,warnings:['NACL 을 읽지 못해 실제 차단 여부를 대조하지 못했습니다(Throttling). 표의 상태만 보입니다.']}));
 network.respond('/api/honeypot/status',()=>ok(status({verdict:{state:'unknown',label:'확인 불가',reasons:['허니팟 로그를 읽지 못함']},
  cards:{instance:card('ok','running','i-1'),logs:card('unknown','읽지 못함','AccessDenied',null),ai:card('unknown','읽지 못함','',null),alarm:card('ok','OK','a'),block:card('info','자동 차단 켜짐 · 아직 실행 없음')}})));
 const {dom,w,$,click,charts,errors}=appDOM(network);t.after(()=>dom.window.close());
 loadD3Force(w);
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 const client=await import(pathToFileURL(path.join(ROOT,'static/js/store/api/client.js')).href+'?v=local-2');client.setTimers({sleep:async()=>{}});
 await until(()=>$('#content .event-trend-widget'));
 click('nav [data-view="honeypot"]');
 await until(()=>$('[data-block]')&&$('.hp-steps'),'honeypot did not render');
 const text=$('#honeypot').textContent;
 // 통계는 읽지 못함 — 0 이나 빈 차트로 위장하지 않는다. 그래프·차트는 그리지 않는다.
 assert(text.includes('허니팟 통계을(를) 읽지 못했습니다')&&text.includes('확인 불가입니다'));
 assert.equal(charts.filter(c=>c.canvas.isConnected).length,0);
 assert.equal($('.hp-graph'),null);
 // 나머지 구역은 정상 표시
 assert.equal($('.hp-verdict').dataset.verdict,'unknown');
 assert.equal(document.querySelector('[data-card="logs"]').dataset.state,'unknown');
 assert(document.querySelectorAll('[data-session]').length>0,'sessions still shown');
 assert.equal(document.querySelectorAll('[data-block]').length,1);
 // 서버 경고가 그대로 보인다
 assert(document.querySelector('#hp-blocklist .hp-warn').textContent.includes('NACL 을 읽지 못해'));
 // 통계 없이도 타임라인 IP 선택은 차단 목록에서 온다
 assert.equal(document.querySelector('[data-hp-select]').value,'10.0.2.55');
 assert.deepEqual(errors,[]);
});
