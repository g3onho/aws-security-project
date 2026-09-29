import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {ok, install, loadD3Force, steps} from './honeypot-fixtures.mjs';

// 차단까지 기록된 공격: 문(gate)이 닫히고 선 9개가 모두 켜진다(한 파일에 appDOM 은 하나).
test('attack path map turns the gate closed only when the NACL block is recorded',async t=>{
 const network=makeFetchMock();
 const all=steps().map(s=>({...s,state:'done',at:s.at||1750000000000}));
 install(network,{timeline:{ip:'10.0.2.55',steps:all,sessions:[]}});
 const {dom,w,$,click}=appDOM(network);t.after(()=>dom.window.close());
 loadD3Force(w);
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 click('nav [data-view="honeypot"]');
 await until(()=>$('#honeypot .hp-map-list'),'map did not render');
 assert.equal($('.hp-mp-gate').dataset.gate,'closed');
 assert($('.hp-mp-cut'));
 assert.equal(document.querySelectorAll('.hp-mp-eg.done').length,9);
});
