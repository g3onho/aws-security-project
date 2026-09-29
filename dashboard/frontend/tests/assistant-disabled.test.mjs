import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {ok, install} from './honeypot-fixtures.mjs';

// 꺼져 있으면 오류로 위장하지 않고 "사용할 수 없음"과 이유를 보여 주며, 입력은 잠긴다.
test('assistant shows an explicit unavailable state when the server has it disabled',async t=>{
 const network=makeFetchMock();install(network);
 network.respond('/api/assistant/status',()=>ok({enabled:false,model:null,readOnly:true,limits:{},tools:[]}));
 const {dom,$,click}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content').textContent.includes('Contract test event'),'overview did not render');
 click('#assistant-fab');
 await until(()=>$('#assistant-panel .as-bad'),'unavailable state missing');
 assert(/AI 도우미를 쓸 수 없습니다/.test($('#assistant-panel').textContent));
 assert.equal($('#assistant-panel .as-input').disabled,true);assert.equal($('#assistant-panel .as-send').disabled,true);
});
