import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {ok, install} from './honeypot-fixtures.mjs';

// 대시보드 도우미: 조회 전용 채팅. 공격자·모델 문자열은 텍스트로만 그려지고, 실패한 질문은 기록에 남지 않으며, 꺼져 있으면 사용 불가로 보인다.
test('assistant panel asks, escapes hostile answers, keeps history, and recovers from failures',async t=>{
 const network=makeFetchMock();install(network);
 const sent=[];let fail=false;
 network.respond('/api/assistant/status',()=>ok({enabled:true,model:'fake',readOnly:true,limits:{},tools:['overview']}));
 network.respond('/api/assistant/chat',call=>{
  const body=JSON.parse(call.options.body);sent.push(body.messages);
  if(fail)return {oops:'응답 형식이 계약과 다름'};   // fetch 목은 항상 200 — 계약 위반 응답이 오류 경로를 탄다
  const last=body.messages.at(-1).content;
  return ok({answer:last.includes('해킹')?'<img src=x onerror="window.__pwn=1">\n둘째 줄':'접속까지 확인됩니다.',
   toolsUsed:[{name:'honeypot_timeline',args:{ip:'10.0.2.55'}},{name:'honeypot_timeline',args:{ip:'10.0.2.55'}}],usage:{inputTokens:1,outputTokens:1},truncated:false});
 });
 const {dom,w,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');

 // 처음엔 닫혀 있고 상태 조회도 하지 않는다(자동 호출 없음).
 assert.equal($('#assistant-panel').hidden,true);
 assert.equal(network.count('/api/assistant/status'),0);
 click('#assistant-fab');
 await until(()=>$('#assistant-panel .as-intro'),'panel did not open with status');
 assert.equal($('#assistant-panel').hidden,false);
 assert.equal($('#assistant-fab').getAttribute('aria-expanded'),'true');
 assert(/읽기 전용/.test($('#assistant-panel').textContent));
 assert($('#assistant-panel .as-sug'),'suggestions are shown');

 // 질문 → 답. 도구 칩은 중복 없이 한 번만.
 const ask=q=>{const input=$('#assistant-panel .as-input');input.value=q;$('#assistant-panel .as-form').dispatchEvent(new w.Event('submit',{cancelable:true,bubbles:true}));};
 ask('10.0.2.55 뭐 했어?');
 await until(()=>$('#assistant-panel .as-bot:not(.as-typing)'),'no answer');
 assert.equal($('#assistant-panel .as-bot:not(.as-typing)').textContent.includes('접속까지 확인됩니다.'),true);
 assert.equal(document.querySelectorAll('#assistant-panel .as-chip').length,1);
 assert.equal(document.querySelector('#assistant-panel .as-chip').textContent,'공격 타임라인 · 10.0.2.55');

 // 적대적 답변은 태그로 살아나지 않는다.
 ask('해킹?');
 await until(()=>document.querySelectorAll('#assistant-panel .as-bot:not(.as-typing)').length===2,'second answer missing');
 assert.equal(document.querySelector('#assistant-panel .as-bot img'),null);assert.equal(w.__pwn,undefined);
 assert(document.querySelectorAll('#assistant-panel .as-bot:not(.as-typing)')[1].textContent.includes('<img src=x'));
 // 두 번째 요청에는 이전 대화가 함께 간다(user/assistant 번갈아, user 로 끝).
 assert.deepEqual(sent[1].map(m=>m.role),['user','assistant','user']);

 // 실패한 질문은 기록에서 빠지고 입력창으로 돌아오며 오류가 보인다.
 fail=true;ask('세 번째');
 await until(()=>$('#assistant-panel [role=alert]'),'error not shown');
 assert.equal(document.querySelectorAll('#assistant-panel .as-user').length,2);
 assert.equal($('#assistant-panel .as-input').value,'세 번째');
 fail=false;ask('세 번째');
 await until(()=>document.querySelectorAll('#assistant-panel .as-bot:not(.as-typing)').length===3,'retry failed');
 assert.deepEqual(sent.at(-1).map(m=>m.role),['user','assistant','user','assistant','user']);

 // 새 대화, Esc 로 닫기(포커스는 버튼으로).
 click('[data-as-reset]');
 assert.equal(document.querySelectorAll('#assistant-panel .as-msg').length,0);
 $('#assistant-panel').dispatchEvent(new w.KeyboardEvent('keydown',{key:'Escape',bubbles:true}));
 assert.equal($('#assistant-panel').hidden,true);
 assert.deepEqual(errors,[]);
});
