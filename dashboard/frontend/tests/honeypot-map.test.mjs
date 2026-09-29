import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {ok, install, loadD3Force, steps} from './honeypot-fixtures.mjs';

// 공격 경로 지도: 타임라인 steps 를 아키텍처 위에 그린다. 상태는 색뿐 아니라 글자로도 나오고, 공격자 문자열은 텍스트로만 들어간다.
test('attack path map draws the eight stages from the timeline and never trusts hostile text',async t=>{
 const network=makeFetchMock();
 const hostile='<img src=x onerror="window.__pwn=1">';
 const list=steps().map(s=>s.key==='command'?{...s,detail:hostile}:s);
 install(network,{timeline:{ip:'10.0.2.55',steps:list,sessions:[]}});
 const {dom,w,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 loadD3Force(w);
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content').textContent.includes('Contract test event'),'overview did not render');
 click('nav [data-view="honeypot"]');
 await until(()=>$('#honeypot .hp-map-svg'),'map did not render');
 await until(()=>$('#honeypot .hp-map-list'),'map did not get timeline steps');
 const svg=$('#honeypot .hp-map-svg');

 // 8단계 배지와 글자 목록. 상태는 fixture 의 실제 값을 따른다(ssm 실패, nacl 기록 없음).
 const badges=[...svg.querySelectorAll('.hp-mp-badge')];
 assert.deepEqual(badges.map(b=>b.dataset.stage),['connect','auth','command','analysis','alarm','judge','ssm','nacl']);
 const state=k=>badges.find(b=>b.dataset.stage===k).dataset.state;
 assert.equal(state('connect'),'done');assert.equal(state('ssm'),'failed');assert.equal(state('nacl'),'missing');
 assert.equal(document.querySelectorAll('.hp-map-list li').length,8);
 assert(document.querySelector('.hp-map-list [data-stage="ssm"]').textContent.includes('실패'));

 // 기록이 없거나 실패한 단계의 선을 성공(완료)으로 그리지 않는다. 차단 문(gate)도 열린 채다.
 assert.equal(svg.querySelector('[data-edge="attack"]').dataset.state,'done');
 assert.equal(svg.querySelector('[data-edge="ssm"]').dataset.state,'failed');
 assert.equal(svg.querySelector('[data-edge="gate"]').dataset.state,'missing');
 assert.equal(svg.querySelector('.hp-mp-gate').dataset.gate,'open');
 assert.equal(svg.querySelector('.hp-mp-cut'),null);

 // 공격자가 조종하는 문자열은 태그로 살아나지 않는다.
 assert.equal(svg.querySelector('img'),null);assert.equal(document.querySelector('.hp-map-list img'),null);
 assert.equal(w.__pwn,undefined);
 assert(svg.querySelector('[data-stage="command"] title').textContent.includes('<img'));

 // 아키텍처 노드(고정 라벨)가 있다.
 for(const id of ['inner','honeypot','bedrock','logs','alarm','eb','lambda','ssm','ddb'])assert(svg.querySelector(`[data-node="${id}"]`),id);

 // 다시 재생 버튼은 애니메이션 클래스를 붙인다.
 click('[data-hp-replay]');
 assert.equal($('#hp-map .hp-map-svg').classList.contains('play'),true);
 assert.deepEqual(errors,[]);
});
