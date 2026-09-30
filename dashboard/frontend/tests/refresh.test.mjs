import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, snapshot, makeFetchMock, appDOM} from './dom-test-support.mjs';

test('refresh keeps previous content on failure and accepts the next canonical response',async t=>{
 const network=makeFetchMock(),{dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 // v20.3: GET 은 네트워크 오류 시 백오프 재시도한다. 테스트는 대기 없이 돌린다(app 과 같은 모듈 URL).
 const client=await import(pathToFileURL(path.join(ROOT,'static/js/store/api/client.js')).href+'?v=v42');
 client.setTimers({sleep:async()=>{}});
 await until(()=>$('#content .event-trend-widget'));
 const before=network.count('/api/events');
 network.respond('/api/events',()=>{throw Error('fixture unavailable');});
 click('#refresh');
 await until(()=>!$('#load-state').hidden&&$('#load-state').textContent.includes('서버에 연결할 수 없습니다'));
 // 이벤트 목록 두 개(선택 기간 + 기간 트랙용 1주일, v20.5)가 각각 정해진 횟수만 재시도한다.
 assert.equal(network.count('/api/events')-before,2*(1+client.RETRY.retries),'network errors are retried a bounded number of times');
 assert($('#content .event-trend-widget'),'최근 이벤트 시간대별 추이를 유지한다');
 network.respond('/api/events',()=>snapshot('Recovered event'));
 click('#retry');
 await until(()=>$('#load-state').hidden);
 click('nav [data-view="events"]');
 await until(()=>$('#content .event-link')?.textContent.includes('Recovered event'));
 assert.equal($('#load-state').hidden,true);
 assert(network.count('/api/events')>=3);
 assert.deepEqual(errors,[]);
});
