import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, snapshot, makeFetchMock, appDOM} from './dom-test-support.mjs';

test('refresh keeps previous content on failure and accepts the next canonical response',async t=>{
 const network=makeFetchMock(),{dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 // v20.3: GET 은 네트워크 오류 시 백오프 재시도한다. 테스트는 대기 없이 돌린다(app 과 같은 모듈 URL).
 const client=await import(pathToFileURL(path.join(ROOT,'static/js/store/api/client.js')).href+'?v=local-2');
 client.setTimers({sleep:async()=>{}});
 await until(()=>$('#content').textContent.includes('Contract test event'));
 const before=network.count('/api/events');
 network.respond('/api/events',()=>{throw Error('fixture unavailable');});
 click('#refresh');
 await until(()=>!$('#load-state').hidden&&$('#load-state').textContent.includes('서버에 연결할 수 없습니다'));
 // 이벤트 목록 두 개(선택 기간 + 기간 트랙용 1주일, v20.5)가 각각 정해진 횟수만 재시도한다.
 assert.equal(network.count('/api/events')-before,2*(1+client.RETRY.retries),'network errors are retried a bounded number of times');
 assert($('#content').textContent.includes('Contract test event'));
 network.respond('/api/events',()=>snapshot('Recovered event'));
 click('#retry');
 await until(()=>$('#content').textContent.includes('Recovered event'));
 assert.equal($('#load-state').hidden,true);
 assert(network.count('/api/events')>=3);
 assert.deepEqual(errors,[]);
});
