import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, snapshot, makeFetchMock, appDOM} from './dom-test-support.mjs';

test('refresh keeps previous content on failure and accepts the next canonical response',async t=>{
 const network=makeFetchMock(),{dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content').textContent.includes('Contract test event'));
 network.respond('/api/events',()=>{throw Error('fixture unavailable');});
 click('#refresh');
 await until(()=>!$('#load-state').hidden&&$('#load-state').textContent.includes('fixture unavailable'));
 assert($('#content').textContent.includes('Contract test event'));
 network.respond('/api/events',()=>snapshot('Recovered event'));
 click('#retry');
 await until(()=>$('#content').textContent.includes('Recovered event'));
 assert.equal($('#load-state').hidden,true);
 assert(network.count('/api/events')>=3);
 assert.deepEqual(errors,[]);
});
