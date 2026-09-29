import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';

// v20.3: 이벤트 CSV 는 Store 가 행만 주고 화면(downloads.js)이 파일을 만든다.
test('event CSV button downloads through the screen helper with current filters',async t=>{
 const network=makeFetchMock();
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 // 화면 모듈은 전역 URL 을 쓴다(Node). 내려받기 호출만 가로챈다.
 const blobs=[];let clicked='';
 t.mock.method(URL,'createObjectURL',blob=>{blobs.push(blob);return 'blob:fixture';});t.mock.method(URL,'revokeObjectURL',()=>{});
 dom.window.HTMLAnchorElement.prototype.click=function(){clicked=this.download;};
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 click('nav [data-view="events"]');
 await until(()=>Boolean($('#export')),'export button is rendered');
 const before=network.count('/api/events');
 click('#export');
 await until(()=>clicked==='events.csv','events.csv is downloaded');
 assert(network.count('/api/events')>before,'export fetches the current event list');
 assert.equal(blobs.length,1);
 assert.equal($('#toast').hidden,true,'no error toast');
 assert.deepEqual(errors,[]);
});
