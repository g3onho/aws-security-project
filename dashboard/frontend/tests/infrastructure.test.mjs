import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';

test('infrastructure uses standard metrics and component status fields',async t=>{
 const network=makeFetchMock();const iso=new Date().toISOString();
 network.respond('/api/metrics',{data:{series:[{resource:'i-fixture',region:'ap-northeast-2',metric:'cpu',unit:'%',collectionStatus:'available',observedAt:iso,points:[{timestamp:iso,value:42}]}],periodSeconds:300},meta:{schemaVersion:'1',asOf:iso}});
 network.respond('/api/infra/status',{data:{components:[{id:'one',name:'EC2',resource:'i-fixture',status:'healthy',source:'EC2',detail:'running',observedAt:iso}],dependencies:[]},meta:{schemaVersion:'1',asOf:iso}});
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content').textContent.includes('Contract test event'));
 click('nav [data-view="infrastructure"]');
 await until(()=>$('#content').textContent.includes('42%'),'metric value not rendered');
 assert($('#content').textContent.includes('healthy'));
 assert(network.calls.some(call=>call.pathname==='/api/metrics'));
 assert(network.calls.some(call=>call.pathname==='/api/infra/status'));
 assert.deepEqual(errors,[]);
});
