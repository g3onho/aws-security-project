import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';

test('infrastructure uses standard metrics and component status fields',async t=>{
 const network=makeFetchMock();const iso=new Date().toISOString();
 const earlier=new Date(Date.now()-300000).toISOString();
 network.respond('/api/metrics',{data:{series:[{resource:'i-fixture',name:'docker-host',region:'ap-northeast-2',metric:'cpu',unit:'%',collectionStatus:'available',observedAt:iso,points:[{timestamp:earlier,value:91},{timestamp:iso,value:42}]}],periodSeconds:300},meta:{schemaVersion:'1',asOf:iso}});
 network.respond('/api/infra/status',{data:{components:[{id:'one',name:'EC2',resource:'i-fixture',status:'healthy',source:'EC2',detail:'running',observedAt:iso}],dependencies:[]},meta:{schemaVersion:'1',asOf:iso}});
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content').textContent.includes('Contract test event'));
 click('nav [data-view="infrastructure"]');
 await until(()=>$('#content').textContent.includes('42%'),'metric value not rendered');
 assert($('#content').textContent.includes('healthy'));
 // 되살린 v17 화면: 호스트 카드 이름, 임계치(80%) 초과 구간 1개, CPU 최대값
 assert($('#content').textContent.includes('docker-host'));
 assert($('#content').textContent.includes('임계 초과 1구간'));
 assert($('#content').textContent.includes('최고 91%'));
 assert(network.calls.some(call=>call.pathname==='/api/metrics'));
 assert(network.calls.some(call=>call.pathname==='/api/infra/status'));
 assert.deepEqual(errors,[]);
});
