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
 // v20.5: 그래프는 기간과 관계없이 5분 평균, 인프라 화면은 기간 막대를 유지한다.
 assert(network.calls.filter(call=>call.pathname==='/api/metrics').every(call=>call.url.searchParams.get('periodSeconds')==='300'));
 assert(network.calls.filter(call=>call.pathname==='/api/infra/status').every(call=>!call.url.searchParams.has('periodSeconds')),'infra/status 는 periodSeconds 를 거절한다');
 assert.equal($('.timeline').hidden,false);
 // v20.5: 지표는 1주일을 받아 그래프는 선택 기간만, 기간 트랙은 임계 초과 구간 수를 센다.
 const metricCall=network.calls.find(call=>call.pathname==='/api/metrics');
 assert.equal(Date.parse(metricCall.url.searchParams.get('to'))-Date.parse(metricCall.url.searchParams.get('from')),7*86400000);
 await until(()=>$('#time-label').textContent.includes('임계 초과'));
 assert.match($('#time-label').textContent,/임계 초과 1구간/);
 assert.deepEqual(errors,[]);
});

test('a week of 5-minute samples is drawn as is; denser series are thinned to bucket maxima',async()=>{
 const {thinSeries}=await import(pathToFileURL(path.join(ROOT,'static/js/ui/pages/infrastructure.js')).href);
 const week=Array.from({length:2016},(_,i)=>({at:i}));
 assert.equal(thinSeries(week,week.map(()=>1),week.map(()=>1)).points.length,2016);
 const points=Array.from({length:10080},(_,i)=>({at:i}));
 const cpu=points.map((_,i)=>i%5?null:10),mem=points.map((_,i)=>i===5000?95:40);
 const out=thinSeries(points,cpu,mem);
 assert.ok(out.points.length<=2100&&out.points.length>1600);
 assert.equal(Math.max(...out.mem),95,'임계치 초과 표본이 묶여도 사라지지 않는다');
 assert.ok(out.cpu.every(v=>v===10),'5분 CPU 표본 사이 빈 값은 구간 최댓값으로 채워진다');
 const small=thinSeries(points.slice(0,60),cpu.slice(0,60),mem.slice(0,60));
 assert.equal(small.points.length,60);
});
