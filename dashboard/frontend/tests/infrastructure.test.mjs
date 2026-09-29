import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';

test('infrastructure uses standard metrics and component status fields',async t=>{
 const network=makeFetchMock();const iso=new Date().toISOString();
 const earlier=new Date(Date.now()-300000).toISOString(),twoHours=new Date(Date.now()-2*3600000).toISOString();
 network.respond('/api/metrics',{data:{series:[{resource:'i-fixture',name:'docker-host',region:'ap-northeast-2',metric:'cpu',unit:'%',collectionStatus:'available',observedAt:iso,instanceIds:['i-before','i-fixture'],points:[{timestamp:twoHours,value:10,instanceId:'i-before'},{timestamp:earlier,value:91,instanceId:'i-fixture'},{timestamp:iso,value:42,instanceId:'i-fixture'}]}],periodSeconds:300},meta:{schemaVersion:'1',asOf:iso}});
 network.respond('/api/infra/status',{data:{components:[{id:'one',name:'EC2',resource:'i-fixture',status:'healthy',source:'EC2',detail:'running',observedAt:iso}],dependencies:[]},meta:{schemaVersion:'1',asOf:iso}});
 const {dom,$,click,charts,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'));
 click('nav [data-view="infrastructure"]');
 await until(()=>$('#content .service-table')&&$('#content').textContent.includes('42%'),'infrastructure details did not render');
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
 const metricCall=network.calls.filter(call=>call.pathname==='/api/metrics').at(-1);
 assert.equal(Date.parse(metricCall.url.searchParams.get('to'))-Date.parse(metricCall.url.searchParams.get('from')),7*86400000);
 await until(()=>$('#time-label').textContent.includes('임계 초과'));
 assert.match($('#time-label').textContent,/임계 초과 1구간/);
 // 호스트 카드는 마지막 표본이 아니라 선택 기간의 평균·최대다 — 기간을 바꾸면 값도 바뀐다.
 // 기본 1일: (10+91+42)/3=47.7 → 1시간: 2시간 전 표본이 빠져 (91+42)/2=66.5
 assert.match($('.host-card').textContent,/1일 평균\s*47\.7%/);
 click('[data-hours="1"]');
 await until(()=>/1시간 평균\s*66\.5%/.test($('.host-card')?.textContent||''),'period change did not update host card');
 assert.match($('.host-card').textContent,/최대\s*91%/);
 const hourChart=charts.at(-1);
 assert.equal(hourChart.options.scales.x.max-hourChart.options.scales.x.min,3600000,'상세 x축은 선택한 1시간 전체를 표시한다');
 click('[data-hours="168"]');
 await until(()=>charts.at(-1)?.options.scales.x.max-charts.at(-1)?.options.scales.x.min===7*86400000,'1주일 x축이 선택 기간 전체로 바뀌어야 한다');
 assert(charts.at(-1).data.datasets[0].data.some(point=>point.x===Date.parse(twoHours)),'과거 CloudWatch 표본이 차트에 남아야 한다');
 assert(charts.at(-1).data.datasets[0].data.some(point=>point.x>Date.parse(twoHours)&&point.x<Date.parse(earlier)&&point.y===null),'수집되지 않은 시간은 선으로 이어 붙이지 않는다');
 assert($('#content').textContent.includes('이전 인스턴스 1개의 CloudWatch 기록을 연결했습니다'));
 assert(!charts.at(-1).data.datasets.some(dataset=>/서버 교체/.test(dataset.label)),'서버 교체 세로선은 그리지 않는다');
 assert(!$('#content').textContent.includes('서버 교체 시점'));
 const weekX=charts.at(-1).options.scales.x,weekAxis={min:weekX.min,max:weekX.max,ticks:[]};
 weekX.afterBuildTicks(weekAxis);
 assert(weekAxis.ticks.length>=27&&weekAxis.ticks.length<=29,'1주일 x축은 6시간 간격 눈금(28개 안팎)');

 // 기간별 눈금 간격(DEC-036): 15분=5분, 1시간=10분, 1일=2시간, 1주일=6시간, 모두 KST 정시 기준
 const {tickStepMs,alignedTicks}=await import(pathToFileURL(path.join(ROOT,'static/js/ui/pages/infrastructure.js')).href);
 assert.deepEqual([15*60000,3600000,86400000,7*86400000].map(tickStepMs),[300000,600000,7200000,21600000]);
 const base=Date.parse('2026-09-29T05:03:00Z');// KST 14:03
 assert.deepEqual(alignedTicks(base,base+3600000,600000).map(t=>new Date(t.value+9*3600000).getUTCMinutes()),[10,20,30,40,50,0]);
 assert.equal(alignedTicks(base-86400000,base,7200000).length,12,'1일은 2시간 간격 12~13개');
 assert(weekAxis.ticks.every((t,i)=>!i||t.value-weekAxis.ticks[i-1].value===6*3600000));
 assert.match(weekX.ticks.callback(Date.parse('2026-09-28T15:00:00Z')),/^9\/29$/,'KST 자정에는 날짜를 표시한다');
 assert.match(weekX.ticks.callback(Date.parse('2026-09-28T21:00:00Z')),/^06시$/);
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
