import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM, snapshot} from './dom-test-support.mjs';

test('canonical events, vulnerabilities, and history render without legacy requests',async t=>{
 const network=makeFetchMock(),iso=new Date().toISOString();
 network.respond('/api/events',()=>{
  const event=snapshot().data.items[0];
  return {data:{items:[{...event,observedAt:new Date(Date.now()-5*60000).toISOString()}],nextCursor:null},
   meta:{schemaVersion:'1',asOf:new Date(Date.now()-20*60000).toISOString()}};
 });
 network.respond('/api/vulnerabilities',()=>({data:{items:[
  ...['i-fixture','i-other','i-third'].map((resource,i)=>({id:`v-a-${i}`,cveId:'CVE-2026-0001',resource,severity:'HIGH',source:'Inspector',region:'ap-northeast-2',observedAt:iso,package:'fixture-package',fixedVersion:null})),
  {id:'v-b-1',cveId:'CVE-2026-0002',resource:'i-fixture',severity:'MEDIUM',source:'Inspector',region:'ap-northeast-2',observedAt:iso,package:'fixture-package',fixedVersion:'1.1'},
  {id:'v-b-2',cveId:'CVE-2026-0002',resource:'i-other',severity:'MEDIUM',source:'Inspector',region:'ap-northeast-2',observedAt:iso,package:'fixture-package',fixedVersion:null},
 ],nextCursor:null},meta:{schemaVersion:'1',asOf:iso}}));
 network.respond('/api/history',{data:{items:[],jobs:[{jobId:'job-1',eventId:'EVT-0003',status:'RUNNING',error:null,createdAt:iso}],nextCursor:null},meta:{schemaVersion:'1',asOf:iso}});
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 assert.equal($('#data-mode').hidden,true,'연결 정상이면 실데이터 표시를 숨긴다');
 await until(()=>$('#content .event-trend-chart'));
 assert.equal($('#content .event-trend-chart').getAttribute('role'),'img');
 assert($('#content .event-trend-widget').textContent.includes('시간대별 탐지 추이'));
 click('nav [data-view="events"]');
 await until(()=>$('#content .event-source-donut-widget')&&$('#content .event-link'));
 assert.equal($('#content .source-severity-ring').getAttribute('role'),'img');
 assert.equal($('#content .event-severity-filters').querySelectorAll('[data-event-severity]').length,4,'기존 위험도 버튼을 보존한다');
 click('#content .event-link');
 await until(()=>$('#event-dialog').open&&$('#dialog-content').textContent.includes('i-fixture'));
 assert($('#dialog-content').textContent.includes('무엇이 문제인가'));
 await until(()=>network.calls.some(call=>call.pathname==='/api/history'),'경로 지도용 기록은 Store 를 통해 읽는다');
 assert(!$('#event-history'),'상세에는 조치 기록 영역이 없다');
 assert(network.calls.some(call=>call.pathname==='/api/history'&&call.url.searchParams.get('eventId')==='EVT-0003'));
 assert.equal($('#dialog-content').querySelector('[data-action="approve"]'),null);
 click('#dialog-content [data-action="close"]');
 click('nav [data-view="vulnerabilities"]');
 await until(()=>$('#vulns')?.textContent.includes('CVE-2026-0001'),'vulnerability view did not render');
 assert($('#vulns').textContent.includes('Inspector'));
 assert($('#vulns .cve-group'),'CVE 는 서버×패키지 묶음으로 보여야 한다');
 assert.match($('#vulns .view-summary').textContent,/고유 CVE\s*2종\s*· 서버별 finding 5건/);
 assert.equal($('#vulns .vuln-summary').querySelectorAll('button').length,4,'요약 필터는 네 묶음만 보여준다');
 assert.match($('#vulns .vuln-summary').textContent,/높음\s*1/);
 assert.deepEqual([...$('#vulns .vuln-summary').querySelectorAll('button')].map(button=>[button.querySelector('span').textContent,button.querySelector('b').textContent]),[['긴급','0'],['높음','1'],['보통','1'],['낮음','0']]);
 click('#vulns [data-vuln-filter="HIGH"]');
 assert.equal($('#vulns [data-vuln-filter="HIGH"]').getAttribute('aria-pressed'),'true');
 assert.match($('#vulns .view-summary').textContent,/고유 CVE\s*1종\s*· 서버별 finding 3건/);
 click('#vulns [data-vuln-filter="HIGH"]');
 assert.match($('#vulns .view-summary').textContent,/고유 CVE\s*2종\s*· 서버별 finding 5건/);
 assert.equal($('#vuln-fixable'),null,'중복된 수정 버전 체크박스를 두지 않는다');
 assert.equal($('#severity').hidden,true,'취약점 화면에서는 위험도 선택창을 숨긴다');
 assert.equal($('#status').hidden,true,'취약점 화면에서는 상태 선택창을 숨긴다');
 assert.equal($('nav [data-view="incidents"]'),null,'설계 밖 침해사례 화면은 없어야 한다');
 click('nav [data-view="responses"]');
 await until(()=>$('#audit-log')?.textContent.includes('job-1'));
 assert($('#audit-log').textContent.includes('job-1'));
 assert($('#audit-log').textContent.includes('실행 중'));
 assert(network.calls.some(call=>call.pathname==='/api/history'));
 assert(network.calls.every(call=>!call.pathname.startsWith('/api/legacy/')));
 // v20.5: 취약점(현재 상태)은 화면 기간과 무관하게 계약 최대 구간(31일)으로 요청하고 기간 막대를 숨긴다. 대응 이력은 기간을 쓴다.
 const vulnCalls=network.calls.filter(call=>call.pathname==='/api/vulnerabilities');
 assert(vulnCalls.length&&vulnCalls.every(call=>Date.parse(call.url.searchParams.get('to'))-Date.parse(call.url.searchParams.get('from'))===31*86400000));
 assert(network.calls.filter(call=>call.pathname==='/api/history').every(call=>call.url.searchParams.has('from')));
 assert.equal($('.timeline').hidden,false,'대응 이력은 기간 막대를 보여준다');
 click('nav [data-view="vulnerabilities"]');
 await until(()=>$('.timeline').hidden===true,'취약점 화면은 기간 막대를 숨긴다');
 click('nav [data-view="events"]');
 await until(()=>$('.timeline').hidden===false,'이벤트 화면은 기간 막대를 보여야 한다');
 // 기간 트랙(v20.5): 지금 → 15분·1시간·1일·1주일 지점 = 기간 버튼. 트랙 지점을 누르면 버튼과 같이 바뀐다.
 assert.equal($('#time-range'),null,'옛 슬라이더는 없다');
 await until(()=>$('#period-track .pt-stop.active')!=null);
 assert.equal($('#period-track .pt-stop.active').dataset.hours,'24');
 assert.equal(dom.window.document.querySelectorAll('#period-track button.pt-stop').length,4);
 assert.ok(network.calls.some(call=>call.pathname==='/api/events'&&Date.parse(call.url.searchParams.get('to'))-Date.parse(call.url.searchParams.get('from'))===7*86400000),'누적 곡선용 1주일 목록');
 click('#period-track [data-hours="0.25"]');
 await until(()=>$('#time-label').textContent.includes('탐지 1건'),'적재 기준 시각이 오래돼도 조회된 15분 이벤트를 세어야 한다');
 assert.equal($('#period-track .pt-marker[data-period-count="0.25"]').textContent,'1');
 click('#period-track [data-hours="168"]');
 await until(()=>$('.time-presets [data-hours="168"]').classList.contains('active'),'트랙 지점과 버튼이 연동되어야 한다');
 await until(()=>network.calls.some(call=>call.pathname==='/api/events'&&Date.parse(call.url.searchParams.get('to'))-Date.parse(call.url.searchParams.get('from'))===7*86400000),'막대로 고른 기간으로 조회');
 assert.deepEqual(errors,[]);
});

test('period track: stops are evenly spaced left (now) to right (1 week) and counts are cumulative',async()=>{
 const {xOf,cumulative,periodTrackMarkup}=await import(pathToFileURL(path.join(ROOT,'static/js/ui/components/period-track.js')).href);
 const H=3600000;
 assert.equal(xOf(0),0);assert.equal(xOf(.25*H),125);assert.equal(xOf(H),312.5);assert.equal(xOf(24*H),600);assert.equal(xOf(168*H),1000);
 assert.ok(xOf(12*H)>312.5&&xOf(12*H)<600);
 const gaps=[125,187.5,287.5,400];assert.ok(gaps.every((g,i)=>!i||g>gaps[i-1]),'뒤로 갈수록 간격이 넓어진다');
 const now=Date.UTC(2026,8,25,2),rows=[{at:now-60000},{at:now-40*60000},{at:now-3*H},{at:now-3*24*H}];
 const ages=rows.map(r=>now-r.at);
 assert.deepEqual([.25,1,24,168].map(h=>cumulative(ages,h*H)),[1,2,3,4],'각 지점 = 그 기간 버튼의 건수');
 const html=periodTrackMarkup(rows.map(r=>r.at),1,now);
 assert.match(html,/data-hours="1" aria-label="최근 1시간 · 탐지 2건" aria-pressed="true"/);
 assert.match(html,/최근 1주일 · 탐지 4건/);
 assert.match(html,/<span class="pt-marker[^>]*data-period-count="0\.25"[^>]*>1<\/span>/,'각 기간의 건수를 그래프 지점 안에 표시한다');
 assert.match(html,/<span class="pt-marker[^>]*data-period-count="0"[^>]*>0<\/span>/,'지금 지점도 0을 사각 표식으로 표시한다');
 assert.doesNotMatch(html,/pt-count-layer|pt-dot/,'숫자 사각 표식으로 원형 지점을 대체한다');
 assert.match(html,/data-hours="1" aria-label="최근 1시간 · 탐지 2건" aria-pressed="true"/,'기간 버튼의 접근 가능한 이름에도 숫자를 포함한다');
 assert.match(periodTrackMarkup([now-2*H],24,now,{noun:'임계 초과',unit:'구간'}),/최근 1일 · 임계 초과 1구간/);
 assert.match(periodTrackMarkup(null,24,now,{noun:'대응 이력'}),/최근 1주일 · 대응 이력 …건/,'불러오는 중에는 0으로 단정하지 않는다');
});
