import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {ok, install, loadD3Force, blockItem, NOW} from './honeypot-fixtures.mjs';

// 허니팟 화면(v25): 상태 판정·타임라인·차트·그래프·세션 재생·차단 IP 관리(해제·기간·예외·보고서).
test('honeypot view shows status, timeline, charts, graph, sessions and the blocklist, and runs the release flow',async t=>{
 const network=makeFetchMock();install(network);
 const {dom,w,$,click,change,charts,errors}=appDOM(network);t.after(()=>dom.window.close());
 loadD3Force(w);let printed=0;w.print=()=>{printed++;};
 const downloads=[];
 const readBlob=blob=>new Promise((resolve,reject)=>{const r=new w.FileReader();r.onload=()=>resolve(r.result);r.onerror=reject;r.readAsText(blob);});
 w.URL.createObjectURL=blob=>{downloads.push(blob);return 'blob:fixture';};w.URL.revokeObjectURL=()=>{};
 globalThis.URL.createObjectURL=w.URL.createObjectURL;
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content').textContent.includes('Contract test event'),'overview did not render');
 click('nav [data-view="honeypot"]');
 await until(()=>$('#honeypot')?.textContent.includes('차단 IP 관리'),'honeypot did not render');
 await until(()=>$('.hp-steps'),'timeline did not render');
 const text=()=>$('#honeypot').textContent;

 // 화면 위치·공통 부품
 assert.equal($('nav [data-view="honeypot"]').textContent.includes('허니팟'),true);
 assert.equal($('.filters').hidden,true);assert.equal($('.timeline').hidden,false);
 assert.equal($('#page-title').textContent.includes('허니팟'),true);
 assert.equal($('#session-user').textContent,'admin · 조치 담당');

 // ① 동작 상태
 assert.equal($('.hp-verdict').dataset.verdict,'ok');assert(text().includes('정상 동작'));
 assert.deepEqual([...document.querySelectorAll('.hp-card')].map(c=>c.dataset.card),['instance','logs','ai','alarm','block']);

 // ② 타임라인: 각 단계 상태가 글자로도 구분된다(색만이 아니다)
 const steps=[...document.querySelectorAll('.hp-steps li')];
 assert.equal(steps.length,8);
 assert.equal(steps.find(s=>s.dataset.step==='ssm').textContent.includes('실패'),true);
 assert.equal(steps.find(s=>s.dataset.step==='nacl').textContent.includes('기록 없음'),true);
 assert(text().includes('"읽지 못함"은 원천을 읽지 못해'));

 // ③ 차트 6개
 const ids=charts.filter(c=>!c.destroyed&&c.canvas.isConnected).map(c=>c.canvas.id).sort();
 assert.deepEqual(ids,['hp-chart-commands','hp-chart-intents','hp-chart-ips','hp-chart-severity','hp-chart-timeline','hp-chart-users']);
 const byId=id=>charts.filter(c=>c.canvas.id===id).at(-1);
 assert.deepEqual(byId('hp-chart-commands').config.data.labels,['whoami','cat /etc/passwd']);
 assert.deepEqual(byId('hp-chart-severity').config.data.labels,['낮음','보통','높음','치명']);
 assert.equal(JSON.stringify(byId('hp-chart-users').config.data).includes('S3cret'),false);

 // ④ 그래프: 노드 4개(IP 1·세션 2·명령 1), 노드는 텍스트로 그려진다
 assert.equal(document.querySelectorAll('.hp-graph .hp-node').length,4);
 assert.equal(document.querySelectorAll('.hp-graph line').length,4);
 for(const n of document.querySelectorAll('.hp-graph .hp-node circle'))assert(Number.isFinite(+n.getAttribute('cx'))&&Number.isFinite(+n.getAttribute('cy')));

 // ⑤ 세션 목록·재생
 assert.equal(document.querySelectorAll('[data-session]').length,2);
 assert(text().includes('분석 없음'));
 click('[data-hp-session="a00000000001"]');
 await until(()=>$('.hp-terminal'),'session detail did not render');
 assert($('.hp-terminal').textContent.includes('$ cat /etc/passwd')&&$('.hp-terminal').textContent.includes('root:x:0:0'));
 assert(text().includes('가림 · 7자')&&!text().includes('S3cret!'),'passwords are masked by default');
 assert(text().includes('참고용 · 차단 판단에 쓰지 않음'));
 click('[data-hp-reveal]');
 await until(()=>text().includes('S3cret!'),'reveal did not show the password');
 assert.equal(network.calls.at(-1).url.searchParams.get('revealPasswords'),'true');
 click('[data-hp-reveal]');
 await until(()=>$('.hp-terminal')&&!text().includes('S3cret!'),'password was not hidden again');
 click('[data-hp-close-detail]');assert.equal($('.hp-terminal'),null);

 // ⑥ 차단 IP 관리: 상태·불일치·기록 없음이 그대로 보인다
 const row=ip=>document.querySelector(`[data-block="${ip}"]`);
 assert.equal(row('10.0.2.55').dataset.state,'blocked');assert(row('10.0.2.55').textContent.includes('차단 중'));
 assert(row('10.0.2.56').textContent.includes('표에는 차단인데 NACL 에 Deny 가 없다'));
 assert(row('10.0.2.99').textContent.includes('표에 기록이 없다'));
 assert(row('10.0.2.56').textContent.includes('근거를 읽지 못함'),'unreadable evidence is not shown as zero');
 assert(row('10.0.2.99').textContent.includes('이 기간 미끼 세션 없음'));

 // 해제: 양식 → 사유 필수 → 전송(본문·헤더 확인) → 결과 안내 → 목록 재조회
 click('[data-hp-release="10.0.2.55"]');
 assert.equal($('[data-hp-form="release"]')!==null,true);
 const releases=network.calls.filter(c=>c.pathname==='/api/blocklist/10.0.2.55/release');
 click('[data-hp-submit]');await new Promise(r=>setTimeout(r,20));
 assert.equal(network.calls.filter(c=>c.pathname==='/api/blocklist/10.0.2.55/release').length,releases.length,'reason is required');
 $('[data-hp-reason]').value='사내 점검 도구';$('[data-hp-allowlist]').checked=true;
 const listCalls=network.count('/api/blocklist');
 network.respond('/api/blocklist/10.0.2.55/release',()=>ok({ip:'10.0.2.55',state:'releasing',executionId:'exec-9',version:4}));
 click('[data-hp-submit]');
 await until(()=>$('.hp-message')?.textContent.includes('해제를 접수했습니다'),'release message missing');
 const post=network.calls.findLast(c=>c.pathname==='/api/blocklist/10.0.2.55/release');
 assert.equal(post.options.method,'POST');
 const headers=new Headers(post.options.headers);
 assert.match(headers.get('Idempotency-Key'),/^hp-[0-9a-f]{32}$/);assert.equal(headers.get('X-CSRF-Token'),'fixture-csrf');
 assert.deepEqual(JSON.parse(post.options.body),{reason:'사내 점검 도구',expectedVersion:2,allowlist:true});
 await until(()=>network.count('/api/blocklist')>listCalls,'blocklist was not reloaded');
 assert.equal($('[data-hp-form]'),null,'form closes after success');

 // 기간 변경
 click('[data-hp-period="10.0.2.55"]');
 change('[data-hp-duration]','168');
 $('[data-hp-reason]').value='조사 연장';
 network.respond('/api/blocklist/10.0.2.55',()=>ok({ip:'10.0.2.55',version:3}));
 click('[data-hp-submit]');
 await until(()=>$('.hp-message')?.textContent.includes('7일'.replace('7일','168시간')),'period message missing');
 const patch=network.calls.findLast(c=>c.pathname==='/api/blocklist/10.0.2.55'&&c.options.method==='PATCH');
 assert.deepEqual(JSON.parse(patch.options.body),{reason:'조사 연장',expectedVersion:2,durationHours:168});

 // 예외 등록
 click('[data-hp-allow="10.0.2.55"]');
 $('[data-hp-reason]').value='정상 스캐너';
 click('[data-hp-submit]');
 await until(()=>$('.hp-message')?.textContent.includes('오탐 예외를 등록'),'allowlist message missing');
 assert.deepEqual(JSON.parse(network.calls.findLast(c=>c.options.method==='PATCH').options.body),{reason:'정상 스캐너',expectedVersion:2,allowlisted:true});

 // 보고서: CSV·JSON 내려받기와 인쇄
 click('[data-hp-export="csv"]');
 const csv=await readBlob(downloads.at(-1));
 assert(csv.replace(/^\uFEFF/,'').startsWith('"IP","상태"')&&csv.includes('"10.0.2.55","blocked","HONEYPOT"'));
 click('[data-hp-export="json"]');
 assert.equal(JSON.parse(await readBlob(downloads.at(-1))).items.length,3);
 click('[data-hp-print]');
 assert.equal(printed,1);
 assert(document.querySelector('#hp-report').textContent.includes('허니팟 차단 IP 보고서'));
 assert.deepEqual(errors,[]);
});
