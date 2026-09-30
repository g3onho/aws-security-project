import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';

const iso=new Date().toISOString();
const env=data=>({data,meta:{schemaVersion:'1',asOf:iso,requestId:'fixture',partial:false,warnings:[]}});
const scenario=(id,purpose,support='prep-needed',label='준비 필요')=>({id,purpose,types:[],sources:['원천'],response:'수동',support,supportLabel:label,observation:'disconnected'});
const catalog=(connected,webScanReady)=>env({
 types:[],
 scenarios:[scenario('SEC-05','노출 자격증명·과도 권한','observe-only','조회 전용'),scenario('SEC-02','서비스 포트·헤더'),scenario('SEC-08','DVWA 웹 공격/WAF'),scenario('SEC-06B','SSH 무차별 대입'),scenario('SEC-10','CPU·메모리 과부하')],
 environment:{dataSourceConnected:connected,providerState:connected?'connected':'not_configured',region:'ap-northeast-2',isolationVerified:'unknown',executionMode:'live',webScanReady},
 supportLegend:{'prep-needed':'준비 필요','observe-only':'조회 전용'}});

// 보안 시나리오: 선택 UI 없이 [전부 실행] 한 번으로 준비된 시나리오를 모두 실행한다.
test('security scenarios run everything with one button and no selection controls',async t=>{
 const network=makeFetchMock();
 network.respond('/api/drills/catalog',()=>catalog(true,true));
 network.respond('/api/drills',()=>env({items:[],nextCursor:null}));
 network.respond('/api/drills/run-all/start',()=>env({runId:'run-1',launched:[{sec:'SEC-02'},{sec:'SEC-08'},{sec:'SEC-10'}],skipped:['SEC-04: 대상 없음']}));
 network.respond('/api/drills/run-all/run-1/status',()=>env({runId:'run-1',skipped:['SEC-04: 대상 없음'],items:[
  {sec:'SEC-02',label:'포트·헤더',status:'Success',output:'ok'},
  {sec:'SEC-08',label:'DVWA 공격',status:'Failed',detail:'timeout'},
  {sec:'SEC-10',label:'부하',status:'InProgress'}]}));

 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 click('nav [data-view="drills"]');
 await until(()=>$('#drills [data-run-all-start]'),'run-all button did not render');

 let text=$('#drills').textContent;
 assert.equal($('nav .sidebar-nav-bottom [data-view="drills"]')?.textContent.includes('보안 시나리오'),true);
 assert.equal($('#drills select'),null,'시나리오·도구·대상 선택 컨트롤은 없다');
 assert.equal($('#drills [data-drill-scenario]'),null);
 assert(text.includes('전부 실행')&&text.includes('SEC-02')&&text.includes('SEC-10'));
 assert(text.includes('실행 결과'),'시나리오 표에 실행 결과 열');
 assert.equal($('#drills .drill-scenario-table tbody').children.length,4);
 assert(text.includes('실행 가능')&&text.includes('전부 실행 가능'));
 assert(text.includes('기록된 실행이 없습니다'),'예시 이력 없이 빈 상태를 표시');
 assert.equal($('.filters').hidden,true);assert.equal($('.timeline').hidden,true);

 click('#drills [data-run-all-start]');
 await until(()=>network.count('/api/drills/run-all/start')===1,'start was not called');
 const call=network.calls.find(c=>c.pathname==='/api/drills/run-all/start');
 assert.equal(call.options.method,'POST');
 assert.deepEqual(JSON.parse(call.options.body),{},'선택값 없이 빈 본문으로 전부 실행');
 await until(()=>$('#drills').textContent.includes('실행 ID: run-1'),'progress did not render');
 text=$('#drills').textContent;
 assert(text.includes('SEC-04: 대상 없음'),'건너뜀 사유 표시');
 const rows=[...$('#drills .drill-scenario-table tbody').children].map(tr=>tr.textContent);
 assert(rows.find(r=>r.includes('SEC-02')).includes('실행 중'),'시작 직후 접수 항목은 실행 중으로 표시');
 assert.equal(rows.some(r=>r.includes('SEC-05')),false,'전부 실행 대상이 아닌 시나리오는 표에서 뺀다');
 assert.deepEqual(errors,[]);
});
