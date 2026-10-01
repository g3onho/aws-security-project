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


// 다른 서버에서 실행 중이면 [전부 실행]을 막는다(environment.activeRun). drills.js 는 모듈 상태를 가지므로 팝업 테스트와 파일을 나눈다.
test('run-all start is blocked while another server is running',async t=>{
 const network=makeFetchMock();
 const blocked=catalog(true,true);
 blocked.data.environment.activeRun={runId:'other-server-run',startedAt:Date.now()};
 network.respond('/api/drills/catalog',()=>blocked);
 network.respond('/api/drills',()=>env({items:[],nextCursor:null}));
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 click('nav [data-view="drills"]');
 await until(()=>$('#drills .drill-actions button'),'run panel did not render');
 const button=$('#drills .drill-actions .primary-button');
 assert.equal(button.disabled,true,'다른 서버 실행 중에는 버튼이 막힌다');
 assert.equal($('#drills [data-run-all-start]'),null);
 assert(button.textContent.includes('다른 서버에서 실행 중'));
 assert(!$('#drills .drill-actions').textContent.includes('최근 실행 보기'));
 assert.deepEqual(errors,[]);
});
