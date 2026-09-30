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

// 진행 팝업: 닫아도 실행은 계속되고, [실행 중 · 진행 보기]로 다시 열 수 있다. 이력의 [보고서]는 지난 실행을 같은 팝업에 연다.
test('run popup can be closed and reopened, and history rows open a report popup',async t=>{
 const network=makeFetchMock();
 network.respond('/api/drills/catalog',()=>catalog(true,true));
 network.respond('/api/drills/run-all/start',()=>env({runId:'run-1',launched:[{sec:'SEC-08'}],skipped:[]}));
 network.respond('/api/drills/run-all/run-1/status',()=>env({runId:'run-1',skipped:[],items:[{sec:'SEC-08',label:'SEC-08 · 도쿄',status:'InProgress'}]}));
 network.respond('/api/drills/run-all/old-1/status',()=>env({runId:'old-1',skipped:[],items:[{sec:'SEC-08',label:'SEC-08 · 시드니',status:'Success'}]}));
 network.respond('/api/drills',()=>env({items:[{runId:'old-1',type:'run-all',title:'전부 실행',secs:['SEC-08'],state:'접수',createdAt:iso}],nextCursor:null}));
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 click('nav [data-view="drills"]');
 await until(()=>$('#drills [data-run-all-start]'),'run-all button did not render');
 assert($('#drills [data-run-report="old-1"]'),'이력의 실행 ID 로 팝업을 연다');

 click('#drills [data-run-all-start]');
 await until(()=>$('#run-dialog').open&&$('#run-dialog-content').textContent.includes('실행 ID: run-1'),'popup did not open');
 assert($('#run-dialog [data-report-extract]'),'보고서 추출은 팝업 안에 있다');
 click('#run-dialog [data-run-close]');
 assert.equal($('#run-dialog').open,false,'닫을 수 있다');
 assert(/실행 중 · 진행 보기/.test($('#drills .drill-actions').textContent),'실행 중 버튼으로 다시 열 수 있다');
 click('#drills [data-run-open]');
 assert.equal($('#run-dialog').open,true);
 click('#run-dialog [data-run-close]');

 click('#drills [data-run-report="old-1"]');
 await new Promise(r=>setTimeout(r,500));await until(()=>$('#run-dialog').open&&$('#run-dialog-content').textContent.includes('SEC-08 · 시드니'),'past run popup did not open');
 assert($('#run-dialog-content').textContent.includes('실행 보고서')&&$('#run-dialog-content').textContent.includes('old-1'));
 assert.deepEqual(errors,[]);
});
