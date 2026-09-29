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
 scenarios:[scenario('SEC-01','과도 공개 SSH SG','observe-only','조회 전용'),scenario('SEC-02','서비스 포트·헤더'),scenario('SEC-08','DVWA 웹 공격/WAF'),scenario('SEC-06B','SSH 무차별 대입'),scenario('SEC-10','CPU·메모리 과부하')],
 environment:{dataSourceConnected:connected,providerState:connected?'connected':'not_configured',region:'ap-northeast-2',isolationVerified:'unknown',executionMode:'live',webScanReady},
 supportLegend:{'prep-needed':'준비 필요','observe-only':'조회 전용'}});

// 앱 모듈은 프로세스당 한 번만 초기화되므로 별도 파일로 둔다.
test('run-all is disabled and explained when the data source is not connected',async t=>{
 const network=makeFetchMock();
 network.respond('/api/drills/catalog',()=>catalog(false,false));
 network.respond('/api/drills',()=>env({items:[],nextCursor:null}));
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 click('nav [data-view="drills"]');
 await until(()=>$('#drills .drill-scenario-table'),'drills did not render');
 assert.equal($('#drills [data-run-all-start]'),null);
 assert($('#drills .primary-button').disabled);
 assert($('#drills').textContent.includes('데이터 소스 미연결')&&$('#drills').textContent.includes('경로 미연결'));
 assert.equal(network.count('/api/drills/run-all/start'),0);
 assert.deepEqual(errors,[]);
});
