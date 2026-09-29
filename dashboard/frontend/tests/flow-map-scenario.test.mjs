import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';

const iso=new Date().toISOString();
const env=data=>({data,meta:{schemaVersion:'1',asOf:iso,requestId:'fixture',partial:false,warnings:[]}});
const sc=(id,src,resp)=>({id,purpose:'p '+id,types:[],sources:src,response:resp,support:'prep-needed',supportLabel:'준비 필요',observation:'connected'});

test('scenario table opens a per-scenario flow map in a dialog and keeps focus on the toggle',async t=>{
 const network=makeFetchMock();
 network.respond('/api/drills/catalog',()=>env({types:[],scenarios:[sc('SEC-02',['Security Hub'],'수동 승인'),sc('SEC-10',['CloudWatch'],'없음')],
  environment:{dataSourceConnected:true,providerState:'connected',region:'ap-northeast-2',isolationVerified:'unknown',executionMode:'live',webScanReady:true},supportLegend:{}}));
 network.respond('/api/drills',()=>env({items:[],nextCursor:null}));
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 click('nav [data-view="drills"]');
 await until(()=>$('#drills [data-flow-toggle="SEC-02"]'),'toggle did not render');
 assert.equal($('#drills .drill-scenario-table tbody').children.length,2);
 assert.equal($('#flow-dialog').open,false,'처음에는 팝업이 닫혀 있다');
 click('#drills [data-flow-toggle="SEC-02"]');
 await until(()=>$('#flow-dialog #flow-SEC-02 svg.flow-svg'),'map did not open');
 assert.equal($('#flow-dialog').open,true);
 assert.equal($('#flow-dialog #flow-SEC-02 .hp-mp-badge[data-stage="detect"]').dataset.state,'design','설계 경로는 관측 사실로 표시하지 않는다');
 assert.equal($('#flow-dialog #flow-SEC-02 li[data-stage="origin"]').dataset.state,'missing','실행 기록 없음');
 assert(/설계된 경로/.test($('#flow-dialog #flow-SEC-02').textContent));
 click('#flow-dialog button[data-flow-close]');
 await until(()=>!$('#flow-dialog').open,'map did not close');
 assert.equal(dom.window.document.activeElement.dataset.flowToggle,'SEC-02');
 assert.deepEqual(errors,[]);
});
