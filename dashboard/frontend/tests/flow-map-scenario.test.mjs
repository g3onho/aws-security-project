import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';

const iso=new Date().toISOString();
const env=data=>({data,meta:{schemaVersion:'1',asOf:iso,requestId:'fixture',partial:false,warnings:[]}});
const sc=(id,src,resp)=>({id,purpose:'p '+id,types:[],sources:src,response:resp,support:'prep-needed',supportLabel:'준비 필요',observation:'connected'});

test('scenario route card draws a per-scenario map (no dialog); row button selects the scenario',async t=>{
 const network=makeFetchMock();
 network.respond('/api/drills/catalog',()=>env({types:[],scenarios:[sc('SEC-02',['Security Hub'],'수동 승인'),sc('SEC-10',['CloudWatch'],'없음')],
  environment:{dataSourceConnected:true,providerState:'connected',region:'ap-northeast-2',isolationVerified:'unknown',executionMode:'live',webScanReady:true},supportLegend:{}}));
 network.respond('/api/drills',()=>env({items:[],nextCursor:null}));
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 click('nav [data-view="drills"]');
 await until(()=>$('#drills #sc-map svg.scenario-svg'),'route card did not render');
 assert.equal($('#drills .drill-scenario-table tbody').children.length,2);
 assert.equal($('#sc-map [data-sc-select]').options.length,2);
 click('#drills [data-flow-toggle="SEC-10"]');
 await until(()=>$('#sc-map [data-sc-select]').value==='SEC-10','row button should select the scenario');
 assert.equal($('#sc-map li[data-stage="judge"]').dataset.state,'missing','대응 없음은 판정 단계 없음');
 click('#drills [data-flow-toggle="SEC-02"]');
 await until(()=>$('#sc-map [data-sc-select]').value==='SEC-02');
 assert.equal($('#sc-map .hp-mp-badge[data-stage="detect"]').dataset.state,'design','설계 경로는 관측 사실로 표시하지 않는다');
 assert.equal($('#sc-map li[data-stage="origin"]').dataset.state,'missing','실행 기록 없음');
 assert(/설계 경로/.test($('#sc-map').textContent));
 assert.equal($('#flow-dialog'),null,'경로 지도 팝업은 없다');
 assert.deepEqual(errors,[]);
});
