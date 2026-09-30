import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';

const iso=new Date().toISOString();
const env=data=>({data,meta:{schemaVersion:'1',asOf:iso,requestId:'fixture',partial:false,warnings:[]}});
const sc=(id,src,resp)=>({id,purpose:'p '+id,types:[],sources:src,response:resp,support:'prep-needed',supportLabel:'준비 필요',observation:'connected'});

const catalog=()=>env({types:[],scenarios:[sc('SEC-02',['Security Hub'],'수동 승인'),sc('SEC-10',['CloudWatch'],'없음'),sc('SEC-01',['AWS Config','Security Hub'],'SG 자동 회수')],
 environment:{dataSourceConnected:true,providerState:'connected',region:'ap-northeast-2',isolationVerified:'unknown',executionMode:'live',webScanReady:true},supportLegend:{}});

test('route map opens in a dialog, differs per scenario, and never paints unobserved steps as done',async t=>{
 const network=makeFetchMock();
 network.respond('/api/drills/catalog',catalog);
 network.respond('/api/drills',()=>env({items:[],nextCursor:null}));
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 click('nav [data-view="drills"]');
 await until(()=>$('#drills [data-flow-toggle="SEC-02"]'),'toggle did not render');
 assert.equal($('#sc-map'),null,'페이지에 지도 카드는 없다(팝업)');
 assert.equal($('#flow-dialog').open,false,'처음에는 팝업이 닫혀 있다');
 click('#drills [data-flow-toggle="SEC-02"]');
 await until(()=>$('#flow-dialog #flow-SEC-02 svg.scenario-svg'),'map did not open');
 assert.equal($('#flow-dialog').open,true);
 assert.equal($('#flow-dialog .hp-mp-badge[data-stage="detect"]').dataset.state,'design','탐지 원천이 없으면 설계 경로');
 assert.equal($('#flow-dialog li[data-stage="origin"]').dataset.state,'missing','실행 기록 없음');
 const sec02=$('#flow-dialog svg').innerHTML;
 $('#flow-dialog [data-sc-select]').value='SEC-01';$('#flow-dialog [data-sc-select]').dispatchEvent(new dom.window.Event('change',{bubbles:true}));
 await until(()=>$('#flow-dialog #flow-SEC-01 svg.scenario-svg'),'scenario switch');
 assert.notEqual($('#flow-dialog svg').innerHTML,sec02,'시나리오마다 다른 경로');
 assert.equal($('#flow-dialog li[data-stage="detect"]').dataset.state,'design','실행 기록이 없으면 이벤트를 찾지 않고 설계 경로로만 둔다(완료로 칠하지 않는다)');
 click('#flow-dialog button[data-flow-close]');
 await until(()=>!$('#flow-dialog').open,'map did not close');
 assert.equal(dom.window.document.activeElement.dataset.flowToggle,'SEC-01');
 assert.deepEqual(errors,[]);
});

