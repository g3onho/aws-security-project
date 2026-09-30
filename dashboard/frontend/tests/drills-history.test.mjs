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

test('run history shows the stored one-line summary and a report button; no SEC/type columns',async t=>{
 const network=makeFetchMock();
 network.respond('/api/drills/catalog',catalog);
 network.respond('/api/drills',()=>env({items:[
  {runId:'aaaaaaaa-2222-3333-4444-555555555555',type:'run-all',title:'전부 실행',secs:['SEC-02'],state:'접수',createdAt:iso,startedAt:Date.now(),summaryLine:'3개 항목 중 성공 2, 실패 1.',summarySource:'ai'},
  {runId:'bbbbbbbb-2222-3333-4444-555555555555',type:'run-all',title:'전부 실행',secs:[],state:'접수',createdAt:iso}],nextCursor:null}));
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 click('nav [data-view="drills"]');
 await until(()=>$('#drills .run-history'),'history did not render');
 const text=$('#drills .run-history').textContent;
 assert(text.includes('3개 항목 중 성공 2, 실패 1.')&&text.includes('AI 요약'));
 assert(text.includes('요약 없음'),'기존 실행은 요약 없음');
 assert(!text.includes('SEC 항목')&&!text.includes('유형'));
 assert.equal($('#drills .run-history [data-run-report]')!==null,true);
 assert.deepEqual(errors,[]);
});
