import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';

// 회귀 방지: DATA_PROVIDER=none 처럼 공용 데이터 로드(events·summary)가 실패해도
// 보안 시나리오는 카탈로그만으로 렌더되어야 한다(실데이터 공급자 불필요).
test('drills renders even when the shared data load fails (disconnected provider)',async t=>{
 const base=makeFetchMock(),iso=new Date().toISOString();
 const env=data=>({data,meta:{schemaVersion:'1',asOf:iso,requestId:'fixture',partial:false,warnings:[]}});
 base.respond('/api/drills/catalog',()=>env({
  types:[{id:'web-scan',name:'웹 보안 검사',tool:'ZAP',kind:'attack',sources:['ZAP 결과'],
          variants:[{id:'web-dvwa',name:'DVWA 웹 공격 검사',note:'SEC-08'}]}],
  scenarios:[{id:'SEC-08',purpose:'DVWA 웹 공격/WAF',types:['web-scan'],sources:['ZAP','WAF'],response:'수동',
              support:'prep-needed',supportLabel:'준비 필요',observation:'disconnected'}],
  environment:{dataSourceConnected:false,providerState:'not_configured',region:'ap-northeast-2',isolationVerified:'unknown',executionMode:'live'},
  supportLegend:{'prep-needed':'준비 필요'}}));
 base.respond('/api/drills',()=>env({items:[],nextCursor:null}));
 // 미연결 백엔드: 데이터 조회는 503 처럼 실패한다(재시도 지연을 피하려 비재시도 500 응답 사용).
 const failing=new Set(['/api/events','/api/summary','/api/metrics','/api/infra/status','/api/history']);
 const network={...base, fetch:async(url,opts)=>{
  const p=new URL(String(url),'http://localhost/').pathname;
  if(failing.has(p))return {ok:false,status:500,json:async()=>({error:{code:'DATA_SOURCE_NOT_CONFIGURED',message:'실데이터 공급자가 연결되지 않았습니다.'},meta:{}})};
  return base.fetch(url,opts);
 }};
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('nav [data-view="drills"]'),'nav did not mount');
 click('nav [data-view="drills"]');
 await until(()=>$('#drills')?.textContent.includes('SEC-08'),'drills did not render while the data provider is disconnected');
 const text=$('#drills').textContent;
 assert(text.includes('보안 시나리오')&&text.includes('전부 실행')&&text.includes('실행 결과'),'전부 실행 UI가 미연결에서도 렌더되어야 한다');
 assert.equal($('#drills [data-run-all-start]'),null,'미연결이면 실행 버튼은 비활성이다');
 assert(text.includes('데이터 소스 미연결'),'미연결 안내가 보여야 한다');
 assert.equal($('#load-state').hidden,true,'drills 렌더 후 상단 오류 배너는 사라져야 한다');
 assert.deepEqual(errors,[]);
});
