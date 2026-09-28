import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';

// 공격·대응 실습 1차: 실행 유형을 고르면 그 유형 전용 설정·정보·연결 시나리오만 보인다.
test('drills shows type-specific settings and only the scenarios linked to the selected type',async t=>{
 const network=makeFetchMock(),iso=new Date().toISOString();
 const env=data=>({data,meta:{schemaVersion:'1',asOf:iso,requestId:'fixture',partial:false,warnings:[]}});
 network.respond('/api/drills/catalog',()=>env({
  types:[
   {id:'web-scan',name:'웹 보안 검사',tool:'ZAP',kind:'attack',sources:['ZAP 결과','WAF 지표·로그','Security Hub finding'],
    variants:[{id:'web-dvwa',name:'DVWA 웹 공격 검사',note:'SEC-08'},{id:'web-service',name:'서비스 웹 보안 설정 검사',note:'SEC-02'}]},
   {id:'sec-scenario',name:'보안 시나리오',tool:'SEC',kind:'scenario',sources:['시나리오별 관측 원천']},
   {id:'load',name:'부하 시험',tool:'stress',kind:'load',sources:['실제 CPU·메모리 사용률','CloudWatch 알람'],
    variants:[{id:'cpu-load',name:'CPU 부하 시험'},{id:'memory-load',name:'메모리 부하 시험'}]},
  ],
  scenarios:[
   {id:'SEC-01',purpose:'과도 공개 SSH SG',types:[],sources:['Config'],response:'SG 자동 회수',support:'observe-only',supportLabel:'조회 전용',observation:'disconnected'},
   {id:'SEC-08',purpose:'DVWA 웹 공격/WAF',types:['web-scan'],sources:['ZAP','WAF'],response:'수동',support:'prep-needed',supportLabel:'준비 필요',observation:'disconnected'},
   {id:'SEC-10',purpose:'CPU·메모리 과부하',types:['load'],sources:['CloudWatch'],response:'없음',support:'prep-needed',supportLabel:'준비 필요',observation:'disconnected'},
  ],
  environment:{dataSourceConnected:false,providerState:'not_configured',region:'ap-northeast-2',isolationVerified:'unknown',executionMode:'live'},
  supportLegend:{runnable:'실행 가능','prep-needed':'준비 필요','observe-only':'조회 전용','design-needed':'설계 필요'}}));
 network.respond('/api/drills',()=>env({items:[],nextCursor:null}));

 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content').textContent.includes('Contract test event'),'overview did not render');
 click('nav [data-view="drills"]');
 await until(()=>$('#drills')?.textContent.includes('실행 설정'),'drills did not render');

 // 세 유형 카드 + 미연결 안내가 보인다.
 let text=$('#drills').textContent;
 assert(text.includes('웹 보안 검사')&&text.includes('보안 시나리오')&&text.includes('부하 시험'),'세 실행 유형 카드');
 assert(text.includes('데이터 소스 미연결'),'미연결 안내');

 // 기본 선택은 첫 유형(웹 보안 검사): 전용 설정 + 연결 시나리오(SEC-08)만, SEC-10/SEC-01 은 아님.
 assert(text.includes('실행 설정 — 웹 보안 검사'),'웹 유형 설정');
 assert(text.includes('HTTP 403만으로'),'웹 유형 전용 주의');
 assert.equal($('#drills .drill-related'),null,'웹 유형에는 연결 시나리오 표를 두지 않는다');

 // 부하 시험 선택: 전용 설정 + SEC-10 만.
 click('[data-drill-type="load"]');
 await until(()=>$('#drills').textContent.includes('실행 설정 — 부하 시험'),'load 설정 미표시');
 text=$('#drills').textContent;
 assert(text.includes('강도·지속')&&text.includes('최소 10분'),'부하 전용 정보');
 assert.equal($('#drills .drill-related'),null,'부하 유형에는 연결 시나리오 표를 두지 않는다');

 // 보안 시나리오 선택: 전체 카탈로그(SEC-01·08·10 모두) + 시나리오 선택.
 click('[data-drill-type="sec-scenario"]');
 await until(()=>$('#drills').textContent.includes('보안 시나리오 카탈로그 (전체)'),'전체 카탈로그 미표시');
 text=$('#drills').textContent;
 const related=$('#drills .drill-related').textContent;
 assert(related.includes('SEC-01')&&related.includes('SEC-08')&&related.includes('SEC-10'),'보안 시나리오 유형에서만 전체 카탈로그');
 assert(text.includes('시나리오 선택'),'시나리오 선택 드롭다운');
 assert.equal($('.filters').hidden,true);assert.equal($('.timeline').hidden,true);
 assert(!/실행 시작|공격 실행/.test(text),'실제 실행 버튼 없음');
 assert.deepEqual(errors,[]);
});
