import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';

// 공격·대응 실습 1차(관측·구조): 카탈로그·지원상태·미연결 관측·빈 실행 이력을 표시하고
// 실제 실행 버튼이나 '0건/정상' 위장이 없어야 한다.
test('drills page renders catalog, support states, disconnected observation and an empty run history',async t=>{
 const network=makeFetchMock(),iso=new Date().toISOString();
 const envelope=data=>({data,meta:{schemaVersion:'1',asOf:iso,requestId:'fixture',partial:false,warnings:[]}});
 network.respond('/api/drills/catalog',()=>envelope({
  types:[
   {id:'web-scan',name:'웹 보안 검사',tool:'ZAP',kind:'attack',sources:['ZAP 결과','WAF 지표·로그'],note:'검사 성공은 침해 확정이 아니다.'},
   {id:'cpu-load',name:'CPU 부하 시험',tool:'stress',kind:'load',sources:['실제 CPU 사용률','CloudWatch 알람'],note:'부하 상승을 침해로 표기하지 않는다.'},
  ],
  scenarios:[
   {id:'SEC-01',purpose:'과도 공개 SSH SG',types:[],sources:['Config','Security Hub'],response:'SG 자동 회수',support:'observe-only',supportLabel:'조회 전용',observation:'disconnected',note:'구성 finding'},
   {id:'SEC-08',purpose:'DVWA 웹 공격/WAF',types:['web-scan'],sources:['ZAP','WAF'],response:'수동',support:'prep-needed',supportLabel:'준비 필요',observation:'disconnected',note:'ZAP 경로 신규'},
  ],
  environment:{dataSourceConnected:false,providerState:'not_configured',region:'ap-northeast-2',isolationVerified:'unknown',executionMode:'live'},
  supportLegend:{runnable:'실행 가능','prep-needed':'준비 필요','observe-only':'조회 전용','design-needed':'설계 필요'}}));
 network.respond('/api/drills',()=>envelope({items:[],nextCursor:null}));

 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content').textContent.includes('Contract test event'),'overview did not render');
 click('nav [data-view="drills"]');
 await until(()=>$('#drills')?.textContent.includes('SEC-08'),'drills catalog did not render');
 const text=$('#drills').textContent;
 assert(text.includes('웹 보안 검사')&&text.includes('CPU 부하 시험'),'실행 유형이 표시되어야 한다');
 assert(text.includes('조회 전용')&&text.includes('준비 필요'),'지원 상태 라벨이 표시되어야 한다');
 assert(text.includes('데이터 소스 미연결'),'미연결 관측 경고가 보여야 한다');
 assert(text.includes('기록된 실습 실행이 없습니다'),'빈 실행 이력을 정상 0건으로 위장하지 않는다');
 assert(!/실행 시작|공격 실행/.test(text),'1차 범위에는 실제 실행 버튼이 없어야 한다');
 // 카탈로그는 기간 필터를 쓰지 않는다(전역 필터·기간 트랙 숨김).
 assert.equal($('.filters').hidden,true,'실습 화면에서는 필터 바를 숨긴다');
 assert.equal($('.timeline').hidden,true,'실습 화면에서는 기간 막대를 숨긴다');
 assert.deepEqual(errors,[]);
});
