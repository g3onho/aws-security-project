// 화면 모듈이 함께 쓰는 것: Store 입구(actions·selectors), DOM 선택, 요청 표시, 화면 전용 상태, render·refresh 연결.
// Store 는 서버 데이터·필터, ui 는 화면 임시 상태(열린 상세 창 등). 화면 모듈끼리 순환 import 를 피하려고 render·refresh 는 hooks 로 잇는다(app.js 가 채운다).
import {store} from '../store.js?v=local-2';
import {createRequestActivity} from './components/request-activity.js?v=ui-1';
import {createNotificationPopover} from './components/notifications.js?v=ui-1';
// UI 는 Store 의 actions·selectors 만 쓴다(설계 2.1). state 는 읽기 전용 필터 화면 모델이고, 바꿀 때는 setFilters.
export const {actions:storeApi,selectors}=store;
export const state=selectors.filters(),summary=selectors.summary(),config=()=>selectors.config();
export const selectEvents=options=>selectors.events(options),metricsFor=()=>selectors.metrics(),servicesOf=()=>selectors.services();
export const setFilters=patch=>storeApi.setFilters(patch);
export const $=s=>document.querySelector(s);
export const $$=s=>[...document.querySelectorAll(s)];
export const activity=createRequestActivity($('#network-activity'));
// Track UI requests without changing either backend adapter or synchronous cache reads.
export const REQUEST_ACTIONS=['init','load','detail','change','job','eventHistory','vulnerabilities','history','logout','exportEvents','drillsCatalog','drills','startWebScan','webScanStatus','startRunAll','runAllStatus','runAllReport','honeypotStatus','honeypotSessions','honeypotSession','honeypotStats','honeypotTimeline','blocklist','blocklistRelease','blocklistPatch','assistantStatus','assistantChat'];
export const api=Object.fromEntries(REQUEST_ACTIONS.map(name=>[name,(...args)=>activity.run(()=>storeApi[name](...args))]));
api.get=id=>storeApi.get(id);
export const notifications=createNotificationPopover({button:$('#notifications'),panel:$('#notification-panel')});
export const ui={refreshSerial:0,activeId:null,approval:false,lastTrigger:null,operationBusy:false};
export const hooks={render:()=>Promise.resolve(),refresh:()=>Promise.resolve()};
