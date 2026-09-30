// Store 공개 진입점(설계 2.2). UI 는 store.actions·store.selectors·store.subscribe 만 쓴다.
// 구조: store/api(client·endpoints·validators) → store/adapters → store/state → store/selectors
// 아래의 옛 이름(state·api·selectEvents 등)은 기존 호환 검사(backend/tests/test_compat_store.mjs)를 위해 남긴다.
import {actions,subscribe,query,request,reset} from './store/actions.js?v=v45';
import {selectors} from './store/selectors.js?v=v45';
export {filters as state,config,summary,DATA_AS_OF} from './store/state.js?v=v45';
export const store=Object.freeze({actions,selectors,subscribe});
export {query,request};
// 세션·필터·데이터·폴링을 처음 상태로(로그아웃과 같은 초기화). 하위 모듈은 한 번만 로드되므로 테스트도 이걸 쓴다.
export const resetStore=reset;
export const api=actions;
export const selectEvents=options=>selectors.events(options);
export const metricsFor=()=>selectors.metrics();
export const servicesOf=()=>selectors.services();
