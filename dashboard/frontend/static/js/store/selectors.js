// 화면은 이 함수들이 돌려주는 화면 모델만 읽는다(설계 2.1-2).
import {data,filters,summary,requests,config,DATA_AS_OF} from './state.js?v=v46';
export const selectors=Object.freeze({
 events:({ignoreRegion=false}={})=>ignoreRegion?data.regional:data.rows,
 metrics:()=>data.metric,
 week:()=>data.week,
 metricWeek:()=>data.metricWeek,
 historyWeek:()=>data.historyWeek,
 services:()=>data.infra,
 summary:()=>summary,
 filters:()=>filters,
 config:()=>config,
 asOf:()=>DATA_AS_OF,
 request:kind=>requests[kind]||{status:'idle',lastUpdated:null,requestId:null,error:null},
});
