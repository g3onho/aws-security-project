// Store 상태(설계 2.2 상태 구성). 재할당이 필요한 값은 이 모듈의 setter 로만 바꾼다(ESM 바인딩 규칙).
export const FILTER_DEFAULTS=Object.freeze({view:'overview',region:'all',resource:'',environment:'',hours:24,severity:'',status:'',source:'',search:'',endOffset:0,page:1,auto:false});
const CONFIG_DEFAULTS=Object.freeze({mode:'live',writeEnabled:false,role:'viewer',dataSourceConnected:false});
export const filters={...FILTER_DEFAULTS};
export let config={...CONFIG_DEFAULTS};
export let DATA_AS_OF=0;
export const summary={};
export const data={rows:[],regional:[],metric:null,infra:null};
export const details=new Map();
// 조회 단위별 요청 상태: idle/loading/success/error, lastUpdated, requestId, error
export const requests={};
export const session={csrf:'',generation:0,epoch:0,controller:null,initializing:null};
export function setConfig(next){config=next;}
export function setAsOf(value){DATA_AS_OF=value;}
export function markRequest(kind,patch){
 requests[kind]={status:'idle',lastUpdated:null,requestId:null,error:null,...requests[kind],...patch};
}
export function resetState(){
 session.controller?.abort();session.generation++;session.epoch++;session.initializing=null;session.csrf='';
 DATA_AS_OF=0;Object.assign(data,{rows:[],regional:[],metric:null,infra:null});details.clear();
 for(const key of Object.keys(summary))delete summary[key];
 for(const key of Object.keys(requests))delete requests[key];
 config={...CONFIG_DEFAULTS};Object.assign(filters,FILTER_DEFAULTS);
}
