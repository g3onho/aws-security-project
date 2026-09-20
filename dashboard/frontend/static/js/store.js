import {createEvents, DEMO_NOW} from './data.js?v=2.2.2';
export const state={view:'overview',region:'ap-northeast-2',environment:'production',hours:24,severity:'',status:'',source:'',search:'',endOffset:0};
let events=createEvents();
export function selectEvents({ignoreRegion=false}={}){
 const end=DEMO_NOW-state.endOffset*3600000;
 return events.filter(e=>(ignoreRegion||state.region==='all'||e.region===state.region)&&e.environment===state.environment&&e.at>=end-state.hours*3600000&&e.at<=end&&(!state.severity||e.severity===state.severity)&&(!state.status||e.status===state.status)&&(!state.source||e.source===state.source)&&(!state.search||`${e.id} ${e.title} ${e.resource} ${e.scenario} ${e.sourceIp??''}`.toLowerCase().includes(state.search.toLowerCase()))).sort((a,b)=>b.at-a.at);
}
// Replace this adapter with authenticated application endpoints, never direct AWS credentials.
export const api={
 async load(){await new Promise(r=>setTimeout(r,260));return events;},
 get(id){return events.find(e=>e.id===id);},
 async execute(id){const e=this.get(id);if(!e||!['신규','승인 대기','재검증 실패'].includes(e.status))throw Error('현재 상태에서는 실행할 수 없습니다.');e.status='조치 실행 중';e.execution='실행 중';e.verification='미실행';e.afterValue=null;e.afterAt=null;e.history.push({at:Date.now(),text:'데모 조치 실행 시작'});await new Promise(r=>setTimeout(r,650));e.execution='성공';e.status='재검증 대기';e.history.push({at:Date.now(),text:'데모 조치 실행 성공 · 재검증 필요'});return e;},
 async verify(id){const e=this.get(id);if(!e||e.status!=='재검증 대기')throw Error('조치 실행 완료 후 재검증할 수 있습니다.');e.status='재검증 중';e.verification='검사 중';await new Promise(r=>setTimeout(r,650));const fail=e.source==='Trivy';e.afterValue=fail?2:e.unit==='%'?e.after:0;e.afterAt=Date.now();e.verification=fail?'실패':'통과';e.status=fail?'재검증 실패':'해결';e.history.push({at:e.afterAt,text:`동일 기준 재검증 ${e.verification}`});return e;}
};
export function toCSV(rows){
 const columns=[['ID','id'],['발생 시각','at'],['시나리오','scenario'],['제목','title'],['위험도','severity'],['리전','region'],['자원','resource'],['탐지 소스','source'],['대응 방식','mode'],['상태','status'],['실행 결과','execution'],['재검증','verification'],['출발 IP','sourceIp'],['위치 상태','geoStatus']];
 const cell=v=>'"'+String(v??'').replace(/^[=+@-]/,"'$&").replaceAll('"','""')+'"';
 return '\uFEFF'+[columns.map(c=>cell(c[0])).join(','),...rows.map(e=>columns.map(c=>cell(c[1]==='at'?new Date(e.at).toISOString():e[c[1]])).join(','))].join('\r\n');
}

