// 화면 우측 상단 [로그 저장] · [AI 요약 보고서] (v28). 보안 이벤트·취약점 점검·인프라 모니터링·보안 시나리오·허니팟에서만 보인다.
// 두 버튼은 서로 독립이다(로그 저장은 AI 를 쓰지 않는다). 기존 패널 안의 CSV 버튼도 그대로 두고, 같은 함수를 다시 쓴다.
import {$,api,state,metricsFor,servicesOf} from '../context.js?v=v44';
import {toast} from './panel.js?v=v44';
import {eventCsv,downloadCsv,stampedName,infrastructureCsv,drillsCsv,honeypotSessionsCsv} from './downloads.js?v=v44';
import {hostViews} from '../pages/infrastructure.js?v=v44';
import {exportVulnerabilities} from '../pages/vulnerabilities.js?v=v44';
import {openReport,initReportDialog} from './report.js?v=v44';

export const EXPORT_VIEWS=new Set(['events','vulnerabilities','infrastructure','drills','honeypot']);
const iso=ms=>ms?new Date(ms).toISOString():'';
const SESSION_PAGE=200,SESSION_PAGES=5;          // 세션 CSV 는 최대 1000개까지(그 이상이면 알린다)
let saving=false;

export function syncPageExports(){
  const box=$('#page-exports');
  if(box)box.hidden=!EXPORT_VIEWS.has(state.view);
}

// 서버가 503(AI 기능 꺼짐)으로 답하면 그때 버튼을 잠근다. 화면을 열 때 상태를 미리 조회하지 않는다(도우미와 같은 원칙: 자동 호출 없음).
function lockReportButton(){
  const button=$('#page-ai-report');
  if(!button)return;
  button.disabled=true;
  button.title='AI 기능이 꺼져 있습니다';
}

async function honeypotSessions(){
  const items=[];let cursor=null,note='';
  for(let page=0;page<SESSION_PAGES;page++){
    const {data,warnings,partial}=await api.honeypotSessions({cursor,limit:SESSION_PAGE});
    items.push(...data.items);
    if(warnings?.length||partial)note='로그 일부를 읽지 못했거나 건너뛰었습니다. 화면의 경고를 확인하세요.';
    cursor=data.nextCursor||null;
    if(!cursor)return {items,note};
  }
  return {items,note:`세션이 많아 앞쪽 ${items.length}개만 저장했습니다. 기간을 줄여 다시 저장하세요.`};
}

export async function saveLog(){
  if(saving)return;
  const view=state.view;
  if(!EXPORT_VIEWS.has(view))return;
  saving=true;$('#page-log-save').disabled=true;
  try{
    if(view==='events'){
      const {items}=await api.exportEvents();
      downloadCsv(stampedName('events'),eventCsv(items));
    }else if(view==='vulnerabilities'){
      exportVulnerabilities(stampedName('vulnerabilities'));
    }else if(view==='infrastructure'){
      const hosts=hostViews(metricsFor());
      if(!hosts.length){toast('CPU·메모리 지표를 읽지 못했거나 대상이 없어 저장하지 않았습니다.');return;}
      downloadCsv(stampedName('infrastructure'),infrastructureCsv(hosts,servicesOf()));
    }else if(view==='drills'){
      const runs=await api.drills();
      downloadCsv(stampedName('drills'),drillsCsv(runs));
    }else if(view==='honeypot'){
      const {items,note}=await honeypotSessions();
      downloadCsv(stampedName('honeypot-sessions'),honeypotSessionsCsv(items,iso));
      if(note)toast(note);
    }
  }catch(error){
    toast(`로그를 읽지 못해 저장하지 않았습니다: ${error.message}`);
  }finally{
    saving=false;
    const button=$('#page-log-save');if(button)button.disabled=false;
  }
}

export function initPageExports(){
  initReportDialog({onDisabled:lockReportButton});
  $('#page-log-save')?.addEventListener('click',saveLog);
  $('#page-ai-report')?.addEventListener('click',()=>{if(EXPORT_VIEWS.has(state.view))openReport(state.view);});
  syncPageExports();
}
