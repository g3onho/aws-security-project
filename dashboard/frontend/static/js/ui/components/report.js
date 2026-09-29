// 화면별 AI 요약 보고서 대화상자(v28) — 조회 전용.
// 서버가 수치를 집계하고 모델은 문장만 쓴다. 이 파일은 서버가 준 문자열(모델 본문·이벤트 제목 등 공격자가 조종할 수 있는 값 포함)을
// 전부 esc() 를 거쳐 텍스트로만 그린다. 본문 마크다운은 제목(##)·목록·표·굵게(**)만 해석하고 링크·HTML·이미지는 해석하지 않는다.
import {$,api} from '../context.js?v=q6-ui-1-l1';
import {esc} from './format.js?v=q6-ui-1';
import {downloadFile,stampedName} from './downloads.js?v=q6-ui-1-l1';

const NAME={events:'보안 이벤트',vulnerabilities:'취약점 점검',infrastructure:'인프라 모니터링',drills:'보안 시나리오',honeypot:'허니팟'};
const NOTE='문장은 AI가 작성했고, 수치는 원천 데이터 집계 기준입니다. 조치 전에 화면의 원본 자료로 확인하세요.';
const S={view:null,busy:false,data:null,error:'',serial:0};
const hooks={onDisabled:null};
const kst=value=>{
  const t=Date.parse(value);
  return Number.isNaN(t)?'':new Date(t).toLocaleString('ko-KR',{timeZone:'Asia/Seoul',hour12:false});
};

// ── 안전 마크다운 변환: esc() 먼저, 그 다음 허용한 표시만 태그로 바꾼다 ───────────────────────────────
const inline=text=>esc(text).replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>');
const cells=line=>line.trim().replace(/^\|/,'').replace(/\|$/,'').split('|').map(c=>c.trim());
const isDivider=line=>/^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(line);
export function markdownHtml(source){
  const lines=String(source||'').replace(/\r/g,'').split('\n');
  const out=[];let list=null,i=0;
  const closeList=()=>{if(list){out.push(`</${list}>`);list=null;}};
  while(i<lines.length){
    const line=lines[i];
    if(!line.trim()){closeList();i++;continue;}
    const heading=/^#{1,6}\s+(.*)$/.exec(line);
    if(heading){closeList();out.push(`<h3>${inline(heading[1])}</h3>`);i++;continue;}
    if(line.includes('|')&&i+1<lines.length&&isDivider(lines[i+1])){
      closeList();
      const head=cells(line);i+=2;const body=[];
      while(i<lines.length&&lines[i].includes('|')&&lines[i].trim()){body.push(cells(lines[i]));i++;}
      out.push(`<div class="table-scroll"><table><thead><tr>${head.map(c=>`<th>${inline(c)}</th>`).join('')}</tr></thead><tbody>${
        body.map(r=>`<tr>${r.map(c=>`<td>${inline(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`);
      continue;
    }
    const bullet=/^\s*[-*]\s+(.*)$/.exec(line),number=/^\s*\d+[.)]\s+(.*)$/.exec(line);
    if(bullet||number){
      const kind=bullet?'ul':'ol';
      if(list!==kind){closeList();out.push(`<${kind}>`);list=kind;}
      out.push(`<li>${inline((bullet||number)[1])}</li>`);i++;continue;
    }
    closeList();out.push(`<p>${inline(line)}</p>`);i++;
  }
  closeList();
  return out.join('');
}

// ── 저장용 Markdown(.md): 머리 정보 + 본문 + 경고 + 집계 수치 ───────────────────────────────────────
const flat=value=>value==null?'':typeof value!=='object'?String(value)
  :Array.isArray(value)?value.map(flat).join(' / ')
  :Object.entries(value).map(([k,v])=>`${k} ${flat(v)}`).join(', ');
const cellText=value=>flat(value).replace(/\|/g,'\\|').replace(/\r?\n/g,' ');
export function reportMarkdown(d){
  const f=d.filters||{},conditions=Object.entries(f).filter(([,v])=>v).map(([k,v])=>`${k}=${v}`).join(', ')||'없음';
  const skip=new Set(['조회 조건','unavailable','필수 항목 값']);
  const facts=d.facts||{};
  const rows=[...Object.entries(facts['필수 항목 값']||{}).map(([k,v])=>[`필수 · ${k}`,v]),
    ...Object.entries(facts).filter(([k])=>!skip.has(k)).map(([k,v])=>[k,v])];
  return [`# ${d.title}`,'',
    `- 화면: ${NAME[d.view]||d.view}`,
    `- 기간(KST): ${kst(d.period?.from)} ~ ${kst(d.period?.to)}`,
    `- 필터: ${conditions}`,
    `- 생성 시각(KST): ${kst(d.generatedAt)}`,
    `- 모델: ${d.model||''}${d.cached?' (5분 내 같은 조건 보고서)':''}`,
    '',`> ${NOTE}`,'',d.markdown||'','',
    ...((d.warnings||[]).length?['## 경고','',...d.warnings.map(w=>`- ${w}`),'']:[]),
    ...((d.unavailable||[]).length?['## 읽지 못한 원천','',...d.unavailable.map(u=>`- ${u}`),'']:[]),
    '## 집계 수치 (서버 계산)','','| 항목 | 값 |','|---|---|',...rows.map(([k,v])=>`| ${cellText(k)} | ${cellText(v)} |`),''].join('\n');
}

// ── 대화상자 ─────────────────────────────────────────────────────────────────────────────────────
function paint(){
  const title=S.data?.title||`${NAME[S.view]||''} AI 요약 보고서`;
  const d=S.data;
  let body;
  if(S.busy)body=`<div class="dialog-body" role="status" aria-live="polite"><p class="panel-loading">보고서 작성 중… (보통 5~15초)</p></div>`;
  else if(S.error)body=`<div class="dialog-body"><p class="panel-error" role="alert">${esc(S.error)}</p></div>`;
  else if(d){
    const filters=Object.entries(d.filters||{}).filter(([,v])=>v).map(([k,v])=>`${esc(k)} ${esc(v)}`).join(' · ')||'필터 없음';
    body=`<div class="dialog-body report-body">
      <p class="report-meta">${esc(NAME[d.view]||d.view)} · ${esc(kst(d.period?.from))} ~ ${esc(kst(d.period?.to))} KST · ${filters}<br>
        생성 ${esc(kst(d.generatedAt))} KST · 모델 ${esc(d.model||'')}${d.cached?' · <strong>캐시됨</strong> (5분 내 같은 조건 보고서)':''}</p>
      <p class="muted-mini">${esc(NOTE)}</p>
      ${(d.warnings||[]).length?`<div class="report-warn" role="status"><strong>확인 필요</strong><ul>${d.warnings.map(w=>`<li>${esc(w)}</li>`).join('')}</ul></div>`:''}
      ${(d.unavailable||[]).length?`<p class="panel-error" role="status">읽지 못한 원천: ${d.unavailable.map(esc).join(', ')}</p>`:''}
      <div class="report-md">${markdownHtml(d.markdown)}</div></div>`;
  }else body='<div class="dialog-body"></div>';
  $('#report-content').innerHTML=`<div class="dialog-header"><div><div class="eyebrow">AI SUMMARY REPORT</div><h2 id="report-title">${esc(title)}</h2></div>
    <button type="button" class="dialog-close" data-report="close" aria-label="보고서 닫기">×</button></div>${body}
    <div class="dialog-actions"><span>${d&&!S.busy?`토큰 입력 ${esc(d.usage?.inputTokens??0)} · 출력 ${esc(d.usage?.outputTokens??0)}`:''}</span>
    <button type="button" class="subtle-button" data-report="save" ${d&&!S.busy&&!S.error?'':'disabled'}>Markdown 저장</button>
    <button type="button" class="subtle-button" data-report="again" ${S.busy?'disabled':''}>다시 생성</button>
    <button type="button" class="subtle-button" data-report="close">닫기</button></div>`;
}

export async function openReport(view){
  if(S.busy)return;
  S.view=view;S.busy=true;S.error='';S.data=null;
  const serial=++S.serial;
  paint();
  if(!$('#report-dialog').open)$('#report-dialog').showModal();
  try{
    const data=await api.assistantReport(view);
    if(serial!==S.serial)return;
    S.data=data;
  }catch(error){
    if(serial!==S.serial)return;
    S.error=error.message||'보고서를 만들지 못했습니다.';
    if(error.status===503)hooks.onDisabled?.();      // AI 기능이 꺼져 있다 — 버튼도 잠근다(상태를 미리 조회하지 않는다)
  }finally{
    if(serial===S.serial){S.busy=false;paint();}
  }
}

export function initReportDialog({onDisabled}={}){
  hooks.onDisabled=onDisabled||null;
  const dialog=$('#report-dialog');
  if(!dialog)return;
  dialog.addEventListener('click',event=>{
    const action=event.target.closest('[data-report]')?.dataset.report;
    if(action==='close')dialog.close();
    if(action==='again')openReport(S.view);          // 5분 안에 같은 조건이면 서버가 저장해 둔 보고서를 돌려준다(비용 없음)
    if(action==='save'&&S.data)downloadFile(stampedName(`${S.view}-ai-report`,'md'),reportMarkdown(S.data),'text/markdown;charset=utf-8');
    if(event.target===dialog)dialog.close();          // 배경 클릭
  });
  dialog.addEventListener('close',()=>{S.serial++;S.busy=false;});   // 닫으면 진행 중이던 응답은 버린다
}
