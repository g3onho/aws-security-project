// 화면별 AI 요약 보고서 대화상자(v28) — 조회 전용.
// 서버가 수치를 집계하고 모델은 문장만 쓴다. 이 파일은 서버가 준 문자열(모델 본문·이벤트 제목 등 공격자가 조종할 수 있는 값 포함)을
// 전부 esc() 를 거쳐 텍스트로만 그린다. 본문 마크다운은 제목(##)·목록·표·굵게(**)만 해석하고 링크·HTML·이미지는 해석하지 않는다.
import {$,api} from '../context.js?v=v46';
import {esc} from './format.js?v=v46';
import {downloadFile,stampedName} from './downloads.js?v=v46';
import {toast} from './panel.js?v=v46';

const NAME={events:'보안 이벤트',vulnerabilities:'취약점 점검',infrastructure:'인프라 모니터링',drills:'보안 시나리오',honeypot:'허니팟','drill-run':'보안 시나리오 실행 결과'};
const NOTE='문장은 AI가 작성했고, 수치는 원천 데이터 집계 기준입니다. 조치 전에 화면의 원본 자료로 확인하세요.';
const S={view:null,extra:{},busy:false,data:null,error:'',serial:0};
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

// ── 보고서 문서(v42): 대시보드 디자인 + Claude 로고. 화면(대화상자)과 PDF(인쇄)가 같은 마크업을 쓴다 ─────────────────
const CLAUDE_LOGO='/static/img/claude-mark.svg';
const SHIELD='<svg width="22" height="26" viewBox="0 0 24 28" fill="none" aria-hidden="true"><path d="M12 2 22 6v8c0 6-10 12-10 12S2 20 2 14V6Z" stroke="currentColor" stroke-width="1.7"/><path d="m7 13 3 3 7-7" stroke="currentColor" stroke-width="1.7"/></svg>';
// 모델 본문(이미 안전하게 변환된 HTML)을 제목(h3) 단위 카드로 나눈다. 제목 글자는 그대로 둔다("1. 요약").
function sections(html){
  const parts=html.split(/(?=<h3>)/).filter(Boolean);
  return parts.map(part=>`<section class="rp-sec">${part}</section>`).join('');
}
// 서버가 집계한 필수 항목 값(숫자·짧은 글자)을 요약 타일로 보인다. 목록형 값은 본문에 있으니 제외한다.
const KPI_TONE=[[/CRITICAL|치명|실패|장애/i,'#c62f3c'],[/HIGH|높음|초과|고위험/i,'#a4530f'],[/수동|대기|미적용|읽지|없음|미/i,'#7a6200']];
function kpis(d){
  const values=d.facts?.['필수 항목 값']||{};
  const tiles=Object.entries(values).filter(([,v])=>typeof v==='number'||(typeof v==='string'&&v.length<=12)).slice(0,6);
  if(!tiles.length)return '';
  return `<div class="rp-kpis" role="list" aria-label="서버 집계 핵심 수치">${tiles.map(([k,v])=>{
    const tone=typeof v==='number'&&v>0?(KPI_TONE.find(([re])=>re.test(k))?.[1]||'#0b7f72'):'#0b7f72';
    return `<div class="rp-kpi" role="listitem" style="--k:${tone}"><span>${esc(k)}</span><b${v===0?' class="zero"':''}>${esc(v)}</b></div>`;
  }).join('')}</div>`;
}
// 본문 첫 줄(종합 판단 한 문장)을 눈에 띄는 띠로 올린다. 긴급·주의·안정 중 하나가 들어 있을 때만 떼어 낸다(없으면 본문 그대로).
export function splitVerdict(markdown){
  const md=String(markdown||'').replace(/\r/g,'');
  const m=/(^|\n)(##\s*1\.[^\n]*\n)[ \t]*([^\n]+)\n?/.exec(md);
  if(!m)return {verdict:null,tone:'',md};
  const line=m[3].trim();
  if(/^([-*]\s|\||#|\d+[.)]\s)/.test(line))return {verdict:null,tone:'',md};
  const word=/긴급|주의|안정/.exec(line);
  if(!word)return {verdict:null,tone:'',md};
  const start=m.index+m[1].length+m[2].length;
  return {verdict:line,tone:{긴급:'urgent',주의:'warn',안정:'ok'}[word[0]],md:md.slice(0,start)+md.slice(m.index+m[0].length)};
}
export function reportDocHtml(d){
  const {verdict,tone,md}=splitVerdict(d.markdown);
  const filters=Object.entries(d.filters||{}).filter(([,v])=>v).map(([k,v])=>`${esc(k)} ${esc(v)}`).join(' · ')||'필터 없음';
  const meta=[['화면',NAME[d.view]||d.view],['기간(KST)',`${kst(d.period?.from)} ~ ${kst(d.period?.to)}`],['생성(KST)',kst(d.generatedAt)+(d.cached?' · 캐시됨':'')]];
  return `<article class="rp" data-view="${esc(d.view)}">
    <header class="rp-hero">
      <div class="rp-top"><span class="rp-brand">${SHIELD}<span>AWS <b>Security Operations</b></span></span>
        <span class="rp-by"><img src="${CLAUDE_LOGO}" width="22" height="22" alt="">Summarized by <b>Claude</b></span></div>
      <div class="rp-eyebrow">AI SUMMARY REPORT</div>
      <h2 id="report-title">${esc(d.title||`${NAME[d.view]||''} AI 요약 보고서`)}</h2>
      <dl class="rp-meta">${meta.map(([k,v])=>`<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('')}<div><dt>필터</dt><dd>${filters}</dd></div></dl>
    </header>
    <div class="rp-page">
      ${kpis(d)}
      ${(d.warnings||[]).length?`<div class="report-warn" role="status"><strong>확인 필요</strong><ul>${d.warnings.map(w=>`<li>${esc(w)}</li>`).join('')}</ul></div>`:''}
      ${(d.unavailable||[]).length?`<p class="panel-error" role="status">읽지 못한 원천: ${d.unavailable.map(esc).join(', ')}</p>`:''}
      ${verdict?`<div class="rp-verdict" data-tone="${tone}" role="note"><span class="rp-verdict-tag">종합 판단</span><p>${inline(verdict)}</p></div>`:''}
      <div class="report-md">${sections(markdownHtml(md))}</div>
      <footer class="rp-foot"><p>${esc(NOTE)}</p><p class="rp-gen"><img src="${CLAUDE_LOGO}" width="14" height="14" alt=""> Generated with Claude · 모델 ${esc(d.model||'')} · 토큰 입력 ${esc(d.usage?.inputTokens??0)} / 출력 ${esc(d.usage?.outputTokens??0)}</p></footer>
    </div></article>`;
}

// ── 대화상자 ─────────────────────────────────────────────────────────────────────────────────────
function paint(){
  const d=S.data;
  let body;
  if(S.busy)body=`<div class="rp-state" role="status" aria-live="polite"><img src="${CLAUDE_LOGO}" width="30" height="30" alt=""><h2 id="report-title">${esc(`${NAME[S.view]||''} AI 요약 보고서`)}</h2><p class="panel-loading">Claude 가 보고서를 작성하는 중… (보통 5~15초)</p></div>`;
  else if(S.error)body=`<div class="rp-state"><h2 id="report-title">${esc(`${NAME[S.view]||''} AI 요약 보고서`)}</h2><p class="panel-error" role="alert">${esc(S.error)}</p></div>`;
  else if(d)body=reportDocHtml(d);
  else body='<div class="rp-state"></div>';
  $('#report-content').innerHTML=`<button type="button" class="dialog-close rp-close" data-report="close" aria-label="보고서 닫기">×</button>${body}
    <div class="dialog-actions"><span>${d&&!S.busy?`토큰 입력 ${esc(d.usage?.inputTokens??0)} · 출력 ${esc(d.usage?.outputTokens??0)}`:''}</span>
    <button type="button" class="subtle-button accent" data-report="pdf" ${d&&!S.busy&&!S.error?'':'disabled'}>PDF 저장</button>
    <button type="button" class="subtle-button" data-report="save" ${d&&!S.busy&&!S.error?'':'disabled'}>Markdown 저장</button>
    <button type="button" class="subtle-button" data-report="again" ${S.busy?'disabled':''}>다시 생성</button>
    <button type="button" class="subtle-button" data-report="close">닫기</button></div>`;
}

// PDF 저장: 브라우저 인쇄 대화상자에서 "PDF로 저장"을 고른다. 보고서만 A4 로 찍히도록 본문에 복사본을 만들고 나머지는 인쇄에서 숨긴다(local.css @media print).
// 파일 이름 제안은 문서 제목을 임시로 바꿔 정한다.
async function savePdf(){
  if(!S.data||S.busy||S.error)return;
  let host=document.getElementById('report-print');
  if(!host){host=document.createElement('div');host.id='report-print';document.body.appendChild(host);}
  host.innerHTML=reportDocHtml(S.data);
  await Promise.all([...host.querySelectorAll('img')].map(img=>img.decode?.().catch(()=>{})));   // 로고가 다 그려진 뒤에 인쇄한다
  const title=document.title;
  document.title=stampedName(`${S.view}-ai-report`,'pdf').replace(/\.pdf$/,'');
  document.body.classList.add('printing-ai-report');
  let finished=false;
  const done=()=>{
    if(finished)return;finished=true;
    document.body.classList.remove('printing-ai-report');host.innerHTML='';document.title=title;
    window.removeEventListener('afterprint',done);
  };
  window.addEventListener('afterprint',done);
  try{window.print();}catch{toast('이 브라우저에서는 PDF 저장(인쇄)을 열 수 없습니다. Markdown 저장을 사용하세요.');done();}
  finally{if(!window.matchMedia?.('print').matches)setTimeout(done,800);}
}

export async function openReport(view,extra={}){
  if(S.busy)return;
  S.view=view;S.extra=extra||{};S.busy=true;S.error='';S.data=null;
  const serial=++S.serial;
  paint();
  if(!$('#report-dialog').open)$('#report-dialog').showModal();
  try{
    const data=await api.assistantReport(view,S.extra);
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
    if(action==='again')openReport(S.view,S.extra);          // 5분 안에 같은 조건이면 서버가 저장해 둔 보고서를 돌려준다(비용 없음)
    if(action==='pdf')savePdf();
    if(action==='save'&&S.data)downloadFile(stampedName(`${S.view}-ai-report`,'md'),reportMarkdown(S.data),'text/markdown;charset=utf-8');
    if(event.target===dialog)dialog.close();          // 배경 클릭
  });
  dialog.addEventListener('close',()=>{S.serial++;S.busy=false;});   // 닫으면 진행 중이던 응답은 버린다
}
