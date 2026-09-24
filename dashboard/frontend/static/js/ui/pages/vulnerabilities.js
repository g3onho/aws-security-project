// 취약점 점검: 서버×패키지 묶음, 대상·페이지·크기·업데이트 가능 필터, CVE CSV. 이 화면 상태는 이 모듈만 바꾼다.
import {$,api,ui} from '../context.js?v=ui-1';
import {esc} from '../components/format.js?v=ui-1';
import {header,empty,loadPanel,patchAnimated,panelScope,resetTableScroll,toast} from '../components/panel.js?v=ui-1';
import {vulnerabilityCsv,downloadCsv} from '../components/downloads.js?v=ui-1';
// ── 취약점 점검 ────────────────────────────────────────────
let vulnTarget='',vulnPage=1,vulnSize=50,vulnFixable=false,vulnData=null,vulnDataKey='';
const vulnKey=()=>panelScope()+JSON.stringify([vulnTarget,vulnFixable,ui.refreshSerial]);
export function renderVulnerabilities({reuse=false}={}){
 const box=$('#vulns');if(!box)return;const key=vulnKey();
 if(reuse&&vulnData&&vulnDataKey===key){patchAnimated(box,vulnerabilityMarkup(vulnData));return;}
 return loadPanel(box,()=>api.vulnerabilities({target:vulnTarget,fixableOnly:vulnFixable}),data=>{vulnData=data;vulnDataKey=key;return vulnerabilityMarkup(data);},'취약점 목록');
}
// CVE 수천 건을 한 줄씩 나열하지 않고 "서버 × 패키지"로 묶는다. 실측(2026-09-23) 4933건 중
// 대부분이 서버마다 linux-image-aws 하나라, 한 줄 = 한 번의 업데이트로 사라지는 묶음이 된다.
const SEV_ORDER=['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL','UNTRIAGED','UNKNOWN'];
const SEV_KO={CRITICAL:'긴급',HIGH:'높음',MEDIUM:'보통',LOW:'낮음',INFORMATIONAL:'정보',UNTRIAGED:'미분류',UNKNOWN:'알 수 없음'};
const SEV_COLOR={CRITICAL:'#EF777F',HIGH:'#E7A064',MEDIUM:'#D8CA78',LOW:'#32D4BE',INFORMATIONAL:'#85B1D5',UNTRIAGED:'#8FA295',UNKNOWN:'#8FA295'};
const VULN_PREVIEW=20;
const fixableNow=v=>!!v.fixedVersion&&!/pending/i.test(v.fixedVersion);
function sevChip(sev,n){const c=SEV_COLOR[sev]||SEV_COLOR.UNTRIAGED;return `<span class="sev-chip" style="color:${c};background:${c}1f;border-color:${c}55">${SEV_KO[sev]||esc(sev)} <b>${n}</b></span>`;}
// 같은 패키지가 여러 서버에 똑같이 걸리면(같은 AMI) 한 줄로 합치고, 토글 안에서 서버별로 보여준다.
// 개수는 CVE 종류(중복 제거) 기준 — 서버 5대 × 951건을 4755건으로 부풀리지 않는다.
export function vulnGroups(rows){
 const groups=new Map();
 for(const v of rows){
  const key=v.package||'—';
  const g=groups.get(key)||{key,package:key,cves:new Map(),servers:new Map(),counts:{},maxCvss:null,fixable:0};
  const s=g.servers.get(v.resource)||{resource:v.resource,name:v.resourceName||v.resource,installed:v.installedVersion,count:0,fixable:0};
  s.count++;if(fixableNow(v))s.fixable++;g.servers.set(v.resource,s);
  const c=g.cves.get(v.cveId),host=s.name.replace(/^soar-sec-dev-/,'');
  if(c){c.servers++;c.hosts.push(host);}
  else{
   g.cves.set(v.cveId,{...v,servers:1,hosts:[host]});g.counts[v.severity]=(g.counts[v.severity]||0)+1;
   if(v.cvss!=null&&(g.maxCvss==null||v.cvss>g.maxCvss))g.maxCvss=v.cvss;
   if(fixableNow(v))g.fixable++;
  }
  groups.set(key,g);
 }
 for(const g of groups.values()){g.items=[...g.cves.values()];g.serverList=[...g.servers.values()].sort((a,b)=>b.count-a.count||a.name.localeCompare(b.name));}
 const rank=g=>SEV_ORDER.map(s=>g.counts[s]||0);
 return [...groups.values()].sort((a,b)=>{const ra=rank(a),rb=rank(b);for(let i=0;i<ra.length;i++)if(ra[i]!==rb[i])return rb[i]-ra[i];return (b.maxCvss??0)-(a.maxCvss??0);});
}
function sevBar(counts,total){return `<div class="sev-bar" aria-hidden="true">${SEV_ORDER.filter(s=>counts[s]).map(s=>`<i style="width:${counts[s]/total*100}%;background:${SEV_COLOR[s]}"></i>`).join('')}</div>`;}
function vulnGroupMarkup(g){
 const top=[...g.items].sort((a,b)=>(b.cvss??-1)-(a.cvss??-1)||SEV_ORDER.indexOf(a.severity)-SEV_ORDER.indexOf(b.severity)).slice(0,VULN_PREVIEW);
 const fix=g.fixable===g.items.length?`<span class="fix-state ok">업데이트 가능</span>`:g.fixable?`<span class="fix-state">일부 업데이트 가능 ${g.fixable}건</span>`:`<span class="fix-state wait">수정본 대기</span>`;
 const one=g.serverList.length===1?g.serverList[0]:null;
 const where=one?`<button class="link-button" data-vuln-target="${esc(one.resource)}" title="${esc(one.resource)}">${esc(one.name)}</button> · 설치 ${esc(one.installed||'—')}`
  :`<span class="server-count">서버 ${g.serverList.length}대</span> · ${g.serverList.slice(0,3).map(s=>esc(s.name.replace(/^soar-sec-dev-/,''))).join(', ')}${g.serverList.length>3?' 외':''}`;
 return `<details class="cve-group" data-key="vg-${esc(g.key)}"><summary>
  <div class="vg-main"><strong>${esc(g.package)}</strong><small>${where}</small></div>
  <div class="vg-count"><b>${g.items.length}</b><span>CVE 종류</span></div>
  <div class="vg-sev">${sevBar(g.counts,g.items.length)}<div class="vg-chips">${SEV_ORDER.filter(s=>g.counts[s]).map(s=>sevChip(s,g.counts[s])).join('')}</div></div>
  <div class="vg-meta"><span>최고 CVSS <b>${g.maxCvss??'—'}</b></span>${fix}</div></summary>
  ${one?'':`<div class="vg-servers"><h3>영향받는 서버 ${g.serverList.length}대</h3><ul>${g.serverList.map(s=>`<li><button class="link-button" data-vuln-target="${esc(s.resource)}" title="${esc(s.resource)}">${esc(s.name)}</button><span>설치 ${esc(s.installed||'—')}</span><span>CVE ${s.count}건</span>${s.fixable?`<span class="fix-state ok">업데이트 가능 ${s.fixable}</span>`:'<span class="fix-state wait">수정본 대기</span>'}</li>`).join('')}</ul></div>`}
  <div class="table-scroll"><table><thead><tr><th>심각도</th><th>CVSS</th><th>CVE</th><th>수정 버전</th><th>영향 서버</th></tr></thead><tbody>${top.map(v=>`<tr><td>${sevChip(v.severity,'')}</td><td>${v.cvss??'—'}</td><td>${esc(v.cveId||'—')}</td><td>${esc(v.fixedVersion||'수정본 없음')}</td><td class="cve-hosts">${v.hosts.sort().map(h=>`<span>${esc(h)}</span>`).join('')}</td></tr>`).join('')}</tbody></table></div>
  ${g.items.length>VULN_PREVIEW?`<p class="muted vg-more">CVSS 상위 ${VULN_PREVIEW}종만 표시 · 나머지 ${g.items.length-VULN_PREVIEW}종은 CVE CSV로 확인</p>`:''}
 </details>`;
}
export function vulnerabilityMarkup(data){
 const rows=data.items,groups=vulnGroups(rows),pages=Math.max(1,Math.ceil(groups.length/(vulnSize||groups.length||1)));
 vulnPage=Math.min(vulnPage,pages);const size=vulnSize||groups.length||1,page=groups.slice((vulnPage-1)*size,vulnPage*size);
 const warn=(data.warnings||[]).map(w=>`<p class="panel-error" role="status">${esc(w)}</p>`).join('');
 const counts={};for(const v of rows)counts[v.severity]=(counts[v.severity]||0)+1;
 const servers=new Set(rows.map(v=>v.resource)).size,fixable=rows.filter(fixableNow).length;
 return `${warn}<div class="view-intro"><span>Inspector 실제 관측 결과 · 서버 ${servers}대 · 패키지 ${groups.length}개</span><span class="view-summary">CVE ${rows.length}건 (서버별 합계)</span></div>
 <div class="vuln-summary">${SEV_ORDER.filter(s=>counts[s]).map(s=>`<div style="border-color:${SEV_COLOR[s]}55"><span>${SEV_KO[s]}</span><b style="color:${SEV_COLOR[s]}">${counts[s]}</b></div>`).join('')}<div><span>지금 업데이트 가능</span><b class="mint">${fixable}</b></div><div><span>수정본 대기</span><b>${rows.length-fixable}</b></div></div>
 <section class="panel full-panel">${header('패키지별 취약점',`<label class="page-size">표시 <select id="vuln-size">${[25,50,100,200,0].map(n=>`<option value="${n}"${n===vulnSize?' selected':''}>${n?n+'개씩':'전체'}</option>`).join('')}</select></label><button id="export-vulns" class="text-button">↓ CVE CSV 내보내기</button>`)}
 <div class="vuln-toolbar">${vulnTarget?`<button class="text-button" data-vuln-target="">전체 서버 보기 ←</button>`:'<span class="muted-mini">패키지를 누르면 영향받는 서버와 CVE가 펼쳐집니다. 서버 이름을 누르면 그 서버만 봅니다.</span>'}<label class="vuln-check"><input type="checkbox" id="vuln-fixable"${vulnFixable?' checked':''}> 지금 업데이트 가능한 항목만</label></div>
 ${page.length?`<div class="cve-groups">${page.map(vulnGroupMarkup).join('')}</div>`:empty('선택한 기간에 탐지된 취약점이 없습니다.')}
 <div class="table-footer"><span>패키지 ${groups.length}개 · CVE ${rows.length}건(서버별 합계)</span><span>정렬: 긴급 → 높음 개수, 최고 CVSS 순</span></div>
 <div class="table-pager"><button data-vuln-page="prev" ${vulnPage<=1?'disabled':''}>← 이전</button><span>${vulnPage} / ${pages}</span><button data-vuln-page="next" ${vulnPage>=pages?'disabled':''}>다음 →</button></div></section>`;
}
export function selectVulnTarget(target){if(vulnTarget===target)return;vulnTarget=target;vulnPage=1;renderVulnerabilities();}
export function stepVulnPage(control,direction){vulnPage+=direction==='next'?1:-1;resetTableScroll(control);renderVulnerabilities({reuse:true});}
export function setVulnSize(control,size){vulnSize=size;vulnPage=1;resetTableScroll(control);renderVulnerabilities({reuse:true});}
export function setVulnFixable(on){vulnFixable=on;vulnPage=1;renderVulnerabilities();}
export function resetVulnerabilityView({keepFixable=true}={}){vulnTarget='';vulnPage=1;if(!keepFixable)vulnFixable=false;}
export function exportVulnerabilities(){
 if(!vulnData||vulnDataKey!==vulnKey()||$('#vulns').hasAttribute('aria-busy')){toast('목록 갱신이 완료된 후 다시 내보내주세요.');return;}
 downloadCsv('vulnerabilities.csv',vulnerabilityCsv(vulnData,vulnTarget));
}
