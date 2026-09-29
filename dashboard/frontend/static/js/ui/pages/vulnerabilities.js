// 취약점 점검: 서버×패키지 묶음, 대상·페이지·크기, CVE CSV. 이 화면 상태는 이 모듈만 바꾼다.
import {$,api,ui} from '../context.js?v=ui-1';
import {esc} from '../components/format.js?v=ui-1';
import {header,empty,loadPanel,patchAnimated,panelScope,resetTableScroll,toast} from '../components/panel.js?v=ui-1';
import {vulnerabilityCsv,downloadCsv} from '../components/downloads.js?v=ui-1';
// ── 취약점 점검 ────────────────────────────────────────────
let vulnTarget='',vulnPage=1,vulnSize=50,vulnFilter='',vulnData=null,vulnDataKey='';
const vulnKey=()=>panelScope()+JSON.stringify([vulnTarget,ui.refreshSerial]);
export function renderVulnerabilities({reuse=false}={}){
 const box=$('#vulns');if(!box)return;const key=vulnKey();
 if(reuse&&vulnData&&vulnDataKey===key){patchAnimated(box,vulnerabilityMarkup(vulnData));return;}
 return loadPanel(box,()=>api.vulnerabilities({target:vulnTarget}),data=>{vulnData=data;vulnDataKey=key;return vulnerabilityMarkup(data);},'취약점 목록');
}
// CVE 수천 건을 한 줄씩 나열하지 않고 패키지로 묶고, 안에서 영향받는 서버와 CVE를 보여준다.
// 수정 버전 제공 여부는 Inspector 응답 기준이며 실제 업데이트 가능 여부를 뜻하지 않는다.
const SEV_ORDER=['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL','UNTRIAGED','UNKNOWN'];
const SEV_KO={CRITICAL:'긴급',HIGH:'높음',MEDIUM:'보통',LOW:'낮음',INFORMATIONAL:'정보',UNTRIAGED:'심각도 미평가',UNKNOWN:'심각도 알 수 없음'};
const SEV_COLOR={CRITICAL:'#EF777F',HIGH:'#E7A064',MEDIUM:'#D8CA78',LOW:'#32D4BE',INFORMATIONAL:'#85B1D5',UNTRIAGED:'#8FA295',UNKNOWN:'#8FA295'};
const VULN_PREVIEW=20;
const hasFixedVersion=v=>!!v.fixedVersion&&!/pending/i.test(v.fixedVersion);
// 같은 CVE가 여러 서버·패키지에서 발견되어도 요약은 CVE ID 한 번만 센다.
export function vulnerabilityCounts(rows){
 const byId=new Map();
 for(const v of rows){
  const key=v.cveId||v.id,entry=byId.get(key)||{severity:v.severity,total:0,fixed:0};
  if(SEV_ORDER.indexOf(v.severity)<SEV_ORDER.indexOf(entry.severity))entry.severity=v.severity;
  entry.total++;if(hasFixedVersion(v))entry.fixed++;
  byId.set(key,entry);
 }
 const bySeverity={},fixed={all:0,some:0,none:0},groups={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
 for(const c of byId.values()){
  bySeverity[c.severity]=(bySeverity[c.severity]||0)+1;
  fixed[c.fixed===0?'none':c.fixed===c.total?'all':'some']++;
  if(Object.hasOwn(groups,c.severity))groups[c.severity]++;
 }
 return {unique:byId.size,bySeverity,fixed,groups};
}
function filteredRows(rows){
 if(!vulnFilter)return rows;
 const byId=new Map();
 for(const v of rows){
  const id=v.cveId||v.id,c=byId.get(id)||{severity:v.severity,total:0,fixed:0};
  if(SEV_ORDER.indexOf(v.severity)<SEV_ORDER.indexOf(c.severity))c.severity=v.severity;
  c.total++;if(hasFixedVersion(v))c.fixed++;
  byId.set(id,c);
 }
 const selected=new Set([...byId].filter(([,c])=>c.severity===vulnFilter).map(([id])=>id));
 return rows.filter(v=>selected.has(v.cveId||v.id));
}
function summaryButton(severity,count,total){
 const active=vulnFilter===severity,color=SEV_COLOR[severity],share=total?count/total*100:0;
 return `<button type="button" class="vuln-summary-button${active?' active':''}" style="--sev-color:${color};--sev-share:${share}%" data-vuln-filter="${severity}" aria-pressed="${active}"><span>${SEV_KO[severity]}</span><b>${count}</b></button>`;
}
function sevChip(sev){const c=SEV_COLOR[sev]||SEV_COLOR.UNTRIAGED;return `<span class="sev-chip" data-severity="${esc(sev)}" style="color:${c};background:${c}1f;border-color:${c}55">${SEV_KO[sev]||esc(sev)}</span>`;}
// 같은 패키지가 여러 서버에 똑같이 걸리면(같은 AMI) 한 줄로 합치고, 토글 안에서 서버별로 보여준다.
// 개수는 CVE 종류(중복 제거) 기준 — 서버 5대 × 951건을 4755건으로 부풀리지 않는다.
export function vulnGroups(rows){
 const groups=new Map();
 for(const v of rows){
  const key=v.package||'—';
  const g=groups.get(key)||{key,package:key,cves:new Map(),servers:new Map(),counts:{},maxCvss:null};
  const s=g.servers.get(v.resource)||{resource:v.resource,name:v.resourceName||v.resource,installed:v.installedVersion,count:0};
  s.count++;g.servers.set(v.resource,s);
  const cveKey=v.cveId||v.id,c=g.cves.get(cveKey),host=s.name.replace(/^soar-sec-dev-/,'');
  if(c){c.servers++;c.hosts.push(host);if(hasFixedVersion(v)){c.fixedCount++;c.fixedVersions.add(v.fixedVersion);}}
  else{
   g.cves.set(cveKey,{...v,servers:1,hosts:[host],fixedCount:hasFixedVersion(v)?1:0,fixedVersions:new Set(hasFixedVersion(v)?[v.fixedVersion]:[])});g.counts[v.severity]=(g.counts[v.severity]||0)+1;
   if(v.cvss!=null&&(g.maxCvss==null||v.cvss>g.maxCvss))g.maxCvss=v.cvss;
  }
  groups.set(key,g);
 }
 for(const g of groups.values()){
  g.items=[...g.cves.values()];
  g.serverList=[...g.servers.values()].sort((a,b)=>b.count-a.count||a.name.localeCompare(b.name));
 }
 const rank=g=>SEV_ORDER.map(s=>g.counts[s]||0);
 return [...groups.values()].sort((a,b)=>{const ra=rank(a),rb=rank(b);for(let i=0;i<ra.length;i++)if(ra[i]!==rb[i])return rb[i]-ra[i];return (b.maxCvss??0)-(a.maxCvss??0);});
}
// v23: 왜 위험한지(대표 CVE 설명·공개 공격 코드·EPSS)와 어떻게 고치는지(수정 방법·업데이트 명령·재부팅)를 묶음 안에 보여준다.
const FIX_METHOD_KO={'package-update':'패키지 업데이트','image-rebuild':'이미지 재빌드 후 다시 배포','function-update':'Lambda 코드·의존성 업데이트'};
const pctScore=v=>v==null?'—':(v*100).toFixed(v<0.01?2:1)+'%';
function cveLink(v){return v.referenceUrl?`<a class="doc-link" href="${esc(v.referenceUrl)}" target="_blank" rel="noreferrer">${esc(v.cveId||'—')}</a>`:esc(v.cveId||'—');}
function fixPanel(g){
 const items=g.items,rep=[...items].filter(v=>v.description).sort((a,b)=>(b.cvss??-1)-(a.cvss??-1))[0];
 const command=items.find(v=>v.updateCommand&&v.updateCommandSource==='inspector')||items.find(v=>v.updateCommand);
 const methods=[...new Set(items.map(v=>FIX_METHOD_KO[v.fixMethod]).filter(Boolean))];
 const reboot=items.some(v=>v.rebootRequired===true),exploits=items.filter(v=>v.exploitAvailable==='YES').length;
 const epss=Math.max(-1,...items.map(v=>v.epss??-1));
 const allFixed=new Set(items.flatMap(v=>[...v.fixedVersions])),fixed=[...allFixed].slice(0,3);  // pending 은 vulnGroups 에서 이미 뺐다
 return `<div class="vuln-fix"><div><h3>왜 위험한가</h3>${rep?`<p>${cveLink(rep)} — ${esc(rep.description.length>320?rep.description.slice(0,320)+'…':rep.description)}</p>`:'<p class="muted-mini">Inspector 설명이 없습니다(적재 형식 갱신 전이면 다음 대조 후 표시).</p>'}
  <p class="muted-mini">공개 공격 코드 ${exploits?`<b class="bad-text">있음 ${exploits}건</b>`:'확인된 것 없음'} · 최고 EPSS(30일 내 악용 가능성) ${epss<0?'—':pctScore(epss)}</p></div>
  <div><h3>어떻게 고치나</h3><p>${esc(methods.join(' · ')||'수정 방법 정보 없음')}${fixed.length?` · Inspector 수정 버전 ${fixed.map(esc).join(', ')}${fixed.length<allFixed.size?' 외':''}`:''}</p>
  ${command?`<code class="cmd">${esc(command.updateCommand)}</code><p class="muted-mini">${command.updateCommandSource==='inspector'?'Inspector 제공 명령':'대시보드가 플랫폼·패키지로 만든 명령 — 적용 전 확인'}</p>`:''}
  ${reboot?'<p class="reboot-note">커널 패키지입니다. 업데이트 후 재부팅해야 적용됩니다 — 시연 일정 중에는 재부팅 시각을 정해 진행하세요.</p>':''}</div></div>`;
}
function fixedVersionText(c){
 if(!c.fixedCount)return '미제공';
 const versions=[...c.fixedVersions].join(', ');
 return c.fixedCount<c.servers?`일부 서버만 명시 · ${versions}`:versions;
}
function vulnGroupMarkup(g){
 const top=[...g.items].sort((a,b)=>(b.cvss??-1)-(a.cvss??-1)||SEV_ORDER.indexOf(a.severity)-SEV_ORDER.indexOf(b.severity)).slice(0,VULN_PREVIEW);
 const mix=SEV_ORDER.filter(sev=>g.counts[sev]);
 const severityMeter=`<div class="vg-severity-meter" role="img" aria-label="${esc(`위험도 구성: ${mix.map(sev=>`${SEV_KO[sev]} ${g.counts[sev]}종`).join(', ')}`)}">${mix.map(sev=>`<i style="width:${(g.counts[sev]/g.items.length*100).toFixed(1)}%;background:${SEV_COLOR[sev]}"></i>`).join('')}</div>`;
 const one=g.serverList.length===1?g.serverList[0]:null;
 const hosts=g.serverList.slice(0,3).map(s=>`<span class="vg-ec2-node" title="${esc(s.resource)} · 설치 ${esc(s.installed||'—')}"><i aria-hidden="true">▣</i>${esc(s.name.replace(/^soar-sec-dev-/,''))}</span>`).join('');
 return `<details class="cve-group" data-key="vg-${esc(g.key)}"><summary>
  <div class="vg-asset-lane"><small>발견 위치 · EC2 ${g.serverList.length}대</small><div class="vg-ec2-nodes">${hosts}${g.serverList.length>3?`<span class="vg-ec2-more">외 ${g.serverList.length-3}대</span>`:''}</div></div>
  <span class="vg-flow-arrow" aria-hidden="true">→</span>
  <div class="vg-main"><small>설치된 패키지</small><strong>${esc(g.package)}</strong>${severityMeter}</div>
  <span class="vg-flow-arrow" aria-hidden="true">→</span>
  <div class="vg-result"><small>발견된 취약점</small><b>${g.items.length}종</b></div></summary>
  ${fixPanel(g)}
  ${one?'':`<div class="vg-servers"><h3>영향받는 서버 ${g.serverList.length}대</h3><ul>${g.serverList.map(s=>`<li><button class="link-button" data-vuln-target="${esc(s.resource)}" title="${esc(s.resource)}">${esc(s.name)}</button><span>설치 ${esc(s.installed||'—')}</span><span>CVE ${s.count}건</span></li>`).join('')}</ul></div>`}
  <div class="table-scroll"><table><thead><tr><th>심각도</th><th>CVSS</th><th>EPSS</th><th>CVE</th><th>공격 코드</th><th>Inspector 수정 버전</th><th>영향 서버</th></tr></thead><tbody>${top.map(v=>`<tr><td>${sevChip(v.severity)}</td><td>${v.cvss??'—'}</td><td>${pctScore(v.epss)}</td><td title="${esc(v.title||'')}">${cveLink(v)}</td><td>${v.exploitAvailable==='YES'?'<span class="bad-text">공개됨</span>':v.exploitAvailable==='NO'?'없음':'—'}</td><td>${esc(fixedVersionText(v))}</td><td class="cve-hosts">${v.hosts.sort().map(h=>`<span>${esc(h)}</span>`).join('')}</td></tr>`).join('')}</tbody></table></div>
  ${g.items.length>VULN_PREVIEW?`<p class="muted vg-more">CVSS 상위 ${VULN_PREVIEW}종만 표시 · 나머지 ${g.items.length-VULN_PREVIEW}종은 CVE CSV로 확인</p>`:''}
 </details>`;
}
export function vulnerabilityMarkup(data){
 const allRows=data.items,rows=filteredRows(allRows),groups=vulnGroups(rows),pages=Math.max(1,Math.ceil(groups.length/(vulnSize||groups.length||1)));
 vulnPage=Math.min(vulnPage,pages);const size=vulnSize||groups.length||1,page=groups.slice((vulnPage-1)*size,vulnPage*size);
 const warn=(data.warnings||[]).map(w=>`<p class="panel-error" role="status">${esc(w)}</p>`).join('');
 const stats=vulnerabilityCounts(rows),allStats=vulnerabilityCounts(allRows),totals=allStats.groups;
 const servers=new Set(rows.map(v=>v.resource)).size;
 return `${warn}<div class="view-intro"><span>열린 취약점 · 최근 31일 관측 · Inspector · 서버 ${servers}대 · 패키지 ${groups.length}개</span><span class="view-summary">고유 CVE <strong>${stats.unique}종</strong> · 서버별 finding ${rows.length}건${(allStats.bySeverity.UNTRIAGED||0)+(allStats.bySeverity.UNKNOWN||0)?` · 미평가 ${(allStats.bySeverity.UNTRIAGED||0)+(allStats.bySeverity.UNKNOWN||0)}종은 전체 목록에 포함`:''}</span></div>
 <div class="vuln-summary" role="group" aria-label="취약점 위험도 필터">${['CRITICAL','HIGH','MEDIUM','LOW'].map(sev=>summaryButton(sev,totals[sev],allStats.unique)).join('')}</div>
 <section class="panel full-panel">${header('패키지별 취약점',`<label class="page-size">표시 <select id="vuln-size">${[25,50,100,200,0].map(n=>`<option value="${n}"${n===vulnSize?' selected':''}>${n?n+'개씩':'전체'}</option>`).join('')}</select></label><button id="export-vulns" class="text-button">↓ CVE CSV 내보내기</button>`)}
 ${vulnTarget?`<div class="vuln-toolbar"><button class="text-button" data-vuln-target="">전체 서버 보기 ←</button></div>`:''}
 ${page.length?`<div class="cve-groups">${page.map(vulnGroupMarkup).join('')}</div>`:empty(vulnFilter?'선택한 조건에 맞는 취약점이 없습니다.':'현재 열린 취약점이 없습니다.')}
 <div class="table-pager"><button data-vuln-page="prev" ${vulnPage<=1?'disabled':''}>← 이전</button><span>${vulnPage} / ${pages}</span><button data-vuln-page="next" ${vulnPage>=pages?'disabled':''}>다음 →</button></div><p class="vuln-note">EC2 → 패키지 → CVE는 Inspector가 발견한 설치 관계이며 네트워크 연결 경로가 아닙니다. 위험도별 건수는 중복을 제거한 CVE 종류 기준입니다. 색상 버튼을 다시 누르면 전체 목록을 봅니다. Inspector 수정 버전은 실제 업데이트 가능 여부를 뜻하지 않습니다.</p></section>`;
}
export function selectVulnTarget(target){if(vulnTarget===target)return;vulnTarget=target;vulnPage=1;renderVulnerabilities();}
export function stepVulnPage(control,direction){vulnPage+=direction==='next'?1:-1;resetTableScroll(control);renderVulnerabilities({reuse:true});}
export function setVulnSize(control,size){vulnSize=size;vulnPage=1;resetTableScroll(control);renderVulnerabilities({reuse:true});}
export function selectVulnFilter(filter){vulnFilter=vulnFilter===filter?'':filter;vulnPage=1;renderVulnerabilities({reuse:true});}
export function resetVulnerabilityView({clearFilter=false}={}){vulnTarget='';vulnPage=1;if(clearFilter)vulnFilter='';}
export function exportVulnerabilities(filename='vulnerabilities.csv'){
 if(!vulnData||vulnDataKey!==vulnKey()||$('#vulns').hasAttribute('aria-busy')){toast('목록 갱신이 완료된 후 다시 내보내주세요.');return;}
 downloadCsv(filename,vulnerabilityCsv({...vulnData,items:filteredRows(vulnData.items)},vulnTarget));
}
