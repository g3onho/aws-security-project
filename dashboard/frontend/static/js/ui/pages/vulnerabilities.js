// 취약점 점검: 서버×패키지 묶음, 대상·페이지·크기, CVE CSV. 이 화면 상태는 이 모듈만 바꾼다.
import {$,api,ui} from '../context.js?v=v44';
import {esc,cmdBlock} from '../components/format.js?v=v44';
import {header,empty,loadPanel,patchAnimated,panelScope,resetTableScroll,toast} from '../components/panel.js?v=v44';
import {vulnerabilityCsv,downloadCsv} from '../components/downloads.js?v=v44';
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
const SEV_TEXT={CRITICAL:'#b3121e',HIGH:'#a85100',MEDIUM:'#7a5b00',LOW:'#1b7a3a',INFORMATIONAL:'#22588a'};
const SEV_COLOR={CRITICAL:'#f28f96',HIGH:'#f8b26e',MEDIUM:'#f6dc7a',LOW:'#8fd4a6',INFORMATIONAL:'#4186be',UNTRIAGED:'#57665c',UNKNOWN:'#57665c'};
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
 return `<button type="button" title="중복을 제거한 CVE 종류 기준 · 다시 누르면 전체 목록" class="vuln-summary-button${active?' active':''}" style="--sev-color:${color};--sev-share:${share}%" data-vuln-filter="${severity}" aria-pressed="${active}"><span>${SEV_KO[severity]}</span><b>${count}</b></button>`;
}
function sevChip(sev,n){const c=SEV_COLOR[sev]||SEV_COLOR.UNTRIAGED,t=SEV_TEXT[sev]||'#3f4e46';return `<span class="sev-chip" data-severity="${esc(sev)}" style="color:${t};background:${c}33;border-color:${c}">${SEV_KO[sev]||esc(sev)}${n==null?'':` <b>${n}</b>`}</span>`;}
function sevBar(counts,total){return `<div class="sev-bar" aria-hidden="true">${SEV_ORDER.filter(s=>counts[s]).map(s=>`<i style="width:${counts[s]/total*100}%;background:${SEV_COLOR[s]}"></i>`).join('')}</div>`;}
// 같은 패키지가 여러 서버에 똑같이 걸리면(같은 AMI) 한 줄로 합치고, 토글 안에서 서버별로 보여준다.
// 개수는 CVE 종류(중복 제거) 기준 — 서버 5대 × 951건을 4755건으로 부풀리지 않는다.
export function vulnGroups(rows){
 const groups=new Map();
 for(const v of rows){
  const key=v.package||'—';
  const g=groups.get(key)||{key,package:key,cves:new Map(),servers:new Map(),counts:{},maxCvss:null};
  const s=g.servers.get(v.resource)||{resource:v.resource,name:v.resourceName||v.resource,installed:v.installedVersion,count:0,fixable:0};
  s.count++;if(hasFixedVersion(v))s.fixable++;g.servers.set(v.resource,s);
  const cveKey=v.cveId||v.id,c=g.cves.get(cveKey),host=s.name.replace(/^soar-sec-dev-/,'');
  if(c){c.servers++;c.hosts.push(host);if(hasFixedVersion(v)){c.fixedCount++;c.fixedVersions.add(v.fixedVersion);}}
  else{
   g.cves.set(cveKey,{...v,servers:1,hosts:[host],fixedCount:hasFixedVersion(v)?1:0,fixedVersions:new Set(hasFixedVersion(v)?[v.fixedVersion]:[])});g.counts[v.severity]=(g.counts[v.severity]||0)+1;
   if(v.cvss!=null&&(g.maxCvss==null||v.cvss>g.maxCvss))g.maxCvss=v.cvss;
  }
  groups.set(key,g);
 }
 for(const g of groups.values()){
  g.items=[...g.cves.values()];g.fixable=g.items.filter(c=>c.fixedCount===c.servers).length;
  g.partial=g.items.filter(c=>c.fixedCount>0&&c.fixedCount<c.servers).length;
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
  ${command?`${cmdBlock(command.updateCommand)}<p class="muted-mini">${command.updateCommandSource==='inspector'?'Inspector 제공 명령':'대시보드가 플랫폼·패키지로 만든 명령 — 적용 전 확인'}</p>`:''}
  ${reboot?'<p class="reboot-note">커널 패키지입니다. 업데이트 후 재부팅해야 적용됩니다 — 시연 일정 중에는 재부팅 시각을 정해 진행하세요.</p>':''}</div></div>`;
}
function fixedVersionText(c){
 if(!c.fixedCount)return '미제공';
 const versions=[...c.fixedVersions].join(', ');
 return c.fixedCount<c.servers?`일부 서버만 명시 · ${versions}`:versions;
}
function vulnGroupMarkup(g){
 const top=[...g.items].sort((a,b)=>(b.cvss??-1)-(a.cvss??-1)||SEV_ORDER.indexOf(a.severity)-SEV_ORDER.indexOf(b.severity)).slice(0,VULN_PREVIEW);
 // v42: 패키지 묶음 행을 v27 모양으로 되돌렸다(패키지·서버 / CVE 종류 / 위험도 구성 / 최고 CVSS·수정 버전 상태). 묶음 기준은 그대로다.
 const known=g.fixable+g.partial;
 const fix=g.fixable===g.items.length?`<span class="fix-state ok">수정 버전 명시</span>`:known?`<span class="fix-state">수정 버전 일부 명시 ${known}종</span>`:`<span class="fix-state wait">수정 버전 미제공</span>`;
 const one=g.serverList.length===1?g.serverList[0]:null;
 // 서버 이름은 링크가 아니라 글자로만 보여준다(서버별 보기는 묶음을 펼친 안의 '영향받는 서버'에서).
 const where=one?`<span class="vg-host" title="${esc(one.resource)}">${esc(one.name)}</span> · 설치 ${esc(one.installed||'—')}`
  :`<span class="server-count">서버 ${g.serverList.length}대</span> · <span class="vg-host-list">${g.serverList.slice(0,3).map(s=>esc(s.name.replace(/^soar-sec-dev-/,''))).join(', ')}${g.serverList.length>3?' 외':''}</span>`;
 return `<details class="cve-group" data-key="vg-${esc(g.key)}"><summary>
  <div class="vg-main"><strong>${esc(g.package)}</strong><small>${where}</small></div>
  <div class="vg-count"><b>${g.items.length}</b><span>CVE 종류</span></div>
  <div class="vg-sev">${sevBar(g.counts,g.items.length)}<div class="vg-chips">${SEV_ORDER.filter(s=>g.counts[s]).map(s=>sevChip(s,g.counts[s])).join('')}</div></div>
  <div class="vg-meta"><span class="vg-score" title="CVSS = 취약점 위험 점수(0~10, 높을수록 위험). 이 패키지 안에서 가장 높은 값입니다.">위험 점수 <b>${g.maxCvss??'—'}</b><em>CVSS 최고</em></span>${fix}${g.items.some(v=>v.rebootRequired===true)?'<span class="fix-state reboot">재부팅 필요</span>':''}${g.items.some(v=>v.exploitAvailable==='YES')?'<span class="fix-state exploit">공격 코드 공개</span>':''}</div></summary>
 ${fixPanel(g)}
  ${one?'':`<div class="vg-servers"><h3>영향받는 서버 ${g.serverList.length}대</h3><ul>${g.serverList.map(s=>`<li><button class="link-button" data-vuln-target="${esc(s.resource)}" title="${esc(s.resource)}">${esc(s.name)}</button><span>설치 ${esc(s.installed||'—')}</span><span>CVE ${s.count}건</span>${s.fixable?`<span class="fix-state ok">수정 버전 명시 ${s.fixable}건</span>`:'<span class="fix-state wait">수정 버전 미제공</span>'}</li>`).join('')}</ul></div>`}
  <div class="table-scroll"><table><thead><tr><th>심각도</th><th title="CVSS = 취약점 위험 점수(0~10, 높을수록 위험)">위험 점수(CVSS)</th><th>EPSS</th><th>CVE</th><th>공격 코드</th><th>Inspector 수정 버전</th><th>영향 서버</th></tr></thead><tbody>${top.map(v=>`<tr><td>${sevChip(v.severity)}</td><td>${v.cvss??'—'}</td><td>${pctScore(v.epss)}</td><td title="${esc(v.title||'')}">${cveLink(v)}</td><td>${v.exploitAvailable==='YES'?'<span class="bad-text">공개됨</span>':v.exploitAvailable==='NO'?'없음':'—'}</td><td>${esc(fixedVersionText(v))}</td><td class="cve-hosts">${v.hosts.sort().map(h=>`<span>${esc(h)}</span>`).join('')}</td></tr>`).join('')}</tbody></table></div>
  ${g.items.length>VULN_PREVIEW?`<p class="muted vg-more">CVSS 상위 ${VULN_PREVIEW}종만 표시 · 나머지 ${g.items.length-VULN_PREVIEW}종은 CVE CSV로 확인</p>`:''}
 </details>`;
}
export function vulnerabilityMarkup(data){
 const MAIN_SEVERITIES=['CRITICAL','HIGH','MEDIUM','LOW'],allRows=data.items.filter(v=>MAIN_SEVERITIES.includes(v.severity)),hiddenRows=data.items.length-allRows.length,rows=filteredRows(allRows),groups=vulnGroups(rows),pages=Math.max(1,Math.ceil(groups.length/(vulnSize||groups.length||1)));
 vulnPage=Math.min(vulnPage,pages);const size=vulnSize||groups.length||1,page=groups.slice((vulnPage-1)*size,vulnPage*size);
 const warn=(data.warnings||[]).map(w=>`<p class="panel-error" role="status">${esc(w)}</p>`).join('');
 const stats=vulnerabilityCounts(rows),allStats=vulnerabilityCounts(allRows),totals=allStats.groups;
 const servers=new Set(rows.map(v=>v.resource)).size;
 return `${warn}<div class="view-intro"><span>Inspector · 최근 31일 관측 · 서버 <strong>${servers}대</strong> · 패키지 <strong>${groups.length}개</strong></span><span class="view-summary"${hiddenRows?` title="정보·미평가 등 긴급~낮음 밖의 finding ${hiddenRows}건은 표시하지 않습니다"`:''}>고유 CVE <strong>${stats.unique}종</strong> · 서버별 finding ${rows.length}건</span></div>
 <div class="vuln-summary" role="group" aria-label="취약점 위험도 필터">${['CRITICAL','HIGH','MEDIUM','LOW'].map(sev=>summaryButton(sev,totals[sev],allStats.unique)).join('')}</div>
 <section class="panel full-panel">${header('패키지별 취약점',`<label class="page-size">표시 <select id="vuln-size">${[25,50,100,200,0].map(n=>`<option value="${n}"${n===vulnSize?' selected':''}>${n?n+'개씩':'전체'}</option>`).join('')}</select></label><button id="export-vulns" class="text-button">↓ CVE CSV 내보내기</button>`)}
 ${vulnTarget?`<div class="vuln-toolbar"><button class="text-button" data-vuln-target="">전체 서버 보기 ←</button></div>`:''}
 ${page.length?`<div class="cve-groups"><div class="vg-head" aria-hidden="true"><span>패키지 · 영향 서버</span><span>취약점</span><span>위험도 구성</span><span title="CVSS = 취약점 위험 점수(0~10, 높을수록 위험)">위험 점수(CVSS) · 조치 정보</span></div>${page.map(vulnGroupMarkup).join('')}</div>`:empty(vulnFilter?'선택한 조건에 맞는 취약점이 없습니다.':hiddenRows?`긴급~낮음 취약점이 없습니다 (그 밖의 finding ${hiddenRows}건은 표시하지 않음).`:'현재 열린 취약점이 없습니다.')}
 <div class="table-pager"><button data-vuln-page="prev" ${vulnPage<=1?'disabled':''}>← 이전</button><span>${vulnPage} / ${pages}</span><button data-vuln-page="next" ${vulnPage>=pages?'disabled':''}>다음 →</button></div></section>`;
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
