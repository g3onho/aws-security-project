function cell(value) {
  let text=String(value??'');
  // Spreadsheet programs must treat package/resource names as text, not formulas.
  if (/^[\s]*[=+@-]/.test(text)) text="'"+text;
  return '"'+text.replaceAll('"','""')+'"';
}

export function eventCsv(items) {
  const columns=['ID','발생 시각','제목','위험도','리전','자원','탐지 소스','상태'];
  const rows=items.map(e=>[e.id,e.observedAt,e.title,e.severity,e.region,e.resource,e.source,e.actionState]);
  return '\uFEFF'+[columns,...rows].map(row=>row.map(cell).join(',')).join('\r\n');
}

export function vulnerabilityCsv(data,target='') {
  const columns=['심각도','CVSS','CVE','패키지','설치 버전','수정 버전','대상','출처','EPSS','공격 코드 공개','재부팅 필요','업데이트 명령','참고 링크'];
  const rows=data.items.filter(item=>!target||item.resource===target).map(item=>
    [item.severity,item.cvss,item.cveId,item.package,item.installedVersion,item.fixedVersion,item.resource,item.source,
     item.epss,item.exploitAvailable,item.rebootRequired==null?'':item.rebootRequired?'예':'아니요',item.updateCommand,item.referenceUrl]);
  return '\uFEFF'+[columns,...rows].map(row=>row.map(cell).join(',')).join('\r\n');
}

export function downloadCsv(filename,text) {
  const url=URL.createObjectURL(new Blob([text],{type:'text/csv;charset=utf-8'}));
  const link=document.createElement('a');link.href=url;link.download=filename;
  document.body.append(link);link.click();link.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}

export function downloadFile(filename,text,type='application/json;charset=utf-8') {
  const url=URL.createObjectURL(new Blob([text],{type}));
  const link=document.createElement('a');link.href=url;link.download=filename;
  document.body.append(link);link.click();link.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}

// 차단 IP 보고서(v25). 서버 GET /api/blocklist?format=csv 와 같은 열·같은 수식 주입 방지 규칙이다.
export function blocklistCsv(items,iso) {
  const columns=['IP','상태','차단 경로','NACL 규칙','차단 시각','만료 시각','오탐 예외','해제 시각','해제자','해제 사유','미끼 세션','명령 수','마지막 관측','의도','상위 명령'];
  const rows=items.map(i=>{
    const s=i.sessions||{};
    return [i.ip,i.state,i.source||'',i.naclRule??i.ruleNumber??'',iso(i.blockedAt),i.expiresAt?iso(i.expiresAt):(i.state==='blocked'?'영구':''),i.allowlisted?'예':'',
      iso(i.releasedAt),i.releasedBy||'',i.releaseReason||'',s.sessionCount??'',s.commandCount??'',iso(s.lastSeenAt),(s.intents||[]).join(' '),(s.topCommands||[]).map(c=>c.key).join(' | ')];
  });
  return '\uFEFF'+[columns,...rows].map(row=>row.map(cell).join(',')).join('\r\n');
}
