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

// ── 화면 우측 상단 [로그 저장] (v28). 모두 위의 cell()·BOM 규칙을 그대로 쓴다(수식 주입 방지, 엑셀 한글). ──────────────────────
export function stampedName(prefix,ext='csv'){
  const d=new Date(),p=n=>String(n).padStart(2,'0');
  return `${prefix}-${d.getFullYear()}${p(d.getMonth()+1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}.${ext}`;
}
const oneDecimal=v=>v==null?'':Math.round(v*10)/10;
const csvText=(columns,rows)=>'﻿'+[columns,...rows].map(row=>row.map(cell).join(',')).join('\r\n');

// 인프라 모니터링: 서버 행(선택 기간의 현재·평균·최대·임계 초과)과 CloudWatch 경보 행을 한 표에 둔다. hosts=hostViews(metrics), svc=/api/infra/status 응답.
export function infrastructureCsv(hosts,svc) {
  const columns=['구분','이름','ID','CPU 현재(%)','CPU 평균(%)','CPU 최대(%)','메모리 현재(%)','메모리 평균(%)','메모리 최대(%)','임계치(%)','임계 초과 구간','상태','비고'];
  const status=new Map((svc?.components||[]).map(c=>[c.resource,c.status]));
  const rows=hosts.map(h=>['서버',h.name,h.resource,oneDecimal(h.stats.cpu.now),oneDecimal(h.stats.cpu.avg),oneDecimal(h.stats.cpu.max),
    oneDecimal(h.stats.memory.now),oneDecimal(h.stats.memory.avg),oneDecimal(h.stats.memory.max),h.threshold.cpu,h.breaches.length,
    status.get(h.resource)||'',h.switches.length?`인스턴스 교체 ${h.switches.length}회`:'']);
  for(const a of svc?.alarms||[])rows.push(['경보',a.name,'','','','','','','','','',a.state,[a.label,a.updatedAt].filter(Boolean).join(' · ')]);
  return csvText(columns,rows);
}

// 보안 시나리오: 실행 이력(GET /api/drills). 항목별 SSM 결과는 실행 중에만 화면이 조회하므로 이 표에는 넣지 않는다.
export function drillsCsv(runs) {
  const columns=['실행 ID','유형','제목','SEC 항목','상태','접수 시각','실행 주체','대상 IP'];
  const rows=(runs?.items||[]).map(r=>[r.runId,r.type||'',r.title||'',(r.secs||[]).join(' '),r.state||'',
    r.createdAt||(r.startedAt?new Date(r.startedAt).toISOString():''),r.actor||'',r.targetIp||'']);
  return csvText(columns,rows);
}

// 허니팟: 세션 목록(비밀번호·명령 원문 없음). iso=시각(ms)→문자열 함수.
export function honeypotSessionsCsv(items,iso) {
  const columns=['세션 ID','시작 시각','종료 시각','공격 IP','로그인 시도 수','명령 수','의도','위험도','AI 분석','세션 종료 분석'];
  const ai=v=>v===true?'적용':v===false?'미적용(규칙 판정)':'';
  const rows=items.map(s=>[s.sessionId,iso(s.startedAt),iso(s.endedAt),s.srcIp||'',s.authCount??'',s.commandCount??'',s.intent||'',s.severity||'',ai(s.aiApplied),s.analyzed?'있음':'없음']);
  return csvText(columns,rows);
}
