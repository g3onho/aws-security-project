function cell(value) {
  let text=String(value??'');
  // Spreadsheet programs must treat package/resource names as text, not formulas.
  if (/^[\s]*[=+@-]/.test(text)) text="'"+text;
  return '"'+text.replaceAll('"','""')+'"';
}

export function vulnerabilityCsv(data,target='') {
  const columns=['심각도','CVSS','CVE','패키지','설치 버전','수정 버전','대상','계열'];
  const rows=data.items.filter(item=>!target||item.target===target).map(item=>
    [item.severity,item.cvss,item.cveId,item.package,item.installedVersion,item.fixedVersion,item.target,item.family]);
  return '\uFEFF'+[columns,...rows].map(row=>row.map(cell).join(',')).join('\r\n');
}

export function downloadCsv(filename,text) {
  const url=URL.createObjectURL(new Blob([text],{type:'text/csv;charset=utf-8'}));
  const link=document.createElement('a');link.href=url;link.download=filename;
  document.body.append(link);link.click();link.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
