export function toCSV(rows){
 const columns=[['ID','id'],['발생 시각','at'],['시나리오','scenario'],['제목','title'],['위험도','severity'],['리전','region'],['자원','resource'],['탐지 소스','source'],['대응 방식','mode'],['상태','status'],['실행 결과','execution'],['재검증','verification'],['출발 IP','sourceIp'],['위치 상태','geoStatus']];
 const cell=v=>'"'+String(v??'').replace(/^[=+@-]/,"'$&").replaceAll('"','""')+'"';
 return '\uFEFF'+[columns.map(c=>cell(c[0])).join(','),...rows.map(e=>columns.map(c=>cell(c[1]==='at'?new Date(e.at).toISOString():e[c[1]])).join(','))].join('\r\n');
}

