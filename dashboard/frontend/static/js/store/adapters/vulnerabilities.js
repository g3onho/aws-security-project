// 취약점 DTO → 화면 모델. Inspector 는 UNTRIAGED 를 쓴다. 그 밖의 모르는 값은 UNKNOWN.
export const VULN_SEVERITIES=Object.freeze(['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL','UNTRIAGED','UNKNOWN']);
const isObject=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
export function adaptVulnerabilities(items){
 const rows=[];let invalid=0,unknown=0;
 for(const dto of items){
  if(!isObject(dto)||typeof dto.id!=='string'||!dto.id||typeof dto.resource!=='string'){invalid++;continue;}
  const known=VULN_SEVERITIES.includes(dto.severity);if(!known)unknown++;
  rows.push(known?dto:{...dto,severity:'UNKNOWN'});
 }
 const warnings=[];
 if(invalid)warnings.push(`취약점 ${invalid}건이 형식 오류로 목록에서 제외되었습니다.`);
 if(unknown)warnings.push(`취약점 ${unknown}건의 심각도를 알 수 없어 UNKNOWN으로 표시합니다.`);
 return {rows,warnings};
}
