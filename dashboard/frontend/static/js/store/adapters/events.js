// 이벤트 DTO → 화면 모델. 순수 함수(DOM·HTTP·Store 변경 없음, 설계 2.2 어댑터).
export const ACTION_LABELS=Object.freeze({PENDING_APPROVAL:'승인 대기',APPROVED:'승인됨',CANCELLED:'취소됨',QUEUED:'실행 대기',
 RUNNING:'조치 실행 중',EXECUTED:'실행 완료',EXECUTION_FAILED:'실행 실패',VERIFY_QUEUED:'재검증 대기',VERIFYING:'재검증 중',
 VERIFIED:'해결',VERIFICATION_FAILED:'재검증 실패',VERIFICATION_ERROR:'재검증 오류',RECONCILING:'상태 확인 중'});
export const SEVERITIES=Object.freeze(['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL','UNKNOWN']);
const isObject=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const title=severity=>severity[0]+severity.slice(1).toLowerCase();

// 한 건. 필수 ID·상태·권한·시각이 틀리면 null(그 행만 제외). 미지의 심각도는 UNKNOWN.
export function adaptEvent(dto){
 if(!isObject(dto)||typeof dto.id!=='string'||!dto.id||typeof dto.title!=='string'||typeof dto.resource!=='string'
    ||typeof dto.actionState!=='string'||!Object.hasOwn(ACTION_LABELS,dto.actionState)
    ||!Array.isArray(dto.allowedActions)||typeof dto.observedAt!=='string')return {row:null};
 const at=Date.parse(dto.observedAt);if(!Number.isFinite(at))return {row:null};
 const known=SEVERITIES.includes(dto.severity),severity=known?dto.severity:'UNKNOWN';
 // 플레이북이 없는 탐지(actionable:false)는 승인할 수 없다 — '승인 대기' 대신 '탐지됨'.
 const status=dto.actionable===false&&dto.actionState==='PENDING_APPROVAL'?'탐지됨':ACTION_LABELS[dto.actionState];
 return {row:{...dto,at,status,severity:title(severity)},unknownSeverity:!known};
}

// 목록. 잘못된 행은 빼고 건수를 경고로 남긴다 — 조용히 사라지지 않게.
export function adaptEvents(items,label='탐지'){
 const rows=[];let invalid=0,unknown=0;
 for(const dto of items){const {row,unknownSeverity}=adaptEvent(dto);if(!row){invalid++;continue;}if(unknownSeverity)unknown++;rows.push(row);}
 const warnings=[];
 if(invalid)warnings.push(`${label} ${invalid}건이 형식 오류로 목록에서 제외되었습니다.`);
 if(unknown)warnings.push(`${label} ${unknown}건의 위험도를 알 수 없어 Unknown으로 표시합니다.`);
 return {rows,warnings};
}
