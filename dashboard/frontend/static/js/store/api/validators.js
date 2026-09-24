// 응답 계약 검증. 해석할 수 없는 응답을 정상 빈 목록으로 바꾸지 않는다(설계 2.2).
export const CONTRACT_ERROR='서버 데이터 형식이 올바르지 않습니다. 새로고침 후 다시 확인해주세요.';
export const isObject=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
export function requireContract(valid){if(!valid)throw Error(CONTRACT_ERROR);}
export function envelope(payload){
 requireContract(isObject(payload)&&isObject(payload.data)&&isObject(payload.meta)&&payload.meta.schemaVersion==='1');
 return payload;
}
export function listEnvelope(payload){
 envelope(payload);requireContract(Array.isArray(payload.data.items));
 return payload;
}
export const warningsOf=payload=>Array.isArray(payload?.meta?.warnings)?payload.meta.warnings.filter(w=>typeof w==='string'):[];
