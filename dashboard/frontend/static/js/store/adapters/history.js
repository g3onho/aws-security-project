// 대응 이력 DTO → 화면 모델. id 없는 행은 뺀다(표 키·상세 연결 불가).
const isObject=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
export function adaptHistory(items,jobs){
 const rows=items.filter(row=>isObject(row)&&typeof row.id==='string'&&row.id);
 const warnings=rows.length<items.length?[`대응 이력 ${items.length-rows.length}건이 형식 오류로 제외되었습니다.`]:[];
 return {rows,jobs:Array.isArray(jobs)?jobs.filter(isObject):[],warnings};
}
