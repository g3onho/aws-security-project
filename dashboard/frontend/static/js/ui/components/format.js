// 화면 표시용 문자열·시각 변환(순수 함수).
export const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export const format=(time,short=false)=>time==null?'데이터 없음':new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',...(short?{}:{month:'2-digit',day:'2-digit'}),hour:'2-digit',minute:'2-digit',hour12:false}).format(time);
// 구간이 하루를 넘으면 시:분만 찍힌 x축은 읽을 수 없다. 창 길이를 보고 날짜를 붙인다.
export const formatAt=(time,span=0)=>time==null?'데이터 없음':new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',...(span>24*3600000?{month:'2-digit',day:'2-digit'}:{}),hour:'2-digit',minute:'2-digit',hour12:false}).format(time);
export const milliseconds=value=>value?Date.parse(value):null;
// arn:aws:ec2:…:instance/i-0abc → i-0abc, AWS::IAM::AccessKey:ASIA… → ASIA… (전체 값은 title 로)
export const shortResource=r=>String(r||'').split(/[/:]/).filter(Boolean).pop()||String(r||'');
