// 화면 표시용 문자열·시각 변환(순수 함수).
export const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export const format=(time,short=false)=>time==null?'데이터 없음':new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',...(short?{}:{month:'2-digit',day:'2-digit'}),hour:'2-digit',minute:'2-digit',hour12:false}).format(time);
// 구간이 하루를 넘으면 시:분만 찍힌 x축은 읽을 수 없다. 창 길이를 보고 날짜를 붙인다.
export const formatAt=(time,span=0)=>time==null?'데이터 없음':new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',...(span>24*3600000?{month:'2-digit',day:'2-digit'}:{}),hour:'2-digit',minute:'2-digit',hour12:false}).format(time);
export const milliseconds=value=>value?Date.parse(value):null;
// arn:aws:ec2:…:instance/i-0abc → i-0abc, AWS::IAM::AccessKey:ASIA… → ASIA… (전체 값은 title 로)
// 명령어는 코드 칸 + 복사 버튼으로 보인다(복사는 app.js 의 [data-copy] 위임 처리).
export const cmdBlock=text=>`<div class="cmd-block"><code>${esc(text)}</code><button type="button" class="copy-button" data-copy="${esc(text)}" aria-label="명령어 복사">복사</button></div>`;
// 문장 안의 `백틱` 구간을 코드 칸으로 바꾼다. 나머지는 이스케이프한 글자 그대로.
export const withCode=text=>String(text??'').split(/`([^`]+)`/).map((part,i)=>i%2?cmdBlock(part):esc(part)).join('');
export const shortResource=r=>{
 const text=String(r||''),waf=text.match(/:wafv2:[^/]*\/webacl\/([^/]+)/);   // WAF ARN 끝은 ID 라서(예: .../web/1) 이름을 보인다
 return waf?waf[1]:text.split(/[/:]/).filter(Boolean).pop()||text;
};
