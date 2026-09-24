// Geographic labels and UI vocabulary; operational data comes from the API.
export const regions = [
  {id:'ap-northeast-2',name:'서울',en:'SEOUL',lon:126.978,lat:37.566},
  {id:'ap-northeast-1',name:'도쿄',en:'TOKYO',lon:139.69,lat:35.68},
  {id:'ap-southeast-1',name:'싱가포르',en:'SINGAPORE',lon:103.82,lat:1.35},
  {id:'eu-central-1',name:'프랑크푸르트',en:'FRANKFURT',lon:8.68,lat:50.11},
  {id:'us-east-1',name:'버지니아 북부',en:'VIRGINIA',lon:-77.49,lat:38.75},
  {id:'global',name:'글로벌 / 위치 미상',en:'GLOBAL'},
  {id:'us-east-2',name:'오하이오',en:'OHIO',lon:-82.99,lat:39.96},
  {id:'us-west-1',name:'캘리포니아',en:'CALIFORNIA',lon:-121.89,lat:37.34},
  {id:'us-west-2',name:'오리건',en:'OREGON',lon:-122.68,lat:45.52},
  {id:'ap-south-1',name:'뭄바이',en:'MUMBAI',lon:72.88,lat:19.08},
  {id:'ap-northeast-3',name:'오사카',en:'OSAKA',lon:135.5,lat:34.69},
  {id:'ap-southeast-2',name:'시드니',en:'SYDNEY',lon:151.21,lat:-33.87},
  {id:'ca-central-1',name:'캐나다 중부',en:'CANADA',lon:-73.57,lat:45.5},
  {id:'eu-west-1',name:'아일랜드',en:'IRELAND',lon:-6.26,lat:53.35},
  {id:'eu-west-2',name:'런던',en:'LONDON',lon:-0.13,lat:51.51},
  {id:'eu-west-3',name:'파리',en:'PARIS',lon:2.35,lat:48.86},
  {id:'eu-north-1',name:'스톡홀름',en:'STOCKHOLM',lon:18.07,lat:59.33},
  {id:'sa-east-1',name:'상파울루',en:'SAO PAULO',lon:-46.63,lat:-23.55},
];
export const severityColors = {Critical:'#EF777F',High:'#E7A064',Medium:'#D8CA78',Low:'#32D4BE',Informational:'#85B1D5',Unknown:'#8FA295'};
// 탐지 소스 필터 목록. Security Hub ProductName 기준(실측 2026-09-24: IAM Access Analyzer 2건).
export const sources = ['GuardDuty','Security Hub','Config','IAM Access Analyzer','WAF','Inspector','Trivy','CloudWatch'];
export const statuses = ['승인 대기','승인됨','취소됨','실행 대기','조치 실행 중','실행 완료','실행 실패','재검증 대기','재검증 중','해결','재검증 실패','재검증 오류','상태 확인 중'];
