export const DEMO_NOW = Date.parse('2026-09-18T15:00:00+09:00');
export const regions = [
  {id:'ap-northeast-2',name:'서울',en:'SEOUL',lon:126.978,lat:37.566,resource:'i-seoul-app-01'},
  {id:'ap-northeast-1',name:'도쿄',en:'TOKYO',lon:139.69,lat:35.68,resource:'i-tokyo-app-01'},
  {id:'ap-southeast-1',name:'싱가포르',en:'SINGAPORE',lon:103.82,lat:1.35,resource:'i-singapore-app-01'},
  {id:'eu-central-1',name:'프랑크푸르트',en:'FRANKFURT',lon:8.68,lat:50.11,resource:'i-frankfurt-app-01'},
  {id:'us-east-1',name:'버지니아 북부',en:'VIRGINIA',lon:-77.49,lat:38.75,resource:'i-virginia-app-01'},
  {id:'global',name:'글로벌 / 위치 미상',en:'GLOBAL',resource:null},
  {id:'us-east-2',name:'오하이오',en:'OHIO',lon:-82.99,lat:39.96,resource:'i-us-east-2-app-01'},
  {id:'us-west-1',name:'캘리포니아',en:'CALIFORNIA',lon:-121.89,lat:37.34,resource:'i-us-west-1-app-01'},
  {id:'us-west-2',name:'오리건',en:'OREGON',lon:-122.68,lat:45.52,resource:'i-us-west-2-app-01'},
  {id:'ap-south-1',name:'뭄바이',en:'MUMBAI',lon:72.88,lat:19.08,resource:'i-ap-south-1-app-01'},
  {id:'ap-northeast-3',name:'오사카',en:'OSAKA',lon:135.5,lat:34.69,resource:'i-ap-northeast-3-app-01'},
  {id:'ap-southeast-2',name:'시드니',en:'SYDNEY',lon:151.21,lat:-33.87,resource:'i-ap-southeast-2-app-01'},
  {id:'ca-central-1',name:'캐나다 중부',en:'CANADA',lon:-73.57,lat:45.5,resource:'i-ca-central-1-app-01'},
  {id:'eu-west-1',name:'아일랜드',en:'IRELAND',lon:-6.26,lat:53.35,resource:'i-eu-west-1-app-01'},
  {id:'eu-west-2',name:'런던',en:'LONDON',lon:-0.13,lat:51.51,resource:'i-eu-west-2-app-01'},
  {id:'eu-west-3',name:'파리',en:'PARIS',lon:2.35,lat:48.86,resource:'i-eu-west-3-app-01'},
  {id:'eu-north-1',name:'스톡홀름',en:'STOCKHOLM',lon:18.07,lat:59.33,resource:'i-eu-north-1-app-01'},
  {id:'sa-east-1',name:'상파울루',en:'SAO PAULO',lon:-46.63,lat:-23.55,resource:'i-sa-east-1-app-01'},
];

// v2.1: 공격 출발지를 AWS 리전과 좌표가 겹치던 파리/뉴욕/시드니 대신, 공개 위협 인텔리전스
// 자료(CISA, MITRE ATT&CK 등) 기준으로 자주 언급되는 국가 배후 위협 행위자로 교체했다. 국가
// 이름(country)은 지도·상세 패널 표기를 위해 영문으로 통일했다. 그룹명/목적/타겟/전술은 공개
// 자료를 참고해 구성한 교육용 데모 정보이며, 개별 이벤트에 대한 실제 귀속(attribution)이 아니다.
export const threatActors = [
  {id:'north-korea',country:'North Korea',city:'평양',ip:'203.0.113.45',lon:125.75,lat:39.02,
   groups:['Lazarus Group','Kimsuky','Andariel'],
   purpose:'외화 획득(가상자산·금융 탈취), 정찰/첩보, 파괴적 공격',
   targets:['금융기관·가상자산 거래소','국방/정부 기관','언론·방송'],
   tactics:['스피어피싱','제로데이 취약점 악용','SWIFT망 조작 부정 송금','공급망 공격']},
  {id:'china',country:'China',city:'베이징',ip:'198.51.100.77',lon:116.41,lat:39.90,
   groups:['Volt Typhoon','APT41'],
   purpose:'지정학적 갈등 대비 사전 침투·교란 준비, 산업/기술 스파이',
   targets:['통신','에너지','교통','상하수도 등 핵심 인프라'],
   tactics:['Living-off-the-Land(정상 관리 도구 악용)','네트워크 장비 취약점 악용','자격증명 탈취 후 장기 잠복']},
  {id:'russia',country:'Russia',city:'모스크바',ip:'192.0.2.88',lon:37.62,lat:55.75,
   groups:['APT28(Fancy Bear)','APT29(Cozy Bear)','Sandworm'],
   purpose:'첩보/정보 수집, 인프라 교란·파괴',
   targets:['정부/군','에너지','항공','NATO 회원국'],
   tactics:['스피어피싱','무차별 대입 공격','파괴적 와이퍼 악성코드','ICS/OT 악성코드']},
  {id:'iran',country:'Iran',city:'테헤란',ip:'203.0.113.201',lon:51.39,lat:35.69,
   groups:['APT33','OilRig(APT34)','MuddyWater'],
   purpose:'첩보 수집·장기 접근 유지, OT 교란',
   targets:['에너지','항공우주','통신','정부'],
   tactics:['비밀번호 스프레이','소셜 엔지니어링','정상 원격관리 도구 악용','인터넷 노출 PLC 설정 변조']},
  {id:'vietnam',country:'Vietnam',city:'하노이',ip:'198.51.100.132',lon:105.85,lat:21.03,
   groups:['APT32(OceanLotus)'],
   purpose:'기업·정부 대상 첩보 수집, 반체제 인사 감시',
   targets:['현지 진출 외국 기업(자동차·소비재 등)','동남아 각국 정부','인권 운동가·언론인'],
   tactics:['워터링홀 공격','스피어피싱(매크로 문서)','가짜 소프트웨어 업데이트 위장 드라이브 바이 다운로드','DLL 사이드로딩']},
  {id:'pakistan',country:'Pakistan',city:'이슬라마바드',ip:'192.0.2.164',lon:73.06,lat:33.72,
   groups:['APT36(Transparent Tribe)'],
   purpose:'인접국 대상 첩보 수집',
   targets:['인도 정부·군','국방 관련 기관','연구·교육기관'],
   tactics:['스피어피싱(악성 문서·PDF)','정상 클라우드 서비스(구글 드라이브 등) 악용','모바일 악성코드를 통한 감시','실제 이슈를 미끼로 한 사회공학']},
  {id:'india',country:'India',city:'뉴델리',ip:'203.0.113.93',lon:77.21,lat:28.61,
   groups:['Patchwork(APT-C-09)'],
   purpose:'외교·정책 관련 첩보 수집',
   targets:['주변국 외교관·경제 전문가','정부·싱크탱크','대사관·외교 공관'],
   tactics:['스피어피싱(악성 문서 첨부)','알려진 취약점 악용','커스텀 원격제어 악성코드(키로깅·스크린샷)','레지스트리·시작프로그램 등록을 통한 지속성 확보']},
  {id:'turkey',country:'Turkey',city:'앙카라',ip:'198.51.100.210',lon:32.85,lat:39.93,
   groups:['Sea Turtle'],
   purpose:'DNS 인프라 탈취를 통한 첩보 수집',
   targets:['DNS 등록기관·통신사·ISP','정부기관','중동·유럽 지역 조직'],
   tactics:['DNS 하이재킹(레코드 조작)','가짜 로그인 페이지를 통한 자격증명 수집','공개 취약점 악용 및 웹셸 설치','정상 SSL 인증서 탈취 후 재사용']},
];
export const severityColors = {Critical:'#EF777F',High:'#E7A064',Medium:'#D8CA78',Low:'#32D4BE'};
export const sources = ['GuardDuty','Security Hub','Config','Inspector','Trivy','CloudWatch'];
export const statuses = ['신규','승인 대기','조치 실행 중','재검증 대기','재검증 중','해결','재검증 실패'];
const scenarios = [
  {scenario:'SEC-01',title:'SSH 포트 외부 공개',source:'Config',severity:'High',criterion:'0.0.0.0/0에 대한 TCP 22 인바운드 규칙 수',before:1,after:0,unit:'개',evidence:'sg-web-01의 TCP 22 인바운드가 0.0.0.0/0에 공개되어 있습니다.',recommendation:'해당 공개 규칙을 회수하고 SSM 연결 상태를 확인합니다.',mode:'자동'},
  {scenario:'SEC-02',title:'HTTP 보안 헤더 누락',source:'Security Hub',severity:'Medium',criterion:'필수 보안 헤더 누락 수 (동일 URL / 동일 헤더 집합)',before:3,after:0,unit:'개',evidence:'GET / 응답에 X-Content-Type-Options 등 필수 헤더 3개가 없습니다. 데모 검사 결과를 정규화한 항목입니다.',recommendation:'Nginx 응답 헤더 설정을 적용한 뒤 같은 URL을 재검사합니다.',mode:'자동'},
  {scenario:'SEC-03',title:'MySQL 3306 포트 과다 공개',source:'Config',severity:'Critical',criterion:'0.0.0.0/0에 대한 TCP 3306 인바운드 규칙 수',before:1,after:0,unit:'개',evidence:'sg-db-manual의 TCP 3306 인바운드가 외부 전체 주소를 허용합니다.',recommendation:'DB 인바운드를 애플리케이션 보안 그룹으로 제한합니다.',mode:'수동'},
  {scenario:'SEC-04',title:'컨테이너 이미지 취약점',source:'Trivy',severity:'High',criterion:'고정 검사 DB demo-20260918의 HIGH 이상 취약점 수',before:12,after:2,unit:'개',evidence:'app:1.2 이미지에서 HIGH 이상 취약점 12개가 발견되었습니다. 동일 검사 DB로 비교합니다.',recommendation:'수정된 app:1.3 이미지로 교체하고 동일 기준으로 재검사합니다.',mode:'수동'},
  {scenario:'DETECT-01',title:'외부 IP의 비정상 접근 탐지',source:'GuardDuty',severity:'Critical',criterion:'동일 10분 관찰 구간의 비정상 접근 수',before:8,after:0,unit:'건',evidence:'외부 출발 IP에서 대상 EC2로 반복적인 비정상 접근이 탐지되었습니다. IP·좌표는 시연용이며 실제 공격자 위치가 아닙니다.',recommendation:'출발 IP와 접근 근거를 검토한 뒤 승인된 접근 차단을 수행하고 재관찰합니다.',mode:'수동'},
  {scenario:'NMS-01',title:'EC2 CPU 사용률 80% 초과',source:'CloudWatch',severity:'Medium',criterion:'동일 5분 평균 CPU 사용률',before:86,after:58,unit:'%',evidence:'5분 평균 CPU 사용률 86%가 임계치 80%를 초과했습니다.',recommendation:'부하 프로세스를 확인하고 조정 후 5분 평균을 재확인합니다.',mode:'수동'},
  {scenario:'SEC-04',title:'패키지 취약점 업데이트 필요',source:'Inspector',severity:'Low',criterion:'동일 패키지 집합의 미해결 취약점 수',before:4,after:0,unit:'개',evidence:'인스턴스 패키지 점검에서 업데이트가 필요한 항목 4개를 발견했습니다.',recommendation:'승인된 패키지를 업데이트하고 동일 패키지 집합을 점검합니다.',mode:'수동'},
  {scenario:'NMS-02',title:'EC2 메모리 사용률 80% 초과',source:'CloudWatch',severity:'High',criterion:'동일 5분 평균 메모리 사용률',before:84,after:63,unit:'%',evidence:'CloudWatch Agent의 메모리 사용률 평균이 84%입니다.',recommendation:'메모리 사용 프로세스를 확인하고 조정 후 재점검합니다.',mode:'수동'},
];
export function createEvents(){
 return regions.flatMap((r,ri)=>Array.from({length:ri===0?24:ri===5?5:12},(_,i)=>{
  const forceAttack=r.lon!==undefined&&i<2; // guarantee at least 2 differently-attributed attack lines per geo region
  const s=forceAttack?scenarios.find(x=>x.scenario==='DETECT-01'):ri===5?{scenario:'IAM-01',title:'글로벌 IAM 역할 신뢰 정책 검토',source:'Security Hub',severity:'High',criterion:'승인되지 않은 외부 계정 신뢰 항목 수',before:1,after:0,unit:'개',evidence:'글로벌 IAM 역할의 신뢰 정책에 검토가 필요한 외부 계정 항목이 있습니다. 지리 좌표가 없는 데모 탐지입니다.',recommendation:'신뢰 관계의 업무 필요성을 검토하고 승인되지 않은 계정 항목을 제거합니다.',mode:'수동'}:scenarios[(i+ri)%scenarios.length];
  const age=[.12,.3,.55,.8,1.2,2,3,4,5,7,9,11,13,15,17,20,23,30,40,50,65,80,110,145][i];
  const at=DEMO_NOW-age*3600000;
  const status=i%7===6?'해결':i%7===5?'재검증 실패':s.mode==='자동'?'신규':'승인 대기';
  const resource=ri===5?'arn:aws:iam::demo:role/shared':s.scenario==='SEC-03'?`sg-${r.id}-db`:s.source==='Trivy'?`ecr/${r.id}/app:1.2`:r.resource;
  const isAttack=s.source==='GuardDuty';
  let origin=threatActors[(ri+i)%threatActors.length];
  if(r.lon!==undefined&&Math.hypot(r.lon-origin.lon,r.lat-origin.lat)<3)origin=threatActors[(ri+i+1)%threatActors.length];
  const sourceIp=isAttack?(i>=20?'10.0.0.8':origin.ip):null;
  const sourceLocation=isAttack&&i<12?{city:origin.city,lon:origin.lon,lat:origin.lat,provenance:'모의 위치 · IP 실제 조회 아님',actorId:origin.id,country:origin.country}:null;
  const geoStatus=!isAttack?'해당 없음':sourceLocation?'모의 위치':i>=20?'사설 IP · 위치 미상':'위치 미상';
  return {...s,sourceIp,sourceLocation,geoStatus,id:`EVT-${String(ri*100+i+1).padStart(4,'0')}`,region:r.id,environment:i%6===5?'staging':'production',resource,at,status,execution:status==='해결'||status==='재검증 실패'?'성공':'미실행',verification:status==='해결'?'통과':status==='재검증 실패'?'실패':'미실행',beforeAt:at,afterAt:status==='해결'||status==='재검증 실패'?at+180000:null,afterValue:status==='해결'?(s.unit==='%'?s.after:0):status==='재검증 실패'?(s.unit==='%'?s.before:s.after||1):null,history:[{at,text:'탐지 근거 수집'},...(status==='해결'||status==='재검증 실패'?[{at:at+60000,text:'데모 조치 실행 성공'},{at:at+180000,text:status==='해결'?'재검증 통과':'재검증 실패 · 미해결 항목 존재'}]:[])]};
 }));
}
export function metricsFor(region,hours,endOffset=0,environment='production'){
 if(!region?.resource)return null;
 const n=regions.findIndex(r=>r.id===region.id)%5;
 const atOffset=offset=>{const k=Math.floor(offset)%12;const env=environment==='staging'?-12:0;return {cpu:[58,61,64,68,73,81,86,65,57,44,47,42][k]+n*2+env,memory:[63,65,66,71,76,84,68,63,59,55,54,51][k]+n+env};};
 return {resource:region.resource,...atOffset(endOffset),at:DEMO_NOW-endOffset*3600000,points:Array.from({length:12},(_,i)=>{const offset=endOffset+(11-i)*hours/11;return {at:DEMO_NOW-offset*3600000,...atOffset(offset)};})};
}
