// v23 화면 개편 테스트 공용 자료(테스트 파일이 아니다 — node --test 가 고르지 않는 이름).
import {snapshot} from './dom-test-support.mjs';

// v23 화면 개편: 문제 → 왜 위험 → 고치는 법 → 고쳐졌나(조치 기록)를 따라갈 수 있어야 한다. 새 API 없이 선택 필드만 쓴다.
export const envelope=data=>({data,meta:{schemaVersion:'1',asOf:new Date().toISOString(),requestId:'fixture',warnings:[]}});
export const iso=()=>new Date().toISOString();
export function detailedEvents(){
 const payload=snapshot('Security groups should not allow unrestricted access to ports with high risk');
 Object.assign(payload.data.items[0],{controlId:'EC2.19',source:'Security Hub',
  description:'This control checks whether unrestricted incoming traffic is accessible to high-risk ports.',
  remediation:{text:null,url:'https://docs.aws.amazon.com/console/securityhub/EC2.19/remediation'},
  guidance:{key:'EC2.19',kind:'control',title:'보안그룹이 위험 포트를 인터넷에 공개',problem:'22·3306·3389 같은 고위험 포트가 0.0.0.0/0 에 열려 있습니다.',
   risk:'DB·원격 접속 포트가 인터넷 스캔과 무차별 대입에 노출됩니다.',fix:['공개 규칙 삭제, DB 포트는 앱 서버 보안그룹에서만 허용'],
   where:'보안그룹 규칙 — Terraform 이 만든 규칙은 코드에서, 수동으로 만든 규칙은 콘솔에서 삭제',whereKey:'sg',scenario:'SEC-01·SEC-03',note:null},
  autoRemediation:{mode:'conditional',label:'조건부 자동',playbookId:'ASR-RevokeSecurityGroupIngress',action:'보안그룹 전체 공개 규칙 회수',
   condition:'보안그룹에 AutoRemediation=enabled 태그가 있을 때만 회수',reason:'화이트리스트 일치(보안그룹 공개 규칙).',basis:'현재 설정으로 본 예상입니다.'}});
 return payload;
}
export const SUMMARY=()=>envelope({totalEvents:1,verifiedEvents:0,resolutionRate:0,openVulnerabilities:{total:7,bySeverity:{},byRegion:{}},
 automation:{configured:true,total:4,autoExecuted:2,succeeded:1,failed:1,inProgress:0,noChange:0,manual:2,dryRun:0,byStatus:{},byDecision:{},
  recent:[{actionId:'ssm-1',eventId:'EVT-0003',controlId:'EC2.2',controlTitle:'VPC 기본 보안그룹에 규칙이 남아 있음',decision:'auto-executed',status:'SUCCESS',lastSeenAt:iso()}]},
 alarms:{total:5,alarm:1,insufficientData:0,noData:1,firing:[{name:'soar-sec-dev-ssh-reject',label:'SSH(22) 접속 거부 급증 (Flow Logs)',scenario:'SEC-06B'}]}});
