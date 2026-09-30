// 위험도·상태·탐지 소스 배지.
import {severityColors,severityText} from '../constants.js?v=v43';
import {esc} from './format.js?v=v43';
// severityBumped: correlator 가 "위협+CVE 동시 존재"로 한 단계 올린 건. 올렸다는 사실이
// 화면에 없으면 자동 모니터링 2번이 동작한 증거가 남지 않는다.
export function badge(e){const c=severityColors[e.severity]||'#4f5b58',t=severityText[e.severity]||'#3f4e46';return `<span class="badge sev-pill" style="color:${t};background:${c}33;border-color:${c}"><i style="background:${c}"></i>${e.severity}</span>`+(e.severityBumped?` <span class="badge bumped" title="GuardDuty 위협과 Inspector CVE가 같은 자원에 있어 심각도를 한 단계 올렸습니다">↑상향</span>`:'');}
export function statusBadge(status){return `<span class="status-badge" style="color:${status==='해결'?'#0b7f72':status==='재검증 실패'?'#c62f3c':status==='승인 대기'?'#a88a0d':status==='탐지됨'?'#365263':'#3f4e46'}">${esc(status)}</span>`;}
export const SOURCE_COLOR={GuardDuty:'#c4691c','Security Hub':'#365263',Config:'#a88a0d',WAF:'#d63a44',Inspector:'#365346'};
export function sourceTag(source){const c=SOURCE_COLOR[source]||'#4f5b58';return `<span class="source-tag" style="color:${c};background:${c}1a;border-color:${c}">${esc(source)}</span>`;}
