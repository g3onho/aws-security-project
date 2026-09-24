// 위험도·상태·탐지 소스 배지.
import {severityColors} from '../constants.js?v=ui-1';
import {esc} from './format.js?v=ui-1';
// severityBumped: correlator 가 "위협+CVE 동시 존재"로 한 단계 올린 건. 올렸다는 사실이
// 화면에 없으면 자동 모니터링 2번이 동작한 증거가 남지 않는다.
export function badge(e){const c=severityColors[e.severity]||'#9baaa6';return `<span class="badge sev-pill" style="color:${c};background:${c}1f;border-color:${c}55"><i style="background:${c}"></i>${e.severity}</span>`+(e.severityBumped?` <span class="badge bumped" title="GuardDuty 위협과 Inspector CVE가 같은 자원에 있어 심각도를 한 단계 올렸습니다">↑상향</span>`:'');}
export function statusBadge(status){return `<span class="status-badge" style="color:${status==='해결'?'#32d4be':status==='재검증 실패'?'#ef777f':status==='승인 대기'?'#d8ca78':status==='탐지됨'?'#8fb3c9':'#a9bcb1'}">${esc(status)}</span>`;}
export const SOURCE_COLOR={GuardDuty:'#e7a064','Security Hub':'#8fb3c9',Config:'#d8ca78',WAF:'#ef777f',Inspector:'#a3c7b7'};
export function sourceTag(source){const c=SOURCE_COLOR[source]||'#9baaa6';return `<span class="source-tag" style="color:${c};border-color:${c}55">${esc(source)}</span>`;}
