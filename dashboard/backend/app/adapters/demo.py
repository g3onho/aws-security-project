"""데모 어댑터 — static/js/data.js 생성기의 파이썬 포팅.

**이 파일은 data.js 와 이벤트 단위로 동일한 결과를 내야 한다.**
backend/tests/test_demo_parity.py 가 Node 로 data.js 를 실행해 바이트 단위로 대조한다.
data.js 를 고치면 이 파일도 같이 고치고, 대조 테스트를 다시 돌린다.

포팅 대상
  data.js:1        DEMO_NOW
  data.js:2-21     regions (17 + global)
  data.js:27-68    threatActors (8)
  data.js:72-81    scenarios (8)
  data.js:82-98    createEvents()
  data.js:99-104   metricsFor()

응답은 data.js 의 국문 값이 아니라 **API enum 모양**으로 내보낸다
(02-frontend-redesign.md §2.5). 국문 변환은 프론트 어댑터와 CSV 내보내기가 한다.
"""
from __future__ import annotations

import math
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

from ..catalog import loader
from .. import enums

# data.js:1 — Date.parse('2026-09-18T15:00:00+09:00')
DEMO_NOW = int(
    datetime(2026, 9, 18, 15, 0, 0, tzinfo=timezone(timedelta(hours=9))).timestamp() * 1000
)

# data.js:2-21
REGIONS = [
    {"id": "ap-northeast-2", "name": "서울", "en": "SEOUL", "lon": 126.978, "lat": 37.566, "resource": "i-seoul-app-01"},
    {"id": "ap-northeast-1", "name": "도쿄", "en": "TOKYO", "lon": 139.69, "lat": 35.68, "resource": "i-tokyo-app-01"},
    {"id": "ap-southeast-1", "name": "싱가포르", "en": "SINGAPORE", "lon": 103.82, "lat": 1.35, "resource": "i-singapore-app-01"},
    {"id": "eu-central-1", "name": "프랑크푸르트", "en": "FRANKFURT", "lon": 8.68, "lat": 50.11, "resource": "i-frankfurt-app-01"},
    {"id": "us-east-1", "name": "버지니아 북부", "en": "VIRGINIA", "lon": -77.49, "lat": 38.75, "resource": "i-virginia-app-01"},
    {"id": "global", "name": "글로벌 / 위치 미상", "en": "GLOBAL", "lon": None, "lat": None, "resource": None},
    {"id": "us-east-2", "name": "오하이오", "en": "OHIO", "lon": -82.99, "lat": 39.96, "resource": "i-us-east-2-app-01"},
    {"id": "us-west-1", "name": "캘리포니아", "en": "CALIFORNIA", "lon": -121.89, "lat": 37.34, "resource": "i-us-west-1-app-01"},
    {"id": "us-west-2", "name": "오리건", "en": "OREGON", "lon": -122.68, "lat": 45.52, "resource": "i-us-west-2-app-01"},
    {"id": "ap-south-1", "name": "뭄바이", "en": "MUMBAI", "lon": 72.88, "lat": 19.08, "resource": "i-ap-south-1-app-01"},
    {"id": "ap-northeast-3", "name": "오사카", "en": "OSAKA", "lon": 135.5, "lat": 34.69, "resource": "i-ap-northeast-3-app-01"},
    {"id": "ap-southeast-2", "name": "시드니", "en": "SYDNEY", "lon": 151.21, "lat": -33.87, "resource": "i-ap-southeast-2-app-01"},
    {"id": "ca-central-1", "name": "캐나다 중부", "en": "CANADA", "lon": -73.57, "lat": 45.5, "resource": "i-ca-central-1-app-01"},
    {"id": "eu-west-1", "name": "아일랜드", "en": "IRELAND", "lon": -6.26, "lat": 53.35, "resource": "i-eu-west-1-app-01"},
    {"id": "eu-west-2", "name": "런던", "en": "LONDON", "lon": -0.13, "lat": 51.51, "resource": "i-eu-west-2-app-01"},
    {"id": "eu-west-3", "name": "파리", "en": "PARIS", "lon": 2.35, "lat": 48.86, "resource": "i-eu-west-3-app-01"},
    {"id": "eu-north-1", "name": "스톡홀름", "en": "STOCKHOLM", "lon": 18.07, "lat": 59.33, "resource": "i-eu-north-1-app-01"},
    {"id": "sa-east-1", "name": "상파울루", "en": "SAO PAULO", "lon": -46.63, "lat": -23.55, "resource": "i-sa-east-1-app-01"},
]

# data.js:27-68 — 지도·상세 패널 표기용. 공개 위협 인텔리전스를 참고한 **교육용 데모**이며
# 개별 이벤트에 대한 실제 귀속(attribution)이 아니다. GuardDuty 는 IP 의 지리 좌표는 주지만
# 위협 그룹 귀속은 주지 않으므로, 실모드에서도 이 배열은 데모 전용으로 남는다.
THREAT_ACTORS = [
    {"id": "north-korea", "country": "North Korea", "city": "평양", "ip": "203.0.113.45", "lon": 125.75, "lat": 39.02},
    {"id": "china", "country": "China", "city": "베이징", "ip": "198.51.100.77", "lon": 116.41, "lat": 39.90},
    {"id": "russia", "country": "Russia", "city": "모스크바", "ip": "192.0.2.88", "lon": 37.62, "lat": 55.75},
    {"id": "iran", "country": "Iran", "city": "테헤란", "ip": "203.0.113.201", "lon": 51.39, "lat": 35.69},
    {"id": "vietnam", "country": "Vietnam", "city": "하노이", "ip": "198.51.100.132", "lon": 105.85, "lat": 21.03},
    {"id": "pakistan", "country": "Pakistan", "city": "이슬라마바드", "ip": "192.0.2.164", "lon": 73.06, "lat": 33.72},
    {"id": "india", "country": "India", "city": "뉴델리", "ip": "203.0.113.93", "lon": 77.21, "lat": 28.61},
    {"id": "turkey", "country": "Turkey", "city": "앙카라", "ip": "198.51.100.210", "lon": 32.85, "lat": 39.93},
]

# data.js:72-81
SCENARIOS = [
    {"scenario": "SEC-01", "title": "SSH 포트 외부 공개", "source": "Config", "severity": "High",
     "criterion": "0.0.0.0/0에 대한 TCP 22 인바운드 규칙 수", "before": 1, "after": 0, "unit": "개",
     "evidence": "sg-web-01의 TCP 22 인바운드가 0.0.0.0/0에 공개되어 있습니다.",
     "recommendation": "해당 공개 규칙을 회수하고 SSM 연결 상태를 확인합니다.", "mode": "자동"},
    {"scenario": "SEC-02", "title": "HTTP 보안 헤더 누락", "source": "Security Hub", "severity": "Medium",
     "criterion": "필수 보안 헤더 누락 수 (동일 URL / 동일 헤더 집합)", "before": 3, "after": 0, "unit": "개",
     "evidence": "GET / 응답에 X-Content-Type-Options 등 필수 헤더 3개가 없습니다. 데모 검사 결과를 정규화한 항목입니다.",
     "recommendation": "Nginx 응답 헤더 설정을 적용한 뒤 같은 URL을 재검사합니다.", "mode": "자동"},
    {"scenario": "SEC-03", "title": "MySQL 3306 포트 과다 공개", "source": "Config", "severity": "Critical",
     "criterion": "0.0.0.0/0에 대한 TCP 3306 인바운드 규칙 수", "before": 1, "after": 0, "unit": "개",
     "evidence": "sg-db-manual의 TCP 3306 인바운드가 외부 전체 주소를 허용합니다.",
     "recommendation": "DB 인바운드를 애플리케이션 보안 그룹으로 제한합니다.", "mode": "수동"},
    {"scenario": "SEC-04", "title": "컨테이너 이미지 취약점", "source": "Trivy", "severity": "High",
     "criterion": "동일 대상의 미해결 CVE 수 (전체 심각도)", "before": 12, "after": 2, "unit": "개",
     "evidence": "app:1.2 이미지에서 취약점 12개가 발견되었습니다. 동일 대상·동일 검사 기준으로 비교합니다.",
     "recommendation": "수정된 app:1.3 이미지로 교체하고 동일 기준으로 재검사합니다.", "mode": "수동"},
    {"scenario": "DETECT-01", "title": "외부 IP의 비정상 접근 탐지", "source": "GuardDuty", "severity": "Critical",
     "criterion": "동일 10분 관찰 구간의 비정상 접근 수", "before": 8, "after": 0, "unit": "건",
     "evidence": "외부 출발 IP에서 대상 EC2로 반복적인 비정상 접근이 탐지되었습니다. IP·좌표는 시연용이며 실제 공격자 위치가 아닙니다.",
     "recommendation": "출발 IP와 접근 근거를 검토한 뒤 승인된 접근 차단을 수행하고 재관찰합니다.", "mode": "수동"},
    {"scenario": "NMS-01", "title": "EC2 CPU 사용률 80% 초과", "source": "CloudWatch", "severity": "Medium",
     "criterion": "동일 5분 평균 CPU 사용률", "before": 86, "after": 58, "unit": "%",
     "evidence": "5분 평균 CPU 사용률 86%가 임계치 80%를 초과했습니다.",
     "recommendation": "부하 프로세스를 확인하고 조정 후 5분 평균을 재확인합니다.", "mode": "수동"},
    {"scenario": "SEC-04", "title": "패키지 취약점 업데이트 필요", "source": "Inspector", "severity": "Low",
     "criterion": "동일 패키지 집합의 미해결 취약점 수", "before": 4, "after": 0, "unit": "개",
     "evidence": "인스턴스 패키지 점검에서 업데이트가 필요한 항목 4개를 발견했습니다.",
     "recommendation": "승인된 패키지를 업데이트하고 동일 패키지 집합을 점검합니다.", "mode": "수동"},
    {"scenario": "NMS-02", "title": "EC2 메모리 사용률 80% 초과", "source": "CloudWatch", "severity": "High",
     "criterion": "동일 5분 평균 메모리 사용률", "before": 84, "after": 63, "unit": "%",
     "evidence": "CloudWatch Agent의 메모리 사용률 평균이 84%입니다.",
     "recommendation": "메모리 사용 프로세스를 확인하고 조정 후 재점검합니다.", "mode": "수동"},
]

GLOBAL_SCENARIO = {
    "scenario": "IAM-01", "title": "글로벌 IAM 역할 신뢰 정책 검토", "source": "Security Hub", "severity": "High",
    "criterion": "승인되지 않은 외부 계정 신뢰 항목 수", "before": 1, "after": 0, "unit": "개",
    "evidence": "글로벌 IAM 역할의 신뢰 정책에 검토가 필요한 외부 계정 항목이 있습니다. 지리 좌표가 없는 데모 탐지입니다.",
    "recommendation": "신뢰 관계의 업무 필요성을 검토하고 승인되지 않은 계정 항목을 제거합니다.", "mode": "수동",
}

# data.js:86
AGES = [.12, .3, .55, .8, 1.2, 2, 3, 4, 5, 7, 9, 11, 13, 15, 17, 20, 23, 30, 40, 50, 65, 80, 110, 145]



def _measure(value, unit, at):
    if value is None:
        return {"value": None, "unit": unit, "label": "검사 대기", "at": at}
    return {"value": value, "unit": unit, "label": f"{value}{unit}", "at": at}


def _build_events() -> list[dict]:
    """data.js:82-98 createEvents() 의 1:1 포팅."""
    out: list[dict] = []
    for ri, r in enumerate(REGIONS):
        length = 24 if ri == 0 else (5 if ri == 5 else 12)
        for i in range(length):
            has_coords = r["lon"] is not None
            force_attack = has_coords and i < 2
            if force_attack:
                s = next(x for x in SCENARIOS if x["scenario"] == "DETECT-01")
            elif ri == 5:
                s = GLOBAL_SCENARIO
            else:
                s = SCENARIOS[(i + ri) % len(SCENARIOS)]

            at = DEMO_NOW - int(AGES[i] * 3600000)

            if i % 7 == 6:
                status_ko = "해결"
            elif i % 7 == 5:
                status_ko = "재검증 실패"
            elif s["mode"] == "자동":
                status_ko = "신규"
            else:
                status_ko = "승인 대기"

            if ri == 5:
                resource = "arn:aws:iam::demo:role/shared"
            elif s["scenario"] == "SEC-03":
                resource = f"sg-{r['id']}-db"
            elif s["source"] == "Trivy":
                resource = f"ecr/{r['id']}/app:1.2"
            else:
                resource = r["resource"]

            is_attack = s["source"] == "GuardDuty"
            origin = THREAT_ACTORS[(ri + i) % len(THREAT_ACTORS)]
            if has_coords and math.hypot(r["lon"] - origin["lon"], r["lat"] - origin["lat"]) < 3:
                origin = THREAT_ACTORS[(ri + i + 1) % len(THREAT_ACTORS)]

            source_ip = ("10.0.0.8" if i >= 20 else origin["ip"]) if is_attack else None
            source_location = None
            if is_attack and i < 12:
                source_location = {
                    "city": origin["city"], "lon": origin["lon"], "lat": origin["lat"],
                    "provenance": "모의 위치 · IP 실제 조회 아님",
                    "actorId": origin["id"], "country": origin["country"],
                }

            if not is_attack:
                geo_status = "해당 없음"
            elif source_location:
                geo_status = "모의 위치"
            elif i >= 20:
                geo_status = "사설 IP · 위치 미상"
            else:
                geo_status = "위치 미상"

            resolved_or_failed = status_ko in ("해결", "재검증 실패")
            after_at = at + 180000 if resolved_or_failed else None
            if status_ko == "해결":
                after_value = s["after"] if s["unit"] == "%" else 0
            elif status_ko == "재검증 실패":
                after_value = s["before"] if s["unit"] == "%" else (s["after"] or 1)
            else:
                after_value = None

            history = [{"at": at, "text": "탐지 근거 수집", "actor": None, "decision": None}]
            if resolved_or_failed:
                history.append({"at": at + 60000, "text": "데모 조치 실행 성공",
                                "actor": "demo", "decision": "auto-executed"})
                history.append({
                    "at": at + 180000,
                    "text": "재검증 통과" if status_ko == "해결" else "재검증 실패 · 미해결 항목 존재",
                    "actor": "demo", "decision": "verified",
                })

            scenario_id = s["scenario"]
            out.append({
                "id": f"EVT-{ri * 100 + i + 1:04d}",
                "scenario": scenario_id,
                "title": s["title"],
                "severity": enums.DISPLAY_TO_SEVERITY[s["severity"]],
                "source": s["source"],
                "mode": enums.KO_TO_MODE[s["mode"]],
                "region": r["id"],
                "environment": "staging" if i % 6 == 5 else "production",
                "resource": resource,
                "at": at,
                "status": enums.KO_TO_STATUS[status_ko],
                "execution": "SUCCEEDED" if resolved_or_failed else "NOT_RUN",
                "verification": ("PASSED" if status_ko == "해결"
                                 else "FAILED" if status_ko == "재검증 실패" else "NOT_RUN"),
                "criterion": s["criterion"],
                "unit": s["unit"],
                "before": _measure(s["before"], s["unit"], at),
                "after": _measure(after_value, s["unit"], after_at),
                "beforeAt": at,
                "afterAt": after_at,
                "afterValue": after_value,
                "evidence": s["evidence"],
                "recommendation": s["recommendation"],
                "sourceIp": source_ip,
                "sourceLocation": source_location,
                "geoStatus": geo_status,
                "history": history,
                "playbook": loader.playbook(scenario_id),
                "cveIds": [],
                "severityBumped": False,
                "approver": None,
                "approvedAt": None,
                # 알림은 대시보드가 보내지 않는다 — CloudWatch 알람의 alarm_actions 와
                # asr_trigger 의 sns.publish 가 보낸다. 화면은 "갔는지"만 표시한다.
                # 실모드는 remediation_actions 의 manual-notified 행에서 온다.
                "notification": _demo_notification(s, status_ko, at),
            })
    return out


def _demo_notification(scenario: dict, status_ko: str, at: int):
    """데모용 알림 이력.

    수동 대응 이벤트가 '승인 대기'에 있다는 것은 asr_trigger 가 게이트 불충족으로 판정하고
    SNS 를 발행한 결과다. 그 사실만 표시한다 — 없는 발송 기록을 만들지 않는다.
    """
    if scenario["source"] == "CloudWatch":
        return {"at": at, "channel": "SNS", "source": "cloudwatch-alarm",
                "reason": scenario["title"], "count": 1}
    if scenario["mode"] == "수동" and status_ko == "승인 대기":
        return {"at": at, "channel": "SNS", "source": "asr_trigger",
                "reason": "자동조치 게이트 불충족 (데모 데이터)", "count": 1}
    return None


# ── 데모 텔레메트리 ────────────────────────────────────────
# v3 (보완설계 §2.1): 곡선 인덱스를 **포인트의 절대 시각**으로 잡는다.
# 이전 구현은 `floor(endOffset) % 12` 였다. 그래서
#   - 1시간 구간: 12개 표본의 offset 이 0.0~1.0 이라 floor 가 전부 0 → 직선
#   - 7일 구간: offset 이 15.3시간씩 뛰면서 12로 감싸 → 실제 시각과 무관한 톱니
# 였다. 지금은 KST 하루를 12구간으로 보고 선형 보간하므로, 어떤 기간을 골라도
# 같은 시각에는 같은 값이 나오고 구간을 좁히면 해상도만 올라간다.
CPU_CURVE = [58, 61, 64, 68, 73, 81, 86, 65, 57, 44, 47, 42]
MEM_CURVE = [63, 65, 66, 71, 76, 84, 68, 63, 59, 55, 54, 51]

KST_OFFSET_MS = 9 * 3600000
SLOT_MS = 86400000 // 12          # 하루 12구간 = 2시간
# CloudWatch 가 실제로 쓰는 period 후보. 화면 표본은 121개를 넘기지 않는다.
SAMPLE_PERIODS = [60, 300, 900, 1800, 3600, 10800, 21600]
MAX_POINTS = 120
THRESHOLD = {"cpu": 80, "memory": 80}

# 서울(ap-northeast-2)은 실제 구축 리전이라 Terraform 의 EC2 5대를 그대로 둔다.
# 나머지 리전은 지도 표기용이므로 대표 인스턴스 1대만 둔다.
HOSTS = {
    "ap-northeast-2": [
        {"id": "i-seoul-app-01", "name": "docker-host", "role": "3-Tier 컨테이너 호스트",
         "type": "t3.small", "tier": "app", "seed": 0},
        {"id": "i-seoul-db-01", "name": "db", "role": "MySQL EC2 (탐지·조치 대상)",
         "type": "t3.small", "tier": "db", "seed": 3},
        {"id": "i-seoul-web-01", "name": "web-dvwa", "role": "DVWA 웹서버",
         "type": "t3.micro", "tier": "web", "seed": 2},
        {"id": "i-seoul-dash-01", "name": "dashboard", "role": "보안 대시보드",
         "type": "t3.micro", "tier": "ops", "seed": 1},
        {"id": "i-seoul-atk-01", "name": "attacker", "role": "공격 시연용 (기본 off)",
         "type": "t3.micro", "tier": "ops", "seed": 4},
    ],
}


def hosts_for(region_id: str) -> list[dict]:
    """리전의 EC2 목록. data.js `hostsFor()` 와 같은 결과여야 한다."""
    if region_id in HOSTS:
        return [dict(h, region=region_id) for h in HOSTS[region_id]]
    region = next((r for r in REGIONS if r["id"] == region_id), None)
    if not region or not region.get("resource"):
        return []
    return [{"id": region["resource"], "name": "app", "role": "애플리케이션 EC2",
             "type": "t3.micro", "tier": "app", "seed": REGIONS.index(region) % 5,
             "region": region_id}]


def _round1(value: float) -> float:
    # JS 와 같은 반올림. Python 의 round() 는 은행가 반올림이라 쓰지 않는다.
    return math.floor(value * 10 + 0.5) / 10


def _curve_value(curve: list[int], at_ms: int) -> float:
    x = ((at_ms + KST_OFFSET_MS) % 86400000) / float(SLOT_MS)
    i = int(x) % 12
    j = (i + 1) % 12
    return curve[i] + (curve[j] - curve[i]) * (x - int(x))


def _jitter(at_ms: int, salt: int) -> float:
    """시각에서 결정되는 0~1 의사난수. JS 와 같은 정수 연산만 쓴다."""
    n = ((at_ms // 1000) + salt) % 100003
    return ((n * 48271) % 2147483647) / 2147483647.0


def _sample(curve: list[int], at_ms: int, seed: int, env_delta: int, salt: int) -> float:
    base = _curve_value(curve, at_ms) + seed + env_delta
    value = base + (_jitter(at_ms, salt) * 2 - 1) * 2.5
    return _round1(max(1.0, min(99.0, value)))


def period_seconds(range_ms: int) -> int:
    for period in SAMPLE_PERIODS:
        if range_ms / 1000.0 / period <= MAX_POINTS:
            return period
    return SAMPLE_PERIODS[-1]


def breaches_of(points: list[dict], threshold: dict) -> list[dict]:
    """임계치를 연속으로 넘은 구간. 화면 음영과 '초과 N회' 요약의 근거다."""
    out = []
    for metric in ("cpu", "memory"):
        limit = threshold[metric]
        run = None
        for point in points:
            value = point.get(metric)
            if value is not None and value > limit:
                if run is None:
                    run = {"metric": metric, "from": point["at"], "to": point["at"],
                           "peak": value, "samples": 1}
                else:
                    run["to"] = point["at"]
                    run["peak"] = max(run["peak"], value)
                    run["samples"] += 1
            elif run is not None:
                out.append(run)
                run = None
        if run is not None:
            out.append(run)
    out.sort(key=lambda r: (r["from"], r["metric"]))
    return out


def _stats(points: list[dict], metric: str) -> dict:
    values = [p[metric] for p in points if p.get(metric) is not None]
    if not values:
        return {"max": None, "avg": None, "last": None}
    return {"max": max(values), "avg": _round1(sum(values) / len(values)), "last": values[-1]}


def metrics_all_for(region_id: str, hours: float, end_offset: float = 0.0,
                    environment: str = "production") -> list[dict]:
    """리전의 **모든 호스트** 시계열. metrics_for 를 호스트 수만큼 돌린 것뿐이라
    data.js 와의 대조는 metrics_for 하나로 충분하다."""
    return [metrics_for(region_id, hours, end_offset, environment, host["id"])
            for host in hosts_for(region_id)]


def metrics_for(region_id: str, hours: float, end_offset: float = 0.0,
                environment: str = "production", resource: str | None = None) -> dict:
    """data.js `metricsFor()` 의 포팅. 두 구현이 같은 값을 내야 한다
    (tests/test_demo_parity.py)."""
    hosts = hosts_for(region_id)
    if not hosts:
        return {"resource": None, "host": None, "at": None, "cpu": None, "memory": None,
                "threshold": dict(THRESHOLD), "period": None, "points": [], "breaches": [],
                "summary": None, "window": None,
                "note": "선택한 리전에 EC2 데모 지표가 없습니다."}

    host = next((h for h in hosts if h["id"] == resource), hosts[0])
    env_delta = -12 if environment == "staging" else 0

    to = int(math.floor(DEMO_NOW - end_offset * 3600000 + 0.5))
    frm = int(math.floor(to - hours * 3600000 + 0.5))
    period = period_seconds(to - frm)
    step = period * 1000
    count = max(2, min(MAX_POINTS + 1, (to - frm) // step + 1))

    points = []
    for k in range(count):
        at = to - (count - 1 - k) * step
        points.append({
            "at": at,
            "cpu": _sample(CPU_CURVE, at, host["seed"] * 2, env_delta, 11),
            "memory": _sample(MEM_CURVE, at, host["seed"], env_delta, 29),
        })

    head = points[-1]
    return {
        "resource": host["id"],
        "host": {k: host[k] for k in ("id", "name", "role", "type", "tier", "region")},
        "hosts": [{k: h[k] for k in ("id", "name", "role", "type", "tier")} for h in hosts],
        "at": head["at"],
        "cpu": head["cpu"],
        "memory": head["memory"],
        "threshold": dict(THRESHOLD),
        "period": period,
        "points": points,
        "breaches": breaches_of(points, THRESHOLD),
        "summary": {"cpu": _stats(points, "cpu"), "memory": _stats(points, "memory"),
                    "samples": len(points)},
        "window": {"from": points[0]["at"], "to": to},
        "note": None,
    }


class DemoAdapter:
    """고정 데이터 + 메모리 상태 전이.

    실제 AWS 호출이 없다. 상태 전이는 store.js:12-13 의 가드와 같은 규칙을 쓰되,
    승인 단계는 서버 리소스로 승격되어 있다(04 §3.1).
    """

    mode = "demo"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events = {e["id"]: e for e in _build_events()}
        self._executions: dict[str, dict] = {}
        self._idempotency: dict[str, str] = {}

    # ── 조회 ────────────────────────────────────────────
    def list_events(self, q: dict) -> dict:
        from ..services.filters import apply_filters, paginate
        rows = apply_filters(list(self._events.values()), q)
        return paginate(rows, q)

    def get_event(self, event_id: str):
        return self._events.get(event_id)

    def metrics(self, q: dict) -> dict:
        # 15분 구간을 보려면 하한이 1시간이면 안 된다. 0.05시간(3분)까지 허용한다.
        hours = max(0.05, (q["to"] - q["from"]) / 3600000)
        end_offset = max(0.0, (DEMO_NOW - q["to"]) / 3600000)
        region = q.get("region") or "ap-northeast-2"
        if region == "all":
            region = "ap-northeast-2"
        environment = q.get("environment") or "production"
        data = metrics_for(region, hours, end_offset, environment, q.get("resource") or None)
        if q.get("scope") == "all":
            # 인프라 화면이 운영 중인 서버를 한 번에 본다. 호출을 1회로 묶는다.
            data["series"] = [
                {k: series[k] for k in ("resource", "host", "cpu", "memory", "period",
                                        "points", "breaches", "summary", "threshold")}
                for series in metrics_all_for(region, hours, end_offset, environment)
            ]
        return data

    def resources(self, q: dict) -> dict:
        """리전별 EC2 목록. 인프라 화면의 호스트 선택기가 쓴다."""
        region = q.get("region") or "all"
        regions = [region] if region not in ("all", "") else [r["id"] for r in REGIONS]
        items = []
        for rid in regions:
            for host in hosts_for(rid):
                items.append({"id": host["id"], "region": rid, "mode": "demo",
                              "name": host["name"], "role": host["role"],
                              "type": host["type"], "tier": host["tier"]})
        return {"items": items}

    def nacls(self, q: dict) -> dict:
        """데모 NACL. 화면에서 차단 폼을 보여주기 위한 표시용이다.
        계획 설정(prepare_plan)은 실모드 전용이라 데모에서는 제출이 막힌다."""
        return {"items": [{
            "id": "acl-demo-private", "vpcId": "vpc-demo", "name": "soar-sec-dev-private-nacl",
            "isDefault": False, "subnets": ["subnet-demo-app", "subnet-demo-db"],
            "usedDenyRuleNumbers": [1, 2], "suggestedRuleNumber": 3, "mode": "demo",
        }], "denyRuleRange": [1, 99]}

    def services(self, q: dict) -> dict:
        """3계층(Nginx→Flask→MySQL) 상태. 데모에서도 실제 값이 흐르게 한다."""
        from ..services.tiers import build_services
        from ..services.filters import apply_filters
        region = q.get("region") or "ap-northeast-2"
        if region == "all":
            region = "ap-northeast-2"
        metrics = self.metrics({**q, "region": region})
        events = apply_filters(list(self._events.values()), {**q, "region": region})
        return build_services(region, q["to"], metrics, events, self.mode)

    def vulnerabilities(self, q: dict) -> dict:
        from ..services.vulns import build_vulnerabilities
        region = q.get("region") or "ap-northeast-2"
        if region == "all":
            region = "ap-northeast-2"
        return build_vulnerabilities(list(self._events.values()), q, DEMO_NOW, region)

    def scenarios(self, q: dict) -> dict:
        from ..services.scenarios import build_coverage
        return build_coverage(list(self._events.values()), q)

    def incidents(self, q: dict) -> dict:
        from ..services.incidents import build_incidents
        return build_incidents(list(self._events.values()), q)

    def evidence(self, event_id: str):
        from ..services.evidence import build_evidence
        event = self._events.get(event_id)
        if not event:
            return None
        return build_evidence(event, ssm_execution_ids=[
            x["executionId"] for x in self._executions.values() if x["eventId"] == event_id
        ])

    # ── 쓰기 ────────────────────────────────────────────
    def approve(self, event_id: str, body: dict, actor: str, key: str) -> dict:
        with self._lock:
            event = self._require(event_id)
            self._check_expected(event, body)
            replay = self._idempotency.get(key)
            if replay:
                return self._events[replay]
            event["approver"] = actor
            event["approvedAt"] = _now_ms()
            event["history"].append({"at": _now_ms(), "text": f"승인 ({actor})",
                                     "actor": actor, "decision": "approved"})
            if event["status"] == "PENDING_APPROVAL":
                event["status"] = "NEW"
            self._idempotency[key] = event_id
            return event

    def execute(self, event_id: str, body: dict, actor: str, key: str) -> dict:
        with self._lock:
            event = self._require(event_id)
            self._check_expected(event, body)
            replay = self._idempotency.get(key)
            if replay and replay in self._executions:
                return {"execution": self._executions[replay], "event": event}

            from ..config import Config
            from ..services.gates import evaluate
            decision = evaluate(event, dry_run=bool(body.get("dry_run")))
            if not decision.allowed and Config.ENFORCE_GATES:
                from ..api.errors import ApiProblem
                raise ApiProblem(422, decision.title, code=decision.code, detail=decision.detail)

            execution_id = f"demo-exec-{uuid.uuid4().hex[:12]}"
            execution = {
                "executionId": execution_id,
                "eventId": event_id,
                "kind": "REMEDIATION",
                "document": event.get("playbook"),
                "status": "RUNNING",
                "startedAt": _now_ms(),
                "endedAt": None,
                "progress": {"step": "실행 요청", "completed": 0, "total": 3},
                "failureMessage": None,
            }
            self._executions[execution_id] = execution
            self._idempotency[key] = execution_id

            event["status"] = "EXECUTING"
            event["execution"] = "RUNNING"
            event["verification"] = "NOT_RUN"
            event["afterValue"] = None
            event["afterAt"] = None
            event["after"] = _measure(None, event["unit"], None)
            event["history"].append({"at": _now_ms(), "text": "데모 조치 실행 시작",
                                     "actor": actor, "decision": "auto-executed"})

            _schedule(0.65, lambda: self._finish_execution(execution_id))
            return {"execution": execution, "event": event}

    def execution_status(self, event_id: str, execution_id: str):
        execution = self._executions.get(execution_id)
        if not execution or execution["eventId"] != event_id:
            return None
        return {"execution": execution, "event": self._events.get(event_id)}

    def verify(self, event_id: str, body: dict, actor: str, key: str) -> dict:
        with self._lock:
            event = self._require(event_id)
            self._check_expected(event, body)
            replay = self._idempotency.get(key)
            if replay and replay in self._executions:
                return {"execution": self._executions[replay], "event": event}

            execution_id = f"demo-verify-{uuid.uuid4().hex[:12]}"
            execution = {
                "executionId": execution_id,
                "eventId": event_id,
                "kind": "VERIFICATION",
                "document": None,
                "status": "RUNNING",
                "startedAt": _now_ms(),
                "endedAt": None,
                "progress": {"step": "동일 기준 재검사", "completed": 0, "total": 1},
                "failureMessage": None,
            }
            self._executions[execution_id] = execution
            self._idempotency[key] = execution_id

            event["status"] = "VERIFYING"
            event["verification"] = "CHECKING"
            _schedule(0.65, lambda: self._finish_verification(execution_id))
            return {"execution": execution, "event": event}

    # ── 내부 ────────────────────────────────────────────
    def _require(self, event_id: str) -> dict:
        from ..api.errors import ApiProblem
        event = self._events.get(event_id)
        if not event:
            raise ApiProblem(404, "이벤트를 찾을 수 없습니다.", code="EVENT_NOT_FOUND")
        return event

    def _check_expected(self, event: dict, body: dict) -> None:
        from ..api.errors import ApiProblem
        expected = body.get("expected_status")
        if expected and expected != event["status"]:
            raise ApiProblem(
                409, "현재 상태에서는 실행할 수 없습니다.", code="STATE_CONFLICT",
                detail=(f"서버 상태는 '{enums.status_ko(event['status'])}' 이고 "
                        f"요청의 expected_status 는 '{enums.status_ko(expected)}' 입니다."),
            )

    def _finish_execution(self, execution_id: str) -> None:
        with self._lock:
            execution = self._executions[execution_id]
            event = self._events[execution["eventId"]]
            execution.update(status="SUCCEEDED", endedAt=_now_ms(),
                             progress={"step": "완료", "completed": 3, "total": 3})
            event["execution"] = "SUCCEEDED"
            event["status"] = "PENDING_VERIFICATION"
            event["history"].append({"at": _now_ms(), "text": "데모 조치 실행 성공 · 재검증 필요",
                                     "actor": None, "decision": None})

    def _finish_verification(self, execution_id: str) -> None:
        with self._lock:
            execution = self._executions[execution_id]
            event = self._events[execution["eventId"]]
            # 데모 규칙: Trivy 항목은 잔존 취약점이 남아 재검증 실패
            # (store.js:13 의 하드코딩과 동일. 실모드 verifier 에는 이 분기가 없다.)
            failed = event["source"] == "Trivy"
            unit = event["unit"]
            after_value = (event["before"]["value"] if failed and unit == "%"
                           else 2 if failed
                           else _scenario_after(event) if unit == "%" else 0)
            now = _now_ms()
            event["afterValue"] = after_value
            event["afterAt"] = now
            event["after"] = _measure(after_value, unit, now)
            event["verification"] = "FAILED" if failed else "PASSED"
            event["status"] = "VERIFICATION_FAILED" if failed else "RESOLVED"
            execution.update(status="SUCCEEDED", endedAt=now,
                             progress={"step": "완료", "completed": 1, "total": 1})
            event["history"].append({
                "at": now,
                "text": f"동일 기준 재검증 {enums.verification_ko(event['verification'])}",
                "actor": None, "decision": "verified",
            })

    def health_checks(self) -> dict:
        return {"catalog": "ok", "demo_events": "ok"}


def _scenario_after(event: dict):
    for s in SCENARIOS + [GLOBAL_SCENARIO]:
        if s["scenario"] == event["scenario"] and s["title"] == event["title"]:
            return s["after"]
    return 0


def _now_ms() -> int:
    return int(time.time() * 1000)


def _schedule(delay: float, fn) -> None:
    timer = threading.Timer(delay, fn)
    timer.daemon = True
    timer.start()
