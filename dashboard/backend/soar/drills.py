"""공격·대응 실습(drills) 조회 계약 — 1차(관측·구조) 범위.

이 모듈은 조회 전용이다. 실제 공격·부하 실행, SSM 호출, 대상 변경은 하지 않는다.
- 실행 유형과 SEC 시나리오 카탈로그(설계 기준 정적 자료)를 제공한다.
- 각 시나리오의 실행 지원 상태는 보안-시나리오 문서의 정적 분류를 그대로 표기한다
  (runnable/prep-needed/observe-only/design-needed). 코드가 임의로 승격하지 않는다.
- 실습 실행 이력은 어댑터 경계(DrillRuns)로 읽는다. 목표 저장소는 DynamoDB이며(DEC-003)
  현재 로컬 구현은 기존 SQLite Store 를 쓴다. 실행 경로가 없으므로 이력은 아직 비어 있다.
"""
from .errors import Problem

SUPPORT_STATES = {"runnable", "prep-needed", "observe-only", "design-needed"}

# 실행 유형(도구 단위). CPU·메모리 상승 자체는 침해가 아니라 부하 시험으로 표기한다.
DRILL_TYPES = [
    {"id": "web-scan", "name": "웹 보안 검사", "tool": "ZAP",
     "kind": "attack", "sources": ["ZAP 결과", "웹 응답", "WAF 지표·로그", "Security Hub finding"],
     "variants": [
         {"id": "web-dvwa", "name": "DVWA 웹 공격 검사", "note": "SEC-08 · 별도 시험 대상"},
         {"id": "web-service", "name": "서비스 웹 보안 설정 검사", "note": "SEC-02 · 헤더·TLS"},
     ],
     "note": "검사 실행 성공은 공격 성공이나 침해 확정이 아니다. HTTP 403만으로 WAF 차단을 단정하지 않는다."},
    {"id": "sec-scenario", "name": "보안 시나리오", "tool": "SEC",
     "kind": "scenario", "sources": ["시나리오별 관측 원천"],
     "note": "시나리오는 웹 보안 검사나 부하 시험을 단계로 포함할 수 있다."},
    {"id": "load", "name": "부하 시험", "tool": "stress",
     "kind": "load", "sources": ["부하 작업 상태", "실제 CPU·메모리 사용률", "CloudWatch 알람", "SNS 전달·회복"],
     "variants": [
         {"id": "cpu-load", "name": "CPU 부하 시험", "note": "EC2 CPU 기본 지표"},
         {"id": "memory-load", "name": "메모리 부하 시험", "note": "Agent 커스텀 지표 · 실행 전 연결 확인"},
     ],
     "note": "부하로 인한 CPU·메모리 상승을 실제 침해로 표기하지 않는다. 메모리 지표 결측을 0%로 표기하지 않는다."},
]

# SEC 시나리오 카탈로그. support 는 보안-시나리오 문서의 정적 분류다(실행 가능 여부의 승인이 아님).
SCENARIOS = [
    {"id": "SEC-01", "purpose": "과도하게 공개된 SSH 보안 그룹 구성", "types": [],
     "sources": ["AWS Config", "Security Hub"], "response": "SG 자동 회수(코드 존재)",
     "support": "observe-only", "note": "SSH 구성 finding은 SSH 무차별 대입 탐지가 아니다."},
    {"id": "SEC-02", "purpose": "서비스 HTTP·보안 헤더 구성", "types": ["web-scan"],
     "sources": ["웹 응답", "curl/ZAP"], "response": "수동(Nginx 강화)",
     "support": "prep-needed", "note": "수동 변경·검증. 설정 파일 존재만으로 TLS 완료로 보지 않는다."},
    {"id": "SEC-03", "purpose": "3306 노출과 자동/수동 SG 비교", "types": [],
     "sources": ["Config", "Security Hub"], "response": "SG 자동/수동",
     "support": "observe-only", "note": "격리된 테스트 SG에서만. 하나의 SG 조치로 전체 차단을 단정하지 않는다."},
    {"id": "SEC-04", "purpose": "컨테이너 이미지 CVE", "types": [],
     "sources": ["Inspector", "Trivy(S3)"], "response": "수동 교체",
     "support": "prep-needed", "note": "Trivy 결과의 화면 통합은 별도 계약."},
    {"id": "SEC-05", "purpose": "노출 자격증명·과도 권한", "types": [],
     "sources": ["GuardDuty", "Access Analyzer", "CloudTrail"], "response": "Access Key 비활성화(자동)",
     "support": "observe-only", "note": "테스트 키만 사용. 최소권한 수정은 수동."},
    {"id": "SEC-06A", "purpose": "MySQL 무차별 대입 인증 실패", "types": [],
     "sources": ["CloudWatch Logs/Alarm"], "response": "수동",
     "support": "prep-needed", "note": "MySQL은 CloudWatch 경로(DEC-005). 외부 Hydra 도구 연결 필요."},
    {"id": "SEC-06B", "purpose": "SSH 무차별 대입 시도", "types": [],
     "sources": ["GuardDuty"], "response": "수동",
     "support": "prep-needed", "note": "SSH는 GuardDuty 경로(DEC-005). 자동 조치 연결 없음."},
    {"id": "SEC-07", "purpose": "비밀값 노출·자격증명 분리", "types": [],
     "sources": ["코드 검토", "Secrets Manager"], "response": "수동 회전",
     "support": "prep-needed", "note": "합성 테스트 비밀만 사용."},
    {"id": "SEC-08", "purpose": "DVWA 웹 공격 및 WAF 반응", "types": ["web-scan"],
     "sources": ["ZAP", "WAF 지표·로그", "Security Hub finding"], "response": "수동",
     "support": "prep-needed", "note": "DVWA는 별도 시험 대상(DEC-004). ZAP 실행 경로는 신규."},
    {"id": "SEC-09", "purpose": "감사·구성·서비스 로그", "types": [],
     "sources": ["CloudTrail", "Config", "VPC Flow Logs", "CloudWatch Logs"], "response": "없음",
     "support": "observe-only", "note": "원본 로그 보관과 finding 통합을 분리한다."},
    {"id": "SEC-10", "purpose": "CPU·메모리 과부하와 운영 알림", "types": ["load"],
     "sources": ["EC2 CPU", "Agent 메모리", "CloudWatch Alarm", "SNS"], "response": "없음",
     "support": "prep-needed", "note": "부하 실행의 대시보드 경로는 신규. 알람 임계값은 실제 설정에서 조회한다."},
]


class DrillRuns:
    """실습 실행 이력의 읽기 어댑터 경계.

    목표 저장소는 DynamoDB(DEC-003). 로컬/테스트는 기존 SQLite Store 의 drills 테이블을 쓴다.
    1차 범위에는 실행 경로가 없으므로 쓰기 메서드를 두지 않는다(이력은 비어 있음).
    """

    def __init__(self, store):
        self.store = store

    def list(self):
        with self.store.connect() as db:
            rows = db.execute("SELECT payload FROM drills ORDER BY created_at DESC, run_id").fetchall()
        import json
        return [json.loads(row[0]) for row in rows]

    def get(self, run_id):
        with self.store.connect() as db:
            row = db.execute("SELECT payload FROM drills WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            return None
        import json
        return json.loads(row[0])

    def save(self, run):
        import json
        from .store import now_ms
        with self.store.connect(write=True) as db:
            db.execute("INSERT INTO drills (run_id, payload, created_at) VALUES (?,?,?)",
                       (run["runId"], json.dumps(run), now_ms()))


class DrillService:
    """실습 서비스. 조회 + 지리별 웹보안검사 실행(SSM). 실행은 라우트에서 WRITE_ENABLED 로 막는다.

    attack_config(선택): {documentName, targetIp, scanBucket, regions:[리전코드…]}
    공격자 인스턴스는 실행 시점에 각 리전에서 태그로 탐색한다. 미배포면 409.
    """

    def __init__(self, store, provider, attack_config=None):
        self.runs = DrillRuns(store)
        self.provider = provider
        self.attack_config = attack_config or {}

    def attack_ready(self):
        cfg = self.attack_config
        return bool(cfg.get("documentName") and cfg.get("targetIp") and cfg.get("regions"))

    def start_web_scan(self, params, actor):
        cfg = self.attack_config
        if not self.attack_ready():
            raise Problem(409, "지리별 공격 설정이 없습니다. terraform enable_geo_attackers 를 켜고 대시보드 env를 확인하세요.",
                          "GEO_ATTACKERS_NOT_CONFIGURED")
        attackers = self.provider.discover_attackers(cfg["regions"]) or []
        if not attackers:
            raise Problem(409, "실행 중인 공격자 노드를 찾지 못했습니다(태그 AttackerFor=dvwa). 배포·부팅을 확인하세요.",
                          "GEO_ATTACKERS_NOT_FOUND")

        parameters = {
            "TargetHost": cfg["targetIp"],
            "ScanBucket": cfg.get("scanBucket", ""),
            "SshUser": (params or {}).get("sshUser", "victim"),
            # 웹 공격 대상은 ALB(WAF 경유). 스크립트가 이 URL 로 자동 로그인해 세션을 얻는다.
            "WebBaseUrl": cfg.get("webUrl") or "",
        }
        targets = [{**a, "documentName": cfg["documentName"]} for a in attackers]
        launched = self.provider.run_web_attack(targets, parameters)

        import uuid
        from .store import now_ms
        run = {"runId": str(uuid.uuid4()), "type": "web-scan", "variant": "web-dvwa",
               "actor": actor, "startedAt": now_ms(), "targetIp": cfg["targetIp"],
               "commands": launched}
        self.runs.save(run)
        return {"runId": run["runId"], "launched": launched}

    def web_scan_status(self, run_id):
        run = self.runs.get(run_id)
        if run is None:
            raise Problem(404, "실습 실행을 찾을 수 없습니다.", "DRILL_NOT_FOUND")
        regions = self.provider.attack_command_status(run.get("commands", []))
        return {"runId": run_id, "targetIp": run.get("targetIp"),
                "startedAt": run.get("startedAt"), "regions": regions}

    def environment(self):
        status = self.provider.status()
        # 데이터 연결 상태는 하나로 합치지 않는다. 격리 VPC는 여기서 증명할 수 없으므로 unknown.
        return {
            "dataSourceConnected": bool(status.get("connected")),
            "providerState": status.get("state"),
            "region": status.get("region"),
            "isolationVerified": "unknown",
            "executionMode": "live",
            "webScanReady": self.attack_ready(),
        }

    def catalog(self):
        connected = bool(self.provider.status().get("connected"))
        scenarios = []
        for scenario in SCENARIOS:
            # 관측 원천이 AWS 공급자에 달린 시나리오는 공급자 미연결 시 관측 불가를 표시(0건으로 위장 금지).
            observation = "connected" if connected else "disconnected"
            scenarios.append({**scenario, "supportLabel": _label(scenario["support"]),
                              "observation": observation})
        return {"types": DRILL_TYPES, "scenarios": scenarios,
                "environment": self.environment(),
                "supportLegend": {key: _label(key) for key in sorted(SUPPORT_STATES)}}

    def run_list(self):
        return {"items": self.runs.list(), "nextCursor": None}

    def run_detail(self, run_id):
        run = self.runs.get(run_id)
        if run is None:
            raise Problem(404, "실습 실행을 찾을 수 없습니다.", "DRILL_NOT_FOUND")
        return run


def _label(support):
    return {"runnable": "실행 가능", "prep-needed": "준비 필요",
            "observe-only": "조회 전용", "design-needed": "설계 필요"}.get(support, support)
