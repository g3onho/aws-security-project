"""공격·대응 실습(drills) — 카탈로그·이력 조회와 실행(web-scan·run-all).

조회(카탈로그·이력·상태·보고서)는 공급자 없이도 동작한다. 실행(start_web_scan·start_all)은 공급자를 통해
SSM SendCommand 로 실제 공격·부하를 일으키며, 호출하는 라우트가 WRITE_ENABLED 로 막는다.
- 실행 유형과 SEC 시나리오 카탈로그(설계 기준 정적 자료)를 제공한다.
- 각 시나리오의 실행 지원 상태는 보안-시나리오 문서의 정적 분류를 그대로 표기한다
  (runnable/prep-needed/observe-only/design-needed). 코드가 임의로 승격하지 않는다.
- 실습 실행 이력은 어댑터 경계(DrillRuns)로 읽는다. 목표 저장소는 DynamoDB이며(DEC-003)
  현재 로컬 구현은 기존 SQLite Store 를 쓴다. web-scan·run-all 실행 기록이 여기에 저장된다.
"""
import re

from .errors import Problem
from .run_report import build_run_facts

SUPPORT_STATES = {"runnable", "prep-needed", "observe-only", "design-needed"}

# 전부 실행 중복 방지. 같은 어택커/호스트에 [전부 실행]이 겹치면 자원 고갈로 SSM 에이전트까지
# 응답 불능(ConnectionLost)이 될 수 있다(2026-09-29 뭄바이·도쿄 사고 참고) — 서버에서 막는다.
# 20분(SEC-08 SendCommand 타임아웃)을 넘겨도 안 끝난 실행은 방치된 것으로 보고 새 실행을 막지 않는다.
RUN_ALL_TERMINAL = {"Success", "Cancelled", "TimedOut", "Failed"}
RUN_ALL_STALE_MS = 40 * 60 * 1000

_SEC_NUM = re.compile(r"^SEC-(\d+)([A-Z]?)")


def _sec_sort_key(sec):
    """SEC-01 < SEC-02 < ... < SEC-06A < SEC-06B < ... < SEC-10 < HONEYPOT 순으로 정렬."""
    m = _SEC_NUM.match(sec or "")
    return (int(m.group(1)), m.group(2)) if m else (99, sec or "")


# [보고서 추출] 다운로드 파일 최상위에 담는 프롬프트. 파일을 통째로 AI 에 붙여넣으면
# 이 지시만으로 리전·시나리오를 넘나드는 종합 분석 보고서가 나오도록 한다(리전별 steps 안의
# analysisPrompt 는 리전 하나만 보고 쓰는 지시라 리전 수만큼 중복되고, 리전 간·시나리오 간
# 비교는 못 한다). 2026-10-02: SEC-08 만 보던 것을 같은 실행의 나머지 시나리오(otherScenarios)
# 까지 포함하도록 넓히고, 시나리오 번호 순서대로 훑으라는 지시를 추가했다.
# 2026-10-02 추가: 사람이 이 파일을 통째로 채팅창에 붙여넣었을 때, AI 가 "이 JSON은 ~~ 구조를
# 담고 있습니다" 식으로 파일을 설명만 하고 끝내거나 추가 지시를 기다리는 경우가 있어 — 무조건
# 바로 보고서 본문으로 응답하라는 지시를 맨 앞에 못박아 둔다.
REPORT_ANALYSIS_PROMPT = (
    "이 메시지를 읽는 즉시, 파일 구조 설명이나 요약·확인 질문 없이 아래 지시에 따른 보고서 "
    "본문만 바로 작성하라. 이 JSON을 읽었다는 것 자체가 보고서 작성 요청이다 — 추가 지시를 "
    "기다리지 마라.\n\n"
    "이 JSON은 격리된 팀 소유 실습 환경에서 '전부 실행' 1회로 수행한 보안 시나리오 결과를 담고 있다. "
    "regions 는 SEC-08(여러 리전의 지리별 웹 공격: nmap 포트 스캔·hydra SSH/웹 무차별 대입·ZAP 베이스라인·"
    "sqlmap SQL 주입) 로그이고, otherScenarios 는 같은 실행에서 함께 돈 나머지 시나리오(SEC-01~SEC-10, "
    "HONEYPOT)의 요약 결과(상태·출력 끝부분)다. 파일 전체를 근거로 종합 보안 분석 보고서를 작성하라.\n"
    "(0) SEC-01 → SEC-02 → … → SEC-10 → HONEYPOT 순서로, regions 와 otherScenarios 를 합쳐 시나리오 "
    "번호 순서대로 하나도 빠짐없이 항목별로 다뤄라. 이번 실행에 없는 번호는 '이번 실행에 포함되지 않음'"
    "이라고 명시하고 건너뛰지 마라.\n"
    "(1) 시나리오별로 (a) 무엇을 시도/점검했는지 (b) 실제로 성공/발견된 것(열린 포트, 유효 자격증명, "
    "취약점, 주입 지점, WAF·NACL 차단 여부 등)만 로그 근거로 정리하라.\n"
    "(2) SEC-08 은 리전 간 공통 결과와 차이도 구분하라(예: 일부 리전만 성공/실패했다면 그 사실과, 로그에 "
    "나온 이유—연결 끊김 등—를 그대로 적고, 로그에 이유가 없으면 '원인 불명'이라고 써라. 방어가 더 강해서 "
    "실패했다고 추측하지 마라).\n"
    "(3) 도구 자체가 실행되지 않은 경우(파라미터 오류 등)와 실제 보안 결과(인증 성공/실패, 주입 성공/실패)"
    "를 명확히 구분하라 — 도구 오류를 취약점 부재의 증거로 쓰지 마라.\n"
    "(4) 항목별 위험도와 근거, (5) 권고 대응을 정리하라.\n"
    "로그에 근거가 없는 내용은 추측·과장하지 말고 '근거 없음'으로 명시하라. 출력에 없는 자격증명·취약점을 "
    "지어내지 마라."
)

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
     "sources": ["AWS Config", "Security Hub"], "response": "SG 자동 회수",
     "support": "runnable", "note": "SSH 구성 finding은 SSH 무차별 대입 탐지가 아니다. 전용 실습 SG에서 재현·즉시 회수(ASR-RevokeSecurityGroupIngress)."},
    {"id": "SEC-02", "purpose": "서비스 HTTP·보안 헤더 구성", "types": ["web-scan"],
     "sources": ["웹 응답", "curl/ZAP"], "response": "수동(Nginx 강화)",
     "support": "runnable", "note": "점검은 자동 실행(SCAN-PortAndWeb). 헤더 강화 자체는 수동. 설정 파일 존재만으로 TLS 완료로 보지 않는다."},
    {"id": "SEC-03", "purpose": "3306 노출과 자동/수동 SG 비교", "types": [],
     "sources": ["Config", "Security Hub"], "response": "SG 자동/수동",
     "support": "runnable", "note": "격리된 테스트 SG에서만. db-auto-sg(자동 회수)·db-manual-sg(알림만)에 같은 위반을 재현해 비교한다."},
    {"id": "SEC-04", "purpose": "컨테이너 이미지 CVE", "types": [],
     "sources": ["Inspector", "Trivy(S3)"], "response": "수동 교체",
     "support": "runnable", "note": "스캔은 자동 실행(SCAN-ContainerImage). 이미지 교체 자체는 수동. Trivy 결과의 화면 통합은 별도 계약."},
    {"id": "SEC-05", "purpose": "노출 자격증명·과도 권한", "types": [],
     "sources": ["GuardDuty", "Access Analyzer", "CloudTrail"], "response": "Access Key 비활성화(자동)",
     "support": "observe-only", "note": "테스트 키만 사용. 최소권한 수정은 수동."},
    {"id": "SEC-06A", "purpose": "MySQL 무차별 대입 인증 실패", "types": [],
     "sources": ["CloudWatch Logs/Alarm"], "response": "Private NACL 자동 차단(코드 존재)",
     "support": "runnable", "note": "MySQL은 CloudWatch 경로(DEC-005). 파리 내부 공격자 EC2에서 ATK-MysqlBruteForce(hydra)로 실행."},
    {"id": "SEC-06B", "purpose": "SSH 무차별 대입 시도", "types": [],
     "sources": ["GuardDuty"], "response": "수동",
     "support": "runnable", "note": "SEC-08 지리 공격 실행에 함께 들어 있다(hydra ssh). SSH는 GuardDuty 경로(DEC-005). 자동 조치 연결 없음."},
    {"id": "SEC-07", "purpose": "비밀값 노출·자격증명 분리", "types": [],
     "sources": ["코드 검토", "Secrets Manager"], "response": "수동 회전",
     "support": "runnable", "note": "스캔은 자동 실행(SCAN-Secrets). 회전 자체는 수동. 합성 테스트 비밀만 사용."},
    {"id": "SEC-08", "purpose": "DVWA 웹 공격 및 WAF 반응", "types": ["web-scan"],
     "sources": ["ZAP", "WAF 지표·로그", "Security Hub finding"], "response": "수동",
     "support": "runnable", "note": "DVWA는 별도 시험 대상(DEC-004). 5개 리전 공격자 EC2가 nmap·hydra·ZAP·sqlmap을 자동 실행."},
    {"id": "SEC-09", "purpose": "감사·구성·서비스 로그", "types": [],
     "sources": ["CloudTrail", "Config", "VPC Flow Logs", "CloudWatch Logs"], "response": "없음",
     "support": "runnable", "note": "원본 로그 보관과 finding 통합을 분리한다. CloudTrail·Config·VPC Flow Logs 수집 상태를 즉시 조회한다(조회 전용, 조치 없음)."},
    {"id": "SEC-10", "purpose": "CPU·메모리 과부하와 운영 알림", "types": ["load"],
     "sources": ["EC2 CPU", "Agent 메모리", "CloudWatch Alarm", "SNS"], "response": "없음",
     "support": "runnable", "note": "부하 실행의 대시보드 경로는 신규. 알람 임계값은 실제 설정에서 조회한다."},
    {"id": "HONEYPOT", "purpose": "내부 침투 시연과 미끼 서버 자동 차단", "types": [],
     "sources": ["허니팟 로그", "CloudWatch Alarm", "asr_trigger"], "response": "Private NACL 자동 차단",
     "support": "runnable", "note": "파리(홈 리전) VPC 안 공격자 EC2가 미끼 서버에 SSH 접속(ATK-HoneypotProbe). 경로 지도는 허니팟 페이지의 공격 경로 지도와 같은 그림을 쓴다."},
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

    def set_summary(self, run_id, line, source):
        """요약 한 줄을 그 실행 기록(payload)에 한 번만 붙인다. 이미 있으면 그대로 둔다(덮어쓰지 않음)."""
        import json
        with self.store.connect(write=True) as db:
            row = db.execute("SELECT payload FROM drills WHERE run_id=?", (run_id,)).fetchone()
            if row is None:
                return None
            payload = json.loads(row[0])
            if payload.get("summaryLine"):
                return payload
            payload["summaryLine"] = line
            payload["summarySource"] = source
            db.execute("UPDATE drills SET payload=? WHERE run_id=?", (json.dumps(payload), run_id))
            return payload

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
        # 파리(홈 리전) 서비스 호스트(docker-host) 스캔·부하 대상 리전. 웹 공격(geo)과 별개.
        self.home_region = self.attack_config.get("homeRegion") or getattr(provider, "region", None)

    def attack_ready(self):
        cfg = self.attack_config
        return bool(cfg.get("documentName") and cfg.get("targetIp") and cfg.get("regions"))

    def _active_run_all(self):
        """가장 최근 run-all 이 아직 안 끝났으면 그 run 을 돌려준다. 없거나 끝났거나
        너무 오래돼 방치된 것으로 보이면 None(새 실행 허용)."""
        from .store import now_ms
        runs = self.runs.list()  # created_at 내림차순
        latest = next((r for r in runs if r.get("type") == "run-all"), None)
        if latest is None:
            return None
        if now_ms() - latest.get("startedAt", 0) > RUN_ALL_STALE_MS:
            return None  # 방치된 실행 — 막지 않는다(2026-09-29 뭄바이·도쿄처럼 에이전트가 영영 안 돌아올 수 있음)
        commands = latest.get("commands", [])
        if not commands:
            return None
        rows = self.provider.attack_command_status(commands) or []
        if all(row.get("status") in RUN_ALL_TERMINAL for row in rows):
            return None
        return latest

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
        from .store import now_ms
        regions = _mark_stale(self.provider.attack_command_status(run.get("commands", [])) or [],
                              run.get("startedAt"), now_ms())
        return {"runId": run_id, "targetIp": run.get("targetIp"),
                "startedAt": run.get("startedAt"), "regions": regions}

    # --- 전부 실행(SEC-08/06B geo + SEC-02/07/10 파리 서비스 호스트) -----------------
    def start_all(self, params, actor):
        """[시작] 하나로 준비된 모든 실습을 실행한다. 대상이 없는 항목은 건너뛰고 사유를 남긴다.
        - SEC-08/06B: 지리별 공격자 → DVWA (nmap·hydra ssh·hydra web)
        - SEC-02: 서비스 HTTP·포트/헤더 점검(SCAN-PortAndWeb)
        - SEC-07: 코드/설정 비밀값 점검(SCAN-Secrets)
        - SEC-10: 파리 서비스 호스트 CPU·메모리 부하(LOAD-Stress) → 운영 경보 검증
        - SEC-06A: 파리(홈 리전) VPC 안 공격자 EC2 → DB EC2 MySQL 무차별 대입(ATK-MysqlBruteForce) → 탐지·자동 차단
        - SEC-01: 전용 실습 SG 에 0.0.0.0/0:22 재현 → asr_trigger 직접 호출 → 즉시 자동 회수
        - SEC-03: db-auto-sg(자동 회수) · db-manual-sg(알림만·대조군) 에 0.0.0.0/0:3306 재현 → asr_trigger 직접 호출
        - SEC-09: CloudTrail·Config·VPC Flow Logs 수집 상태 조회(쓰기 없음)
        - HONEYPOT: 파리(홈 리전) VPC 안 공격자 EC2 → 미끼서버 SSH 접속(ATK-HoneypotProbe) → 탐지·자동 차단"""
        active = self._active_run_all()
        if active:
            raise Problem(409, f"이미 실행 중인 작업이 있습니다(실행 ID: {active['runId']}). "
                          "끝난 뒤 다시 시도하세요.", "RUN_ALREADY_ACTIVE")

        cfg = self.attack_config
        p = params or {}
        launched, skipped = [], []

        # 1) 지리별 웹 공격(SEC-08 + SEC-06B). 설정/공격자 없으면 건너뛴다.
        if self.attack_ready():
            attackers = self.provider.discover_attackers(cfg["regions"]) or []
            if attackers:
                atk_params = {
                    "TargetHost": cfg["targetIp"],
                    "ScanBucket": cfg.get("scanBucket", ""),
                    "SshUser": p.get("sshUser", "victim"),
                    "WebBaseUrl": cfg.get("webUrl") or "",
                }
                targets = [{**a, "documentName": cfg["documentName"]} for a in attackers]
                for c in self.provider.run_web_attack(targets, atk_params):
                    launched.append({**c, "sec": "SEC-08"})
            else:
                skipped.append("SEC-08/06B(공격자 노드 미탐색)")
        else:
            skipped.append("SEC-08/06B(지리 공격 미설정)")

        # 2) 파리(홈 리전) 로컬 실습(SEC-02/07/10). SSM 문서가 실행 시 도구(nmap·trivy·stress-ng)를 자가 설치한다.
        region = self.home_region
        bucket = cfg.get("scanBucket", "")
        # SEC-02(서비스 헤더·포트)와 SEC-07(코드 비밀값)은 서비스와 코드(/opt/app)가 있는
        # docker-host 에서 로컬로 돈다. SSM 문서가 실행 시 nmap·trivy 를 자가 설치한다.
        svc = self.provider.discover_host_by_role(region, "service-3tier") if region else None
        if svc:
            launched.extend(self.provider.send_commands(svc, [
                {"sec": "SEC-02", "documentName": "SCAN-PortAndWeb",
                 "parameters": {"TargetHost": "127.0.0.1", "ScanBucket": bucket}},
                {"sec": "SEC-04", "documentName": "SCAN-ContainerImage",
                 "parameters": {"ServiceDir": "/opt/app", "ScanBucket": bucket}},
                {"sec": "SEC-07", "documentName": "SCAN-Secrets",
                 "parameters": {"ServiceDir": "/opt/app", "ScanBucket": bucket, "RegionLabel": "paris"}}]))
        else:
            skipped.append("SEC-02/04/07(서비스 호스트 미탐색)")

        # SEC-10: 부하. stress-ng 는 실행 노드 자신을 부하시키므로, 파리 EC2(대시보드 제외) 전부에 보낸다.
        load = {"ScanBucket": bucket}
        for k_out, k_in in (("DurationSeconds", "durationSeconds"),
                            ("CpuTarget", "cpuTarget"), ("MemPercent", "memPercent")):
            if p.get(k_in):
                load[k_out] = p[k_in]
        load_targets = self.provider.discover_load_targets(region) if region else []
        if load_targets:
            for t in load_targets:
                launched.extend(self.provider.send_commands(
                    t, [{"sec": "SEC-10", "documentName": "LOAD-Stress",
                         "parameters": {**load, "RegionLabel": t["regionLabel"]}}]))
        else:
            skipped.append("SEC-10(부하 대상 미탐색)")

        # 파리(홈 리전) VPC 안 내부 공격자 EC2(Role=attack-simulation). SEC-06A·HONEYPOT 이 함께 쓴다.
        inner = self.provider.discover_host_by_role(region, "attack-simulation") if region else None

        # SEC-06A: MySQL 무차별 대입 시연. inner 공격자 EC2 → DB EC2(Role=database, db-manual-sg 경유)
        # root 계정에 사전 단어 목록으로 로그인을 반복 시도한다(ATK-MysqlBruteForce). 전부 실패해도
        # CloudWatch 알람(mysql-bruteforce) → asr_trigger 의 Private NACL 자동 차단으로 이어진다(DEC-018).
        db = self.provider.discover_host_by_role(region, "database") if region else None
        if inner and db and db.get("privateIp"):
            launched.extend(self.provider.send_commands(inner, [
                {"sec": "SEC-06A", "documentName": "ATK-MysqlBruteForce",
                 "parameters": {"DbHost": db["privateIp"], "RegionLabel": "paris"}}]))
        else:
            skipped.append("SEC-06A(공격자 EC2 또는 DB 미탐색)")

        # SEC-01: SSH 과다 공개 SG 자동 회수 시연. 전용 실습 SG(AutoRemediation=enabled, 어디에도
        # 연결 안 됨)에 0.0.0.0/0:22 를 재현하고 asr_trigger 를 직접 호출해 즉시 회수 결과를 본다
        # (demo/trigger-auto-remediation.sh 와 같은 기법 — Security Hub 실제 평가 주기를 기다리지 않는다).
        prefix = self.provider.name_prefix
        sec01_sg = self.provider.discover_sg_by_name(region, f"{prefix}-sec01-ssh-demo-sg") if region and prefix else None
        if sec01_sg:
            launched.append(self.provider.run_sg_violation_drill(
                region, sec01_sg, 22, "SEC-01",
                "Security group allows ingress from 0.0.0.0/0 to port 22", expect_revoked=True))
        else:
            skipped.append("SEC-01(실습 SG 미배포 — enable_sec01_demo_sg)")

        # SEC-03: 3306 노출 자동/수동 비교. db-auto-sg(AutoRemediation=enabled → 자동 회수)와
        # db-manual-sg(태그 없음 → 알림만, 대조군)에 같은 위반을 넣어 결과가 갈리는 것을 보여준다.
        db_auto_sg = self.provider.discover_sg_by_name(region, f"{prefix}-db-auto-sg") if region and prefix else None
        db_manual_sg = self.provider.discover_sg_by_name(region, f"{prefix}-db-manual-sg") if region and prefix else None
        if db_auto_sg and db_manual_sg:
            launched.append(self.provider.run_sg_violation_drill(
                region, db_auto_sg, 3306, "SEC-03",
                "Security group allows ingress from 0.0.0.0/0 to port 3306",
                expect_revoked=True, region_label="auto"))
            launched.append(self.provider.run_sg_violation_drill(
                region, db_manual_sg, 3306, "SEC-03",
                "Security group allows ingress from 0.0.0.0/0 to port 3306",
                expect_revoked=False, region_label="manual"))
        else:
            skipped.append("SEC-03(db-auto-sg 또는 db-manual-sg 미탐색)")

        # SEC-09: 감사·구성·로그 수집 상태 조회. 아무것도 바꾸지 않는다 — 항상 대상이 있다(region 만 있으면 됨).
        if region:
            launched.append(self.provider.check_audit_sources(region))
        else:
            skipped.append("SEC-09(리전 미설정)")

        # HONEYPOT: 내부 침투 시연. 파리(홈 리전) VPC 안 공격자 EC2(Role=attack-simulation)가 미끼서버(Role=honeypot-decoy)
        # 사설 IP 로 SSH 접속한다. 인터넷 경유 공격(SEC-08)과 달리 "이미 안으로 들어온" 출발지라야 미끼에 닿는다.
        # 두 인스턴스 중 하나라도 없으면 건너뛴다(enable_attacker_instance·enable_honeypot).
        decoy = self.provider.discover_host_by_role(region, "honeypot-decoy") if region else None
        if inner and decoy and decoy.get("privateIp"):
            launched.extend(self.provider.send_commands(inner, [
                {"sec": "HONEYPOT", "documentName": "ATK-HoneypotProbe",
                 "parameters": {"HoneypotHost": decoy["privateIp"], "RegionLabel": "paris"}}]))
        else:
            skipped.append("HONEYPOT(공격자 EC2 또는 미끼서버 미탐색)")

        if not launched:
            raise Problem(409, "실행 가능한 대상이 없습니다: " + ", ".join(skipped) +
                          ". terraform 배포(enable_geo_attackers·docker-host)와 대시보드 env를 확인하세요.",
                          "NOTHING_LAUNCHED")

        import uuid
        from .contracts import iso
        from .store import now_ms
        secs = sorted({c["sec"] for c in launched})
        # createdAt 은 프런트 milliseconds()가 Date.parse 로 읽으므로 ms 정수가 아니라 ISO 문자열이어야 한다
        # (contracts.iso 관례). 정수를 그대로 넣으면 Date.parse(숫자)→NaN→"Invalid time value"로 갱신이 깨진다.
        run = {"runId": str(uuid.uuid4()), "type": "run-all", "title": "전부 실행",
               "actor": actor, "startedAt": now_ms(), "createdAt": iso(now_ms()),
               "targetIp": cfg.get("targetIp", ""), "secs": secs, "skipped": skipped,
               "state": "접수", "commands": launched}
        self.runs.save(run)
        return {"runId": run["runId"], "launched": launched, "skipped": skipped, "secs": secs}

    def all_status(self, run_id):
        run = self.runs.get(run_id)
        if run is None:
            raise Problem(404, "실습 실행을 찾을 수 없습니다.", "DRILL_NOT_FOUND")
        cmds = run.get("commands", [])
        rows = self.provider.attack_command_status(cmds) or []
        # attack_command_status 는 입력 순서를 보존한다 → sec/label 을 되붙인다.
        for cmd, row in zip(cmds, rows):
            row["sec"] = cmd.get("sec")
            row["label"] = _step_label(cmd)
        from .store import now_ms
        _mark_stale(rows, run.get("startedAt"), now_ms())
        return {"runId": run_id, "startedAt": run.get("startedAt"),
                "targetIp": run.get("targetIp"), "skipped": run.get("skipped", []), "items": rows}

    def report(self, run_id):
        """SEC-08(공격) 로그를 리전별로 읽어와 하나로 합친 JSON + 같은 실행의 나머지 시나리오
        (SEC-01~10·HONEYPOT) 요약. '보안 시나리오' 페이지 [보고서 추출]이 부른다 — 프런트가 이
        응답을 그대로 파일 하나로 내려받게 한다. 리전별 steps 안에도 analysisPrompt 가 하나씩
        들어 있지만(리전 수만큼 중복), 파일 전체를 한 번에 AI 에 넣었을 때 리전·시나리오를
        넘나들며 종합하도록 최상위에도 별도 프롬프트를 담는다(2026-10-02: otherScenarios 추가).
        otherScenarios 는 시나리오 번호 순서(SEC-01→…→SEC-10→HONEYPOT)로 정렬해서 담는다 —
        AI 가 번호를 빼먹거나 뒤섞어 쓰지 않도록 순서 자체를 데이터로도 보장한다."""
        run = self.runs.get(run_id)
        if run is None:
            raise Problem(404, "실습 실행을 찾을 수 없습니다.", "DRILL_NOT_FOUND")
        atk_cmds = [c for c in run.get("commands", []) if c.get("sec") == "SEC-08"]
        bucket = self.attack_config.get("scanBucket", "")
        regions = self.provider.merged_report(atk_cmds, bucket) if atk_cmds else {}

        status = self.all_status(run_id)
        facts = build_run_facts(run, status, None)
        other = [
            {**row, "sec": item.get("sec") or "?"}
            for row, item in zip(facts.get("항목별 결과") or [], status.get("items") or [])
            if item.get("sec") != "SEC-08"
        ]
        other.sort(key=lambda r: _sec_sort_key(r["sec"]))

        return {"runId": run_id, "analysisPrompt": REPORT_ANALYSIS_PROMPT, "regions": regions,
                "otherScenarios": other}

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
            "activeRun": self._active_run_summary(),
        }

    def _active_run_summary(self):
        """아직 끝나지 않은 [전부 실행]이 있으면 {runId, startedAt}, 없으면 None.
        다른 서버에서 시작한 실행도 공유 이력으로 보이므로, 화면이 시작 버튼을 미리 잠그는 데 쓴다.
        조회가 실패하면 None 으로 두되(화면 보조 정보일 뿐) 시작 API(start_all)가 같은 검사로 409 를 돌려 막는다."""
        if not self.provider.status().get("connected"):
            return None
        try:
            active = self._active_run_all()
        except Exception:
            return None
        if not active:
            return None
        return {"runId": active.get("runId"), "startedAt": active.get("startedAt")}

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


def _mark_stale(rows, started_at, now):
    """에이전트가 죽으면 SSM invocation 이 InProgress 에서 영영 안 바뀐다(2026-09-29 뭄바이·도쿄).
    SendCommand 의 TimeoutSeconds 는 에이전트에 배달되기 전까지만 적용되므로, 일단 실행에 들어간
    뒤 에이전트가 끊기면 AWS 가 상태를 끝내주지 않는다. _active_run_all 과 같은 기준
    (RUN_ALL_STALE_MS)으로 화면 표기만 끊는다 — 실제 명령을 취소하지는 않는다."""
    if not started_at or now - started_at <= RUN_ALL_STALE_MS:
        return rows
    for row in rows:
        if row.get("status") not in RUN_ALL_TERMINAL:
            row["staleFrom"] = row.get("status")
            row["status"] = "TimedOut"
            row["detail"] = "40분 초과 · SSM 에이전트 무응답(표기상 종료)"
    return rows


def _label(support):
    return {"runnable": "실행 가능", "prep-needed": "준비 필요",
            "observe-only": "조회 전용", "design-needed": "설계 필요"}.get(support, support)


_REGION_KO = {"paris": "파리", "tokyo": "도쿄", "singapore": "싱가포르",
              "sydney": "시드니", "mumbai": "뭄바이", "us-virginia": "미국(버지니아)"}


def _step_label(cmd):
    """진행·이력 표기는 리전이 아니라 SEC 항목을 앞세운다(예: 'SEC-10 · docker-host', 'SEC-08 · 도쿄')."""
    sec = cmd.get("sec") or "실행"
    region = cmd.get("regionLabel")
    if sec == "SEC-08" and region and region != "paris":
        return f"{sec} · {_REGION_KO.get(region, region)}"  # geo: 출발 지역
    if sec == "HONEYPOT":
        return "HONEYPOT · 내부 침투"  # 출발은 파리(홈 리전) VPC 안 공격자 EC2
    if sec == "SEC-10" and region:
        return f"{sec} · {_REGION_KO.get(region, region)}"  # 부하: 대상 EC2 이름
    if sec == "SEC-03" and region in ("auto", "manual"):
        return f"{sec} · {region}"  # db-auto-sg(자동) vs db-manual-sg(대조군) 구분
    return sec
