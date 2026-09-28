"""Configuration is read per app creation, never cached at module import."""
import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def boolean(value, name):
    if isinstance(value, bool):
        return value
    if str(value).lower() in {"true", "1", "yes", "on"}:
        return True
    if str(value).lower() in {"false", "0", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true or false")


def configure(overrides=None):
    instance = Path(os.getenv("DASHBOARD_INSTANCE", ROOT / "instance")).resolve()
    config = {
        "DATABASE": str(instance / "dashboard.sqlite3"),
        "FRONTEND_PATH": str(ROOT.parent / "frontend"),
        "DATA_PROVIDER": os.getenv("DATA_PROVIDER", "none").lower(),
        "AWS_REGION": os.getenv("AWS_REGION", "ap-northeast-2"),
        # Terraform modules/soar 의 DynamoDB 테이블(dashboard.sh.tftpl 이 env 로 넣는다). 없으면 해당 기능은 경고로 표시.
        "REMEDIATION_ACTIONS_TABLE": os.getenv("REMEDIATION_ACTIONS_TABLE") or None,
        "CORRELATED_FINDINGS_TABLE": os.getenv("CORRELATED_FINDINGS_TABLE") or None,
        # 탐지·취약점 적재 테이블(v21, modules/soar finding_sync)과 읽을 곳. 기본값은 AWS 직접 조회.
        "FINDINGS_TABLE": os.getenv("FINDINGS_TABLE") or None,
        "VULNERABILITIES_TABLE": os.getenv("VULNERABILITIES_TABLE") or None,
        "EVENT_SOURCE": os.getenv("EVENT_SOURCE", "securityhub").lower(),
        "VULNERABILITY_SOURCE": os.getenv("VULNERABILITY_SOURCE", "inspector").lower(),
        # Terraform name_prefix. CloudWatch 알람 이름 접두어·메모리 지표 네임스페이스. 없으면 경보 상태를 읽지 않는다.
        "NAME_PREFIX": os.getenv("NAME_PREFIX") or None,
        # asr_trigger 와 같은 자동 조치 설정(dashboard.sh.tftpl). 탐지 상세의 "자동 조치 여부" 예상에 쓴다.
        # 셋 중 하나라도 없으면 예상하지 않고 '확인 불가'로 표시한다.
        "AUTO_REMEDIABLE_PATTERNS": os.getenv("AUTO_REMEDIABLE_PATTERNS"),
        "AUTO_REMEDIABLE_CONTROLS": os.getenv("AUTO_REMEDIABLE_CONTROLS"),
        "ENABLE_AUTO_REMEDIATION": os.getenv("ENABLE_AUTO_REMEDIATION"),
        # 지리별 공격 실행(웹보안검사 [시작]). terraform 이 dashboard.sh 로 주입.
        # 공격자 인스턴스는 런타임에 태그(AttackerFor=dvwa)로 각 리전에서 탐색한다(순환참조 회피).
        "ATTACK_REGIONS": os.getenv("ATTACK_REGIONS") or None,  # "us-east-1,ap-southeast-1,..."
        "ATTACK_DOCUMENT_NAME": os.getenv("ATTACK_DOCUMENT_NAME") or None,
        "DVWA_TARGET_IP": os.getenv("DVWA_TARGET_IP") or None,
        "SCAN_RESULTS_BUCKET": os.getenv("SCAN_RESULTS_BUCKET") or None,
        "HOST": os.getenv("DASHBOARD_HOST", "127.0.0.1"),
        "PORT": int(os.getenv("DASHBOARD_PORT", "5051")),
        "WRITE_ENABLED": os.getenv("WRITE_ENABLED", "false"),
        "SECRET_KEY": os.getenv("FLASK_SECRET_KEY"),
        "TESTING": False,
        "SESSION_COOKIE_NAME": "soar_session",
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Strict",
        "SESSION_COOKIE_SECURE": os.getenv("SESSION_COOKIE_SECURE", "false"),
        "PERMANENT_SESSION_LIFETIME": 3600,
        "MAX_CONTENT_LENGTH": 65536,
        "WORKER_LEASE_SECONDS": 30,
        "APPROVAL_TTL_SECONDS": 900,
        "VERSION": "0.1.0",
    }
    config.update(overrides or {})
    if config["DATA_PROVIDER"] not in {"none", "aws"}:
        raise ValueError("DATA_PROVIDER must be none or aws")
    if config["EVENT_SOURCE"] not in {"securityhub", "dynamodb"}:
        raise ValueError("EVENT_SOURCE must be securityhub or dynamodb")
    if config["VULNERABILITY_SOURCE"] not in {"inspector", "dynamodb"}:
        raise ValueError("VULNERABILITY_SOURCE must be inspector or dynamodb")
    # 테이블 없이 dynamodb 를 고르면 조용히 빈 목록이 되지 않게 기동 단계에서 멈춘다.
    if config["EVENT_SOURCE"] == "dynamodb" and not config["FINDINGS_TABLE"]:
        raise ValueError("EVENT_SOURCE=dynamodb requires FINDINGS_TABLE")
    if config["VULNERABILITY_SOURCE"] == "dynamodb" and not config["VULNERABILITIES_TABLE"]:
        raise ValueError("VULNERABILITY_SOURCE=dynamodb requires VULNERABILITIES_TABLE")
    config["WRITE_ENABLED"] = boolean(config["WRITE_ENABLED"], "WRITE_ENABLED")
    config["SESSION_COOKIE_SECURE"] = boolean(config["SESSION_COOKIE_SECURE"], "SESSION_COOKIE_SECURE")
    if not 1 <= config["PORT"] <= 65535:
        raise ValueError("DASHBOARD_PORT must be between 1 and 65535")
    database = Path(config["DATABASE"]).resolve()
    database.parent.mkdir(parents=True, exist_ok=True)
    config["DATABASE"] = str(database)
    if not config["SECRET_KEY"]:
        key_file = database.parent / "session.key"
        try:
            descriptor = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(secrets.token_hex(32))
        config["SECRET_KEY"] = key_file.read_text(encoding="utf-8").strip()
        if not config["SECRET_KEY"]:
            raise ValueError("Empty session.key; stop other server processes and restore the key")
    return config
