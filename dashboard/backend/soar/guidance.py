"""탐지 설명·AWS 조치 안내·자동 조치 판정(설정 기준 예상).

- 설명(explain): guidance_catalog 의 팀 설명. AWS 원문과 따로 싣는다.
- AWS 조치 안내(remediation): finding 의 Remediation.Recommendation. 규칙 탐지는 AWS 가 문구 대신 링크만 주는
  경우가 많아, 링크가 없으면 규칙 ID 로 공식 조치 문서 주소를 만든다.
- 자동 조치 판정(AutoPolicy): terraform/modules/soar 의 EventBridge 규칙(eventbridge.tf ②·③)과
  asr_trigger/handler.py 판정 순서를 그대로 옮긴 "설정 기준 예상"이다. 실제로 무엇을 했는지는 조치 이력
  (DynamoDB remediation-actions)이 기준이다. Lambda 규칙을 바꾸면 여기도 함께 바꾼다.
"""
import re

from . import guidance_catalog as catalog

CONTROL_TAIL = re.compile(r"([A-Za-z0-9]+\.\d+)$")
SECURITY_HUB_CONTROL = re.compile(r"^[A-Z][A-Za-z0-9]*\.\d+$")
REMEDIATION_URL = "https://docs.aws.amazon.com/console/securityhub/{}/remediation"
# ASFF Types 끝의 GuardDuty 유형. Security Hub 는 "UnauthorizedAccess:EC2/SSHBruteForce" 의 "/" 를 "-" 로 바꿔 넣는다.
GUARDDUTY_TYPE = re.compile(r"([A-Z][A-Za-z]+):([A-Za-z0-9]+)[-/]([^/]+)$")

# asr_trigger CONTROL_PLAYBOOKS 와 같은 목록. 문서 이름 = modules/soar/ssm.tf automation_docs 키.
CONTROL_PLAYBOOKS = {
    "EC2.2": ("ASR-RemoveDefaultSgRules", "기본 보안그룹 규칙 제거"),
    "EC2.7": ("ASR-EnableEbsDefaultEncryption", "EBS 기본 암호화 켜기"),
    "EC2.182": ("ASR-BlockEbsSnapshotPublicAccess", "EBS 스냅샷 공개 차단"),
    "S3.1": ("ASR-BlockS3AccountPublicAccess", "S3 계정 퍼블릭 액세스 차단"),
    "IAM.7": ("ASR-SetIamPasswordPolicy", "IAM 비밀번호 정책 강화"),
    "SSM.6": ("ASR-EnableSsmAutomationLogging", "SSM Automation 로그 켜기"),
    "SSM.7": ("ASR-BlockSsmDocumentPublicSharing", "SSM 문서 공개 공유 차단"),
}
SG_PLAYBOOK = ("ASR-RevokeSecurityGroupIngress", "보안그룹 전체 공개 규칙 회수")
KEY_PLAYBOOK = ("ASR-DisableExposedAccessKey", "노출 의심 액세스 키 비활성화")
# eventbridge.tf ② — asr_trigger 로 가는 GuardDuty 유형(앞부분 일치).
GUARDDUTY_ROUTED = ("UnauthorizedAccess:IAMUser", "CredentialAccess:IAMUser", "Discovery:IAMUser")
CONFIG_RULES = ("restricted-common-ports", "restricted-ssh", "iam-no-full-admin", "cloudtrail-enabled")

MODE_LABELS = {"auto": "자동 조치", "conditional": "조건부 자동", "dry-run": "판단만(dry-run)",
               "manual": "수동 대응", "none": "자동 조치 경로 없음", "unknown": "확인 불가"}
BASIS = "현재 설정으로 본 예상입니다. 실제 판정은 조치 이력에 남은 기록이 기준입니다."


def _norm(text):
    return re.sub(r"[^a-z0-9]", "", str(text or "").lower())


_GUARDDUTY_INDEX = {_norm(key): key for key in catalog.GUARDDUTY}


def control_id(finding):
    """Security Hub 규칙 ID(EC2.2 등). asr_trigger._control_id 와 같은 순서:
    Compliance.SecurityControlId → ProductFields.ControlId → GeneratorId 끝(security-control/EC2.2)."""
    control = ((finding.get("Compliance") or {}).get("SecurityControlId")
               or (finding.get("ProductFields") or {}).get("ControlId"))
    if control:
        return str(control)
    match = CONTROL_TAIL.search(str(finding.get("GeneratorId") or ""))
    return match.group(1) if match else None


def guardduty_type(finding):
    """GuardDuty 유형을 원래 형식(ThreatPurpose:Resource/Name)으로. GuardDuty finding 이 아니면 None."""
    if finding.get("ProductName") != "GuardDuty":
        return None
    for entry in finding.get("Types") or []:
        match = GUARDDUTY_TYPE.search(str(entry))
        if match:
            return f"{match.group(1)}:{match.group(2)}/{match.group(3)}"
    return None


def _entry(key, entry, kind):
    if not entry:
        return None
    return {"key": key, "kind": kind, "title": entry["title"], "problem": entry["problem"], "risk": entry["risk"],
            "fix": list(entry["fix"]), "where": catalog.WHERE.get(entry["where"]), "whereKey": entry["where"],
            "scenario": entry.get("scenario"), "note": entry.get("note")}


def explain(finding, control=None, gd_type=None):
    """팀 설명. 표에 없으면 None(화면은 AWS 원문만 보여준다)."""
    product = finding.get("ProductName") or "Security Hub"
    if finding.get("GeneratorId") == "soar-waf-alarm":
        return _entry("waf:soar-waf-alarm", catalog.OTHERS["waf:soar-waf-alarm"], "waf")
    if control and control in catalog.CONTROLS:
        return _entry(control, catalog.CONTROLS[control], "control")
    if gd_type:
        key = _GUARDDUTY_INDEX.get(_norm(gd_type))
        if key:
            return _entry(key, catalog.GUARDDUTY[key], "guardduty")
        family = gd_type.split(":", 1)[0]
        return _entry("family:" + family, catalog.family_entry(family), "guardduty-family")
    if product == "Config":
        name = " ".join([str((finding.get("ProductFields") or {}).get("aws/config/ConfigRuleName") or ""),
                         str(finding.get("Title") or "")]).lower()
        for rule in CONFIG_RULES:
            if rule in name:
                return _entry("config:" + rule, catalog.OTHERS["config:" + rule], "config")
    key = "product:" + product
    return _entry(key, catalog.OTHERS.get(key), "product")


def _https(url):
    return url if isinstance(url, str) and url.startswith("https://") else None


def remediation(finding, control=None):
    """AWS 원문 조치 안내 {text, url}. 둘 다 없으면 None. 링크는 https 만(화면이 그대로 연다)."""
    recommendation = (finding.get("Remediation") or {}).get("Recommendation") or {}
    text = (recommendation.get("Text") or "")[:500] or None
    url = _https(recommendation.get("Url")) or _https((finding.get("ProductFields") or {}).get("RecommendationUrl"))
    if not url and control and SECURITY_HUB_CONTROL.match(control) \
            and (finding.get("ProductName") or "Security Hub") == "Security Hub":
        url = REMEDIATION_URL.format(control)
    return {"text": text, "url": url} if text or url else None


def control_title(control, finding_type=None):
    """조치 이력 제목용 한글 이름. 규칙 ID(EC2.2 등)·SEC-06A·SEC-06B, 없으면 GuardDuty 유형(직접 이벤트 기록은
    finding_type 에 유형 원문이 들어 있다). 모르면 None."""
    entry = catalog.CONTROLS.get(control) if control else None
    if entry:
        return entry["title"]
    if control and control in catalog.BRUTEFORCE:
        return catalog.BRUTEFORCE[control]
    key = _GUARDDUTY_INDEX.get(_norm(finding_type)) if finding_type else None
    return catalog.GUARDDUTY[key]["title"] if key else None


def _result(mode, reason, playbook=None, condition=None):
    doc, action = playbook or (None, None)
    return {"mode": mode, "label": MODE_LABELS[mode], "playbookId": doc, "action": action,
            "condition": condition, "reason": reason, "basis": BASIS}


def _split(value):
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [part.strip() for part in str(value).split(",") if part.strip()]


class AutoPolicy:
    """asr_trigger 판정 미러. 세 설정 중 하나라도 없으면(로컬 실행 등) 판정하지 않고 unknown 을 돌려준다
    — 설정을 모르는데 '수동'이라고 보여주지 않는다."""

    def __init__(self, patterns=None, controls=None, enabled=None):
        self.configured = patterns is not None and controls is not None and enabled is not None
        self.patterns = _split(patterns) or []
        self.controls = set(_split(controls) or [])
        self.enabled = str(enabled).lower() == "true" if not isinstance(enabled, bool) else enabled

    @classmethod
    def from_settings(cls, settings):
        return cls(settings.get("AUTO_REMEDIABLE_PATTERNS"), settings.get("AUTO_REMEDIABLE_CONTROLS"),
                   settings.get("ENABLE_AUTO_REMEDIATION"))

    def _whitelisted(self, text):
        return any(re.search(re.escape(p), text, re.IGNORECASE) for p in self.patterns)

    def evaluate(self, finding, control=None, gd_type=None):
        if not self.configured:
            return _result("unknown", "대시보드가 자동 조치 설정(AUTO_REMEDIABLE_*·ENABLE_AUTO_REMEDIATION)을 받지 못했습니다.")
        if finding.get("ProductName") == "GuardDuty":
            return self._guardduty(finding, gd_type)
        if finding.get("GeneratorId") == "soar-waf-alarm":
            return _result("none", "WAF 가 요청을 이미 차단했습니다. 이 탐지는 차단 급증을 알리는 기록입니다.")
        status = (finding.get("Compliance") or {}).get("Status")
        if status not in ("FAILED", "WARNING") or finding.get("RecordState") == "ARCHIVED":
            return _result("none", "설정 점검 실패(Compliance FAILED·WARNING) finding 만 자동 조치 판단으로 보냅니다. "
                                   "이 탐지는 기록·알림만 합니다.")
        return self._security_hub(finding, control)

    def _security_hub(self, finding, control):
        types = finding.get("Types") or []
        generator = str(finding.get("GeneratorId") or "")
        first_type = str(types[0]) if types else generator
        finding_type = str(finding["Title"]) if "Title" in finding else first_type
        match_text = " ".join([str(finding.get("Title") or ""), first_type, generator])
        if control and control in self.controls and control in CONTROL_PLAYBOOKS:
            if not self.enabled:
                return _result("dry-run", f"{control} 는 자동 조치 대상이지만 전체 dry-run(ENABLE_AUTO_REMEDIATION=false) — 판단만 기록합니다.",
                               CONTROL_PLAYBOOKS[control])
            reason = f"규칙 ID {control} 가 자동 조치 목록(DEC-017)에 있습니다. 재부팅 없는 설정 변경입니다."
            if control == "EC2.2":
                # Lambda 는 보안그룹 자원이 없거나 프로젝트 VPC 밖이면 수동으로 돌린다. 대시보드는 VPC 를 모르므로 조건부.
                if not any(r.get("Type") == "AwsEc2SecurityGroup" and r.get("Id") for r in finding.get("Resources") or []):
                    return _result("manual", "EC2.2 자동 조치 대상이지만 대상 보안그룹 ID 가 없어 수동 알림합니다.")
                return _result("conditional", reason, CONTROL_PLAYBOOKS[control],
                               "프로젝트 VPC 의 기본 보안그룹일 때만 (계정 기본 VPC 등 다른 VPC 는 수동 알림)")
            return _result("auto", reason, CONTROL_PLAYBOOKS[control])
        if not self._whitelisted(match_text):
            return _result("manual", "자동 조치 목록·화이트리스트 밖 — 담당자에게 알림(SNS)만 보냅니다.")
        if not self.enabled:
            return _result("dry-run", "화이트리스트에 있지만 전체 dry-run(ENABLE_AUTO_REMEDIATION=false) — 판단만 기록합니다.")
        kind = (finding_type + " " + generator).lower()
        if any(word in kind for word in ("port", "sg", "ssh", "ingress")) or "3306" in match_text:
            has_group = any(r.get("Type") == "AwsEc2SecurityGroup" and r.get("Id") for r in finding.get("Resources") or [])
            if not has_group:
                return _result("manual", "화이트리스트에 있지만 대상 보안그룹 ID 가 없어 수동 알림합니다.")
            return _result("conditional", "화이트리스트 일치(보안그룹 공개 규칙).", SG_PLAYBOOK,
                           "보안그룹에 AutoRemediation=enabled 태그가 있을 때만 회수 (태그 없으면 대조군 → 수동 알림)")
        if "credential" in kind or "unauthorizedaccess" in kind:
            return _result("manual", "화이트리스트에 있지만 Security Hub 경로는 액세스 키 ID 를 받지 않아 수동 알림합니다.")
        return _result("manual", "화이트리스트에는 있으나 처리기가 없어 수동 알림합니다.")

    def _guardduty(self, finding, gd_type):
        if not gd_type or not gd_type.startswith(GUARDDUTY_ROUTED):
            return _result("none", "이 GuardDuty 유형은 자동 조치 판단으로 보내지 않습니다(IAM 자격 증명 계열만). 탐지·알림만 합니다.")
        if not self._whitelisted(gd_type):
            return _result("manual", "자동 조치 화이트리스트 밖 — 담당자에게 알림(SNS)만 보냅니다.")
        if not self.enabled:
            return _result("dry-run", "화이트리스트에 있지만 전체 dry-run(ENABLE_AUTO_REMEDIATION=false) — 판단만 기록합니다.")
        kind = (gd_type + " guardduty").lower()
        if any(word in kind for word in ("port", "sg", "ssh", "ingress")) or "3306" in gd_type:
            return _result("manual", "화이트리스트에 있지만 대상 보안그룹 ID 가 없어 수동 알림합니다.")
        keys = [str(r.get("Id") or "").rsplit(":", 1)[-1] for r in finding.get("Resources") or []
                if "AccessKey" in str(r.get("Type") or "") or "AccessKey:" in str(r.get("Id") or "")]
        if any(key.startswith("AKIA") for key in keys):
            return _result("auto", "화이트리스트 일치(IAM 자격 증명 탐지).", KEY_PLAYBOOK)
        return _result("conditional", "화이트리스트 일치(IAM 자격 증명 탐지).", KEY_PLAYBOOK,
                       "장기 액세스 키(AKIA…)만 비활성화할 수 있습니다. 역할 임시 자격 증명(ASIA…)이면 실행이 실패합니다.")


def annotate(finding, policy):
    """이벤트 행에 붙일 설명·조치 필드. policy 가 없으면 자동 조치 판정은 None."""
    control = control_id(finding)
    gd_type = guardduty_type(finding)
    return {"controlId": control, "findingType": gd_type,
            "remediation": remediation(finding, control), "guidance": explain(finding, control, gd_type),
            "autoRemediation": policy.evaluate(finding, control, gd_type) if policy else None}
