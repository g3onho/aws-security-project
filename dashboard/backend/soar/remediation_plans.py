"""대시보드에서 실행할 수 있는 조치 목록과, 탐지 → 조치 계획 변환.

계획은 항상 서버가 탐지에서 새로 만든다. 브라우저가 보낸 문서 이름·대상은 신뢰하지 않고, 서버가 만든 계획과
같은지만 확인한다. 지원하는 문서는 asr_trigger 의 CONTROL_PLAYBOOKS·SG_PLAYBOOK 과 같은 SSM 문서이며,
액세스 키 ID·공격 IP 처럼 별도 입력이 필요한 조치는 지원하지 않는다(이유를 화면에 알린다).
"""
import re

from .guidance import CONTROL_PLAYBOOKS, KEY_PLAYBOOK, SG_PLAYBOOK

# 실제 ID 는 16진수지만 형식 검증은 SSM 문서(allowedPattern)가 최종으로 한다. 모의 자료의 ID 도 받도록 영숫자로 넓게 읽는다.
SG_ID = re.compile(r"(?:^|security-group/)(sg-[0-9a-z]{8,17})$")
# 인바운드 공개 규칙을 점검하는 Security Hub 규칙. asr_trigger 는 이 계열을 SG_PLAYBOOK 으로 보낸다.
SG_OPEN_CONTROLS = ("EC2.13", "EC2.18", "EC2.19", "EC2.21", "EC2.53", "EC2.54")
ELIGIBLE_MODES = ("auto", "conditional", "dry-run", "manual", "unknown")

# 문서 → 화면 설명. change=무엇을 바꾸는가, criterion=재검증이 확인하는 것.
SPECS = {
    "ASR-RemoveDefaultSgRules": {
        "title": "기본 보안그룹 규칙 제거", "needs_sg": True, "needs_vpc": True,
        "change": "기본 보안그룹의 인바운드·아웃바운드 규칙을 모두 삭제합니다.",
        "criterion": "보안그룹에 인바운드·아웃바운드 규칙이 0개"},
    "ASR-RevokeSecurityGroupIngress": {
        "title": "보안그룹 전체 공개 규칙 회수", "needs_sg": True, "needs_vpc": False, "needs_tag": True,
        "change": "0.0.0.0/0·::/0 에서 들어오는 인바운드 규칙을 회수합니다. 다른 규칙은 그대로 둡니다.",
        "criterion": "보안그룹에 0.0.0.0/0·::/0 인바운드 규칙이 없음"},
    "ASR-EnableEbsDefaultEncryption": {
        "title": "EBS 기본 암호화 켜기", "needs_sg": False, "needs_vpc": False,
        "change": "이 리전의 새 EBS 볼륨을 기본으로 암호화합니다. 기존 볼륨은 바뀌지 않습니다.",
        "criterion": "EBS 기본 암호화가 켜져 있음"},
    "ASR-BlockEbsSnapshotPublicAccess": {
        "title": "EBS 스냅샷 공개 차단", "needs_sg": False, "needs_vpc": False,
        "change": "이 리전의 EBS 스냅샷 공개 공유를 모두 차단합니다(block-all-sharing).",
        "criterion": "스냅샷 퍼블릭 액세스 차단 상태가 block-all-sharing"},
    "ASR-BlockS3AccountPublicAccess": {
        "title": "S3 계정 퍼블릭 액세스 차단", "needs_sg": False, "needs_vpc": False,
        "change": "계정 수준 S3 퍼블릭 액세스 차단 4개 항목을 모두 켭니다.",
        "criterion": "계정 S3 퍼블릭 액세스 차단 4개 항목이 모두 켜져 있음"},
    "ASR-SetIamPasswordPolicy": {
        "title": "IAM 비밀번호 정책 강화", "needs_sg": False, "needs_vpc": False,
        "change": "최소 8자와 대·소문자·숫자·기호 요구를 켭니다. 기존 만료·재사용 방지 값은 유지합니다.",
        "criterion": "최소 길이 8 이상, 대·소문자·숫자·기호 요구가 모두 켜져 있음"},
    "ASR-EnableSsmAutomationLogging": {
        "title": "SSM Automation 로그 켜기", "needs_sg": False, "needs_vpc": False,
        "change": "Automation 스크립트 로그 대상을 CloudWatch 로 바꿉니다.",
        "criterion": "스크립트 로그 대상이 CloudWatch"},
    "ASR-BlockSsmDocumentPublicSharing": {
        "title": "SSM 문서 공개 공유 차단", "needs_sg": False, "needs_vpc": False,
        "change": "SSM 문서를 공개로 공유하는 권한을 Disable 로 바꿉니다.",
        "criterion": "공개 공유 권한이 Disable"},
}


def _unsupported(reason, eligible=True, **extra):
    """eligible=False: 자동 조치 경로 자체가 없는 탐지(화면에 조치 영역을 만들지 않는다)."""
    return {"supported": False, "eligible": eligible, "reason": reason, "playbookId": None, "title": None, "change": None,
            "criterion": None, "parameters": {}, **extra}


def sg_id_of(resource):
    match = SG_ID.search(str(resource or ""))
    return match.group(1) if match else None


def resolve(event, project_vpc_id=None):
    """탐지 → 조치 계획. 실행 가능 여부(권한·설정)는 서비스가 따로 덧붙이고, 여기는 '무엇을' 만 정한다."""
    auto = event.get("autoRemediation") or {}
    mode = auto.get("mode")
    if mode not in ELIGIBLE_MODES:
        return _unsupported(auto.get("reason") or "이 탐지는 자동 조치 경로가 없어 대시보드에서도 실행하지 않습니다.", eligible=False)
    control = event.get("controlId")
    doc = auto.get("playbookId")
    if doc in (KEY_PLAYBOOK[0], "ASR-BlockAttackerNacl"):
        return _unsupported("액세스 키 ID·공격 IP 입력이 필요한 조치라 대시보드 원클릭 조치를 지원하지 않습니다."
                            + (" 차단 IP 는 허니팟 화면의 차단 목록에서 관리합니다." if doc == "ASR-BlockAttackerNacl" else ""))
    if doc not in SPECS:
        doc = CONTROL_PLAYBOOKS.get(control, (None,))[0]
    if doc not in SPECS and control in SG_OPEN_CONTROLS:
        doc = SG_PLAYBOOK[0]
    if doc not in SPECS:
        return _unsupported("이 탐지에 대응하는 대시보드 조치 문서가 없습니다. 담당자가 직접 조치해야 합니다.")
    spec = SPECS[doc]
    params, target = {}, {"resource": event.get("resource"), "region": event.get("region"), "accountId": event.get("accountId")}
    if spec["needs_sg"]:
        sg = sg_id_of(event.get("resource"))
        if not sg:
            return _unsupported("대상 보안그룹 ID 를 탐지에서 찾지 못했습니다.")
        params["SecurityGroupId"] = sg
        target["securityGroupId"] = sg
    if spec["needs_vpc"]:
        if not project_vpc_id:
            return _unsupported("프로젝트 VPC ID(PROJECT_VPC_ID) 설정이 없어 기본 보안그룹 조치를 실행할 수 없습니다.")
        params["VpcId"] = project_vpc_id
    return {"supported": True, "eligible": True, "reason": None, "playbookId": doc, "title": spec["title"], "change": spec["change"],
            "criterion": spec["criterion"], "parameters": params, "needsTag": bool(spec.get("needs_tag")),
            "category": "auto-eligible" if mode in ("auto", "conditional", "dry-run") else "manual",
            "mode": mode, "target": target}
