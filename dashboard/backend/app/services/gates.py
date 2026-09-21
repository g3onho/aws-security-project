"""실행 게이트 — asr_trigger Lambda 와 **같은 판정**을 대시보드에서도 한다.

자동 경로(Lambda)와 수동 경로(대시보드)의 판정이 갈리면 안 되므로
handler.py 의 3중 안전장치를 그대로 옮기고, 가역성 게이트 ④를 추가한다.

  ① 화이트리스트      AUTO_REMEDIABLE_PATTERNS   (handler.py:130 / variables.tf:189-200)
  ② 리소스 태그        AutoRemediation=enabled    (handler.py:47-57, SG 경로 한정)
  ③ 전역 dry-run      ENABLE_AUTO_REMEDIATION    (handler.py:137 / variables.tf:177-181)
  ④ 가역성 (신설)      카탈로그 reversible         — 04-backend-design.md §3.2

④를 새로 두는 이유: "되돌릴 수 있는 조치만 자동화"(README:511)가 지금은 사람의 약속일
뿐 코드가 강제하지 않는다. 카탈로그에 명시하고 서버가 막으면 약속이 코드가 된다.

③에 대한 주의: `enable_auto_remediation` 의 기본값은 **true** 다(variables.tf:180).
README 는 dry-run 스위치로 설명하지만 기본은 실제 실행이다. 다만 ③은 **Lambda 의 자동
실행**을 막는 스위치이므로, 사람이 승인한 수동 실행까지 막지는 않는다.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from ..catalog import loader

# variables.tf:189-200 의 기본 화이트리스트
DEFAULT_PATTERNS = [
    "restricted-ssh",
    "restricted-common-ports",
    "vpc-sg-open-only-to-authorized-ports",
    "EC2.13",
    "EC2.14",
    "EC2.19",
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
    "CredentialAccess:IAMUser/AnomalousBehavior",
    "Discovery:IAMUser/AnomalousBehavior",
]


def patterns() -> list[str]:
    raw = os.getenv("AUTO_REMEDIABLE_PATTERNS", "")
    items = [p for p in raw.split(",") if p]
    return items or DEFAULT_PATTERNS


@dataclass
class Decision:
    allowed: bool
    code: str = ""
    title: str = ""
    detail: str = ""
    gate: str = ""


def matches_whitelist(text: str) -> bool:
    """handler.py:43-44 와 동일 — 패턴을 리터럴로 이스케이프해 대소문자 무시 검색."""
    return any(re.search(re.escape(p), text, re.IGNORECASE) for p in patterns())


def match_text(event: dict) -> str:
    """화이트리스트 판정에 쓸 문자열.

    Lambda 는 finding 원문(Title / Types / GeneratorId)을 본다(handler.py:98).
    대시보드는 데모에서 국문 제목만 가지므로, 카탈로그가 선언한 **식별자**를 함께
    넣어 같은 판정이 나오게 한다. 예: SEC-01 → restricted-ssh, EC2.13.
    """
    spec = loader.get(event.get("scenario", "")) or {}
    match = spec.get("match") or {}
    tokens = [
        event.get("title", ""),
        event.get("scenario", ""),
        event.get("source", ""),
        *(match.get("config_rules") or []),
        *(match.get("securityhub_generator_contains") or []),
        *(match.get("guardduty_type_prefix") or []),
    ]
    return " ".join(str(t) for t in tokens if t)


def evaluate(event: dict, dry_run: bool = False, sg_has_auto_tag=None) -> Decision:
    """대시보드에서의 실행 가능 여부.

    sg_has_auto_tag: SG 경로에서 태그를 확인하는 콜러블. 데모에서는 None(건너뜀).
    """
    scenario = event.get("scenario", "")

    # ④ 가역성 — 되돌릴 수 없는 조치는 승인 여부와 무관하게 막는다.
    if not loader.is_reversible(scenario):
        return Decision(
            False, "GATE_IRREVERSIBLE",
            "되돌릴 수 없는 조치는 자동 실행할 수 없습니다.",
            f"{scenario} 의 카탈로그 remediation.reversible 이 false 입니다. "
            "콘솔에서 절차를 따라 수동 수행하세요.",
            gate="4",
        )

    playbook = loader.playbook(scenario)

    # 플레이북이 없으면 SSM 이 할 일이 없다. 사람이 수행하고 결과만 기록하는 조치이므로
    # **승인이 있으면 통과**시킨다(하드 블록 아님). SEC-04 이미지 교체가 여기 해당한다.
    if not playbook:
        if event.get("approver"):
            return Decision(True, gate="1-manual")
        return Decision(
            False, "APPROVAL_REQUIRED",
            "승인이 필요한 조치입니다.",
            f"{scenario} 는 SSM 플레이북 없이 사람이 수행합니다. 승인 후 결과를 기록하세요.",
            gate="1",
        )

    # 배선되지 않은 플레이북 — ASR-HardenNginx 가 여기 걸린다 (README:303).
    # 이건 승인으로도 풀 수 없다. 호출할 분기 자체가 코드에 없다.
    if not loader.is_wired(scenario):
        return Decision(
            False, "GATE_WHITELIST",
            "플레이북이 아직 배선되지 않았습니다.",
            f"{playbook} 은 SSM 문서와 Lambda 환경변수는 있으나 asr_trigger 에 호출 분기가 "
            "없습니다(README:303). 수동 절차로 수행하세요.",
            gate="1",
        )

    # ① 화이트리스트 — 미포함이면 자동은 못 하지만, 승인된 실행은 허용한다.
    if not matches_whitelist(match_text(event)) and not event.get("approver"):
        return Decision(
            False, "APPROVAL_REQUIRED",
            "승인이 필요한 조치입니다.",
            "화이트리스트에 없는 finding 이라 승인 기록 없이는 실행할 수 없습니다.",
            gate="1",
        )

    # ② SG 태그 — 태그 없는 대상(db-manual-sg 등)은 대조군이다.
    if sg_has_auto_tag is not None and event.get("resource", "").startswith("sg-"):
        if not sg_has_auto_tag(event["resource"]) and not event.get("approver"):
            return Decision(
                False, "GATE_RESOURCE_TAG",
                "AutoRemediation 태그가 없는 대상입니다.",
                f"{event['resource']} 는 대조군입니다. 승인 후 수동 조치하세요.",
                gate="2",
            )

    if dry_run:
        return Decision(True, "", "dry-run 통과", "게이트만 판정하고 실행하지 않았습니다.", gate="3")

    return Decision(True, gate="pass")
