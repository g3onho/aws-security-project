"""3계층(Nginx·Flask·MySQL) 점검 결과 표(tier_check Lambda 가 저장) → 화면용 계층 상태(순수 변환).

대시보드는 컨테이너에 접속하지 않고 저장된 증거만 읽는다(DEC-016). 아래 경우는 정상으로 보이지 않고 unknown 이다.
  - 행이 없음 · 상태 값이나 점검 시각을 해석할 수 없음
  - 행에 오래된 결과 기준(stale_after_seconds)이 없어 신선도를 판단할 수 없음
  - 점검 시각이 현재보다 미래임
  - 마지막 점검이 기준(stale_after_seconds)보다 오래됨 — 점검 작업이 멈췄을 수 있다
저장된 상태가 unknown 이면 tier_check 가 남긴 사유(detail)를 그대로 보여 준다.
"""
from ..integrations.aws.paging import to_ms

STATUSES = ("healthy", "degraded", "unhealthy", "unknown")


def _unknown(tier, detail, observed_at=None, source=None):
    return {**tier, "status": "unknown", "observedAt": observed_at, "source": source, "detail": detail}


def evaluate(tier, row, now):
    """tier: {id, name, role}. row: 저장된 행(dict) 또는 None. now: 현재 시각(ms). → 계층 상태 dict(observedAt 은 ms)."""
    if not row:
        return _unknown(tier, "점검 결과 없음")
    source = row.get("source")
    status = row.get("status")
    if status not in STATUSES:
        return _unknown(tier, "저장된 점검 상태를 해석할 수 없습니다", source=source)
    try:
        checked = to_ms(row.get("checked_at")) if row.get("checked_at") else None
    except (TypeError, ValueError):
        checked = None
    if not checked:
        return _unknown(tier, "점검 시각을 해석할 수 없습니다", source=source)
    stale_after = row.get("stale_after_seconds")
    if not isinstance(stale_after, (int, float)) or isinstance(stale_after, bool) or stale_after <= 0:
        return _unknown(tier, "오래된 결과 기준이 없어 점검 결과의 신선도를 판단할 수 없습니다", checked, source)
    age_seconds = (now - checked) / 1000
    if age_seconds < 0:
        return _unknown(tier, "점검 시각이 현재보다 미래라 점검 결과의 신선도를 판단할 수 없습니다", checked, source)
    if age_seconds > stale_after:
        return _unknown(tier, f"마지막 점검이 {int(age_seconds // 60)}분 전이라 오래된 결과입니다"
                              f"(기준 {int(stale_after // 60)}분, 마지막 상태 {status}). 점검 작업을 확인하세요",
                        checked, source)
    return {**tier, "status": status, "observedAt": checked, "source": source, "detail": row.get("detail") or None}
