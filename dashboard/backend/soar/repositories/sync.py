"""적재 동기화 상태(modules/soar finding_sync 의 "__sync__" 행) → asOf·경고.

설계 2.3 원칙 6: 조회별 asOf·warnings 전달. 2.2: 지연·실패를 정상 목록으로 위장하지 않는다.
asOf 는 마지막 전체 대조 성공 시각이다. 이벤트 적재는 그보다 새로울 수 있지만, 빠짐없음이 보장되는
시각은 대조 시각이라 이것을 기준으로 둔다.
"""
from ..integrations.aws.paging import to_ms

STALE_MS = 20 * 60 * 1000  # 대조 주기(10분) 두 번


def freshness(status, label, now):
    if status is None:
        return {"asOf": None, "warnings": [f"{label} 동기화 기록이 없습니다. 백필 전이거나 적재가 시작되지 않았습니다."]}
    if status.get("unreadable"):
        return {"asOf": None, "warnings": [f"{label} 동기화 상태를 확인하지 못했습니다."]}
    success = to_ms(status["last_success_at"]) if status.get("last_success_at") else None
    attempt = to_ms(status["last_attempt_at"]) if status.get("last_attempt_at") else None
    warnings = []
    if success is None or now - success > STALE_MS:
        minutes = "알 수 없는 시간" if success is None else f"{(now - success) // 60000}분"
        warnings.append(f"{label} 동기화가 {minutes} 동안 완료되지 않았습니다. 최신 변경이 빠졌을 수 있습니다.")
    if status.get("last_error") and (success is None or (attempt or 0) > success):
        warnings.append(f"최근 {label} 동기화가 실패했습니다.")
    source, table = status.get("source_open"), status.get("table_open")
    if source is not None and table is not None and source != table:
        warnings.append(f"마지막 대조에서 {label} 원본 {source}건과 저장 {table}건이 달랐습니다.")
    return {"asOf": success, "warnings": warnings}
