"""DynamoDB 상관분석(correlated-findings) → GuardDuty finding ID 별 위험도 상향 정보."""
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class CorrelationRepository:
    def __init__(self, table):
        self._table = table

    def by_guardduty_id(self):
        rows, _ = self._table.scan()
        return {str(row.get("finding_id")): {"bumped": bool(row.get("severity_bumped")),
                                             "finalSeverity": str(row.get("final_severity") or "").upper() or None,
                                             "cves": list(row.get("cve_ids") or [])}
                for row in rows if row.get("finding_id")}


def apply(events, correlations):
    """GuardDuty 이벤트에 상관분석 결과를 붙인다. 위험도 상향 판단은 서버가 한다(설계 2.1-3)."""
    for event in events:
        external = str(event.get("externalFindingId") or "")
        found = correlations.get(external.rsplit("/finding/", 1)[-1]) or correlations.get(external)
        if not found:
            continue
        event["relatedCves"] = found["cves"]
        final = found["finalSeverity"]
        if found["bumped"] and SEVERITY_RANK.get(final, 0) > SEVERITY_RANK.get(event.get("severity"), 0):
            event["severity"] = final
            event["severityBumped"] = True
    return events
