"""CloudTrail 관리 이벤트에서 EC2 교체 이력을 읽는다."""
import json
import re
from datetime import datetime, timedelta, timezone

from .paging import collect


INSTANCE_ID = re.compile(r"^i-[0-9a-f]+$")


def _ids(event):
    return {item.get("ResourceName") for item in event.get("Resources", [])
            if INSTANCE_ID.fullmatch(item.get("ResourceName") or "")}


def _profile(event):
    try:
        detail = json.loads(event.get("CloudTrailEvent") or "{}")
    except (TypeError, ValueError):
        detail = {}
    profile = (detail.get("requestParameters") or {}).get("iamInstanceProfile") or {}
    name = (profile.get("name") or (profile.get("arn") or "").rsplit("/", 1)[-1]) if isinstance(profile, dict) else None
    if name:
        return name
    candidates = []
    for item in event.get("Resources", []):
        if "instanceprofile" in (item.get("ResourceType") or "").lower():
            name = (item.get("ResourceName") or "").rsplit("/", 1)[-1]
            if name and not name.startswith("AIPA"):
                candidates.append(name)
    return candidates[0] if candidates else None


def replaced_instances(session, start, end, profiles):
    """조회 구간에 종료된 EC2를 실행 당시의 IAM 인스턴스 프로필에 연결한다.

    CloudTrail 이벤트 조회는 최근 90일로 제한된다. 실행 기록을 검증할 수 없는
    인스턴스의 지표는 다른 서버에 잘못 이어 붙이지 않는다.
    """
    if not profiles:
        return {}, False
    client = session.client("cloudtrail")
    terminations = collect(client, "lookup_events", "Events",
                           LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "TerminateInstances"}],
                           StartTime=start, EndTime=end)
    terminated = set().union(*(_ids(event) for event in terminations)) if terminations else set()
    if not terminated:
        return {}, False
    # RunInstances 의 실행 시각이 조회 구간보다 앞설 수 있다.
    lookback = datetime.now(timezone.utc) - timedelta(days=90)
    if end <= lookback:
        return {}, True
    launches = collect(client, "lookup_events", "Events",
                       LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "RunInstances"}],
                       StartTime=lookback, EndTime=end)
    by_profile = {profile: {} for profile in profiles}
    matched = set()
    for event in launches:
        ids = _ids(event) & terminated
        profile = _profile(event)
        if profile:
            matched.update(ids)
        if profile in by_profile:
            for identifier in ids:
                by_profile[profile][identifier] = event.get("EventTime") or datetime.min.replace(tzinfo=timezone.utc)
    return {name: sorted(ids, key=lambda identifier: (ids[identifier], identifier))
            for name, ids in by_profile.items()}, bool(terminated - matched)
