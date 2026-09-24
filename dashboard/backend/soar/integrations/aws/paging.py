"""AWS 페이지 처리와 시각 변환."""
from datetime import datetime, timezone


def collect(client, operation, key, max_items=None, **kwargs):
    """Collect all pages while keeping small test clients compatible."""
    try:
        paginator = client.get_paginator(operation)
        if max_items:
            kwargs["PaginationConfig"] = {"MaxItems": max_items, "PageSize": 100}
        pages = paginator.paginate(**kwargs)
    except (AttributeError, NotImplementedError):
        method = getattr(client, operation)
        return list(method(**kwargs).get(key, []))
    rows = []
    for page in pages:
        rows.extend(page.get(key, []))
    return rows


def to_ms(value):
    if isinstance(value, str):  # Security Hub(ASFF) 날짜는 ISO 문자열이다.
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if isinstance(value, datetime):
        return int(value.astimezone(timezone.utc).timestamp() * 1000)
    return int(value or 0)
