"""Validation for the retained epoch-millisecond frontend compatibility API."""
import re

from .domain import SEVERITIES, SOURCES, STATUSES
from .errors import Problem


def legacy_query(args, as_of):
    def integer(name, default):
        raw = args.get(name, "")
        if raw == "":
            return default
        try:
            return int(raw)
        except (ValueError, TypeError) as error:
            raise Problem(400, f"{name}은 정수여야 합니다.") from error

    def enum(name, choices):
        value = args.get(name) or None
        if value is not None and value not in choices:
            raise Problem(400, f"{name} 값이 올바르지 않습니다.")
        return value

    end = integer("to", as_of)
    start = integer("from", end - 86400000)
    if start < 0 or start >= end or end - start > 31 * 86400000 or end > as_of + 300000:
        raise Problem(400, "조회 시간은 31일 이내의 유효한 구간이어야 합니다.")
    region = args.get("region") or "all"
    if not re.fullmatch(r"(?:[a-z]{2}(?:-[a-z]+)+-\d|all|global|unknown)", region):
        raise Problem(400, "리전 값이 올바르지 않습니다.")
    needle = args.get("q") or ""
    if len(needle) > 200:
        raise Problem(400, "검색어는 200자 이하여야 합니다.")
    limit = integer("limit", 200)
    if not 1 <= limit <= 1000:
        raise Problem(400, "limit은 1~1000이어야 합니다.")
    return {
        "from": start, "to": end, "region": region, "q": needle, "limit": limit,
        "severity": enum("severity", SEVERITIES), "status": enum("status", STATUSES),
        "source": enum("source", SOURCES), "environment": args.get("environment") or None,
        "resource": args.get("resource") or None, "scenario": args.get("scenario") or None,
        "view": args.get("view") or "overview", "cursor": args.get("cursor") or None,
        "scope": "all" if args.get("scope") == "all" else "one",
        **{name: args.get(name, "").lower() in {"true", "1"}
           for name in ("ignoreRegion", "fixableOnly")},
    }
