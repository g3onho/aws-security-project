"""One account, region and resource boundary for every read surface."""


def matches(row, principal):
    scope = principal.get("scope") or {}
    for field, key in (("accountId", "accounts"), ("region", "regions"), ("resource", "resources")):
        allowed = scope.get(key)
        if allowed is not None and row.get(field) not in allowed:
            return False
    return True
