"""Tron — the Grid guardian.

Given a policy of sanctioned flows (same shape as kitchen-microsegmenter), classify observed
connections against it. Where the micro-segmenter writes the rules at design time, Tron watches
whether reality obeys them at run time. Pure functions — unit-testable, no I/O.

"I fight for the Users."
"""

# Trust tiers: higher = more sensitive. A lower tier reaching a higher one is a climb.
TIERS = {"iot": 1, "boh": 2, "pos": 3, "admin": 4}


def sanctioned_set(policy):
    return {
        (f["src_zone"], f["dst_zone"], f["port"])
        for f in policy.get("flows", [])
    }


def _tier(policy, zone):
    return TIERS.get(policy.get("zones", {}).get(zone))


def classify(policy, conn, sanctioned=None):
    """Classify one observed connection: sanctioned / intrusion / unsanctioned."""
    sanctioned = sanctioned_set(policy) if sanctioned is None else sanctioned
    key = (conn.get("src_zone"), conn.get("dst_zone"), conn.get("port"))

    if key in sanctioned:
        return {"verdict": "sanctioned", "reason": "on the sanctioned list"}

    st, dt = _tier(policy, conn.get("src_zone")), _tier(policy, conn.get("dst_zone"))
    if st is not None and dt is not None and st < dt:
        return {"verdict": "intrusion",
                "reason": f'{conn.get("src_zone")}->{conn.get("dst_zone")} climbs trust tiers and '
                          f'is not sanctioned — derezzed'}

    return {"verdict": "unsanctioned", "reason": "not on the sanctioned list"}


def patrol(policy, connections):
    s = sanctioned_set(policy)
    return [dict(c, **classify(policy, c, s)) for c in connections]


def has_intrusions(results):
    return any(r["verdict"] == "intrusion" for r in results)
