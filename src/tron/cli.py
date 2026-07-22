"""tron patrol <policy.json> <observed.jsonl> — watch the Grid for rogue programs.

Exit 1 if any intrusion (uptier, unsanctioned) is seen."""
import argparse
import json
import sys

from .grid import patrol, has_intrusions


def _load_jsonl(path):
    rows = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(prog="tron")
    parser.add_argument("command", choices=["patrol"])
    parser.add_argument("policy", help="sanctioned-flow policy JSON")
    parser.add_argument("observed", help="observed connections, one JSON object per line")
    args = parser.parse_args(argv)

    with open(args.policy) as fh:
        policy = json.load(fh)
    results = patrol(policy, _load_jsonl(args.observed))

    glyph = {"sanctioned": "  ok  ", "unsanctioned": " warn ", "intrusion": "▲ ROGUE",
             "unknown-zone": "? BLIND"}
    for r in results:
        print(f"{glyph.get(r['verdict'], '  ?  ')}  "
              f"{r.get('src_zone')}->{r.get('dst_zone')}:{r.get('port')}  {r['reason']}",
              file=sys.stderr)

    intrusions = sum(1 for r in results if r["verdict"] == "intrusion")
    offlist = sum(1 for r in results if r["verdict"] != "sanctioned")
    print(f"patrol complete — {len(results)} connections, {offlist} off-list, {intrusions} intrusions",
          file=sys.stderr)
    return 1 if has_intrusions(results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
