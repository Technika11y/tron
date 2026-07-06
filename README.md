```
   ┌──┬──┬──┬──┬──┐
   │░░│  │▓▓│  │░░│   T R O N · the Grid guardian
   ├──┼──┼──┼──┼──┤   "I fight for the Users."
   │  │▓▓│  │░░│  │
   └──┴──┴──┴──┴──┘
```

# tron

> The Grid guardian. Patrols observed network traffic against a sanctioned-flow policy and
> **derezzes** what doesn't belong.
>
> Technika11y **Labs** · *"I fight for the Users."*

![status](https://img.shields.io/badge/status-pre--alpha-orange)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)

> Affectionate homage. Not affiliated with or endorsed by Disney; *Tron* and related marks belong
> to their owners.

---

## Quick start

```bash
git clone https://github.com/technika11y/tron && cd tron
PYTHONPATH=src python3 -m tron.cli patrol examples/policy.json examples/observed.jsonl
```

## Status

| Capability | State |
|---|---|
| Classify an observed connection vs. sanctioned flows (sanctioned / intrusion / unsanctioned) | ✅ works, tested |
| Trust-tier awareness (a lower zone reaching a higher one = intrusion) | ✅ works, tested |
| `patrol` a batch of observed connections; exit 1 on any intrusion | ✅ works, tested |
| Live capture / NetFlow / pcap ingestion | ❌ not built — you supply the observed connections |

## Why it exists

`kitchen-microsegmenter` writes the rules; `tron` watches whether reality obeys them. Point it at a
sanctioned-flow policy and a log of observed connections, and it tells you which ones climbed a
trust tier they had no business touching — the runtime half of the same zero-trust idea.

## Usage

```bash
PYTHONPATH=src python -m tron.cli patrol examples/policy.json examples/observed.jsonl
```

```
  ok    boh->iot:1883  on the sanctioned list
▲ ROGUE iot->pos:443  iot->pos climbs trust tiers and is not sanctioned — derezzed
 warn   pos->boh:8080  not on the sanctioned list
patrol complete — 3 connections, 2 off-list, 1 intrusions
```

## License

[Apache-2.0](LICENSE). Report issues privately — see [`SECURITY.md`](SECURITY.md).

---

**Part of the [Technika11y](https://github.com/technika11y) suite** · [technika11y.github.io](https://technika11y.github.io/) · security, compliance, and accessibility as one discipline.
