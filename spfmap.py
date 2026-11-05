#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any, Dict, List

from spfmap import audit_spf
from spfmap.models import SpfAuditResult, IpFinding, AsnOwner, OverlapFinding, AsnSummaryItem


def _result_to_dict(res: SpfAuditResult, show_chain: bool = False) -> Dict[str, Any]:
    def owner_to_dict(o: AsnOwner | None) -> Dict[str, Any] | None:
        if not o:
            return None
        return {"asn": o.asn, "country": o.country, "rir": o.rir, "name": o.name}

    def finding_to_dict(f: IpFinding) -> Dict[str, Any]:
        d = {
            "network": f.network,
            "ip_version": f.ip_version,
            "declared_in": f.declared_in,
            "mechanism": f.mechanism,
            "source": f.source,
        }
        if show_chain:
            d["chain"] = list(f.chain)
        return d

    overlaps = []
    for o in res.overlaps:
        overlaps.append({"a": o.a, "b": o.b, "same_asn": o.same_asn})

    asn_summary = [
        {
            "asn": s.asn,
            "count": s.count,
            "name": s.name,
            "country": s.country,
            "rir": s.rir,
        }
        for s in res.asn_summary
    ]

    return {
        "domain": res.domain,
        "stats": {
            "visited_domains": res.stats.visited_domains,
            "spf_txt_lookups": res.stats.spf_txt_lookups,
            "dns_lookups_estimate": res.stats.dns_lookups_estimate,
            "ip_findings": res.stats.ip_findings,
        },
        "flags": {
            "has_exists": res.flags.has_exists,
            "has_ptr": res.flags.has_ptr,
            "has_redirect": res.flags.has_redirect,
            "has_include": res.flags.has_include,
            "multiple_spf_records": res.flags.multiple_spf_records,
        },
        "findings": {
            dom: [finding_to_dict(f) for f in sorted(items, key=lambda x: (x.ip_version, x.network))]
            for dom, items in sorted(res.findings_by_domain.items(), key=lambda x: x[0])
        },
        "owners_by_network": {k: owner_to_dict(v) for k, v in res.owners_by_network.items()},
        "duplicates": res.duplicate_networks,
        "overlaps": overlaps,
        "asn_summary": asn_summary,
    }


def _print_human(res: SpfAuditResult, owner: bool, show_chain: bool) -> None:
    print(f"SPFMap audit for: {res.domain}")
    print(f"Visited SPF domains: {res.stats.visited_domains}")
    print(f"SPF TXT lookups: {res.stats.spf_txt_lookups}")
    print(f"Estimated SPF DNS lookups: {res.stats.dns_lookups_estimate} (limit is 10)")
    print(f"IP findings: {res.stats.ip_findings}")
    print("")

    if res.flags.multiple_spf_records:
        print("Flag: Multiple SPF records found (permerror risk).")
    if res.flags.has_ptr:
        print("Flag: ptr mechanism found (unreliable, and discouraged).")
    if res.flags.has_exists:
        print("Flag: exists mechanism found (dynamic DNS logic).")
    if res.flags.has_redirect:
        print("Note: redirect= present in the root SPF.")
    print("")

    for declared_in, items in sorted(res.findings_by_domain.items(), key=lambda x: x[0]):
        print(f"Declared in: {declared_in} ({len(items)} networks)")
        for f in sorted(items, key=lambda x: (x.ip_version, x.network)):
            owner_str = ""
            if owner:
                o = res.owners_by_network.get(f.network)
                if o:
                    owner_str = f" | ASN {o.asn} | {o.name} | {o.country} | {o.rir}"
                else:
                    owner_str = " | ASN unknown"
            print(f"  - {f.network} (ip{f.ip_version}) [{f.source}]{owner_str}")
            if show_chain:
                chain_str = " -> ".join(f.chain) if f.chain else declared_in
                print(f"    via: {chain_str}")
            print(f"    mech: {f.mechanism}")
        print("")

    print("Duplicates (exact same network):")
    if res.duplicate_networks:
        for net, cnt in sorted(res.duplicate_networks.items(), key=lambda x: (-x[1], x[0])):
            print(f"  - {net}: {cnt}")
    else:
        print("  None found.")
    print("")

    print("Overlaps (intersecting networks):")
    if res.overlaps:
        for o in res.overlaps[:200]:
            if o.same_asn is None:
                print(f"  - {o.a} overlaps {o.b}")
            else:
                tag = "same ASN" if o.same_asn else "different ASN"
                print(f"  - {o.a} overlaps {o.b} ({tag})")
        if len(res.overlaps) > 200:
            print(f"  ...and {len(res.overlaps) - 200} more")
    else:
        print("  None found.")
    print("")

    if owner and res.asn_summary:
        print("ASN summary (networks per ASN):")
        for s in res.asn_summary[:20]:
            if s.name:
                print(f"  - AS{s.asn}: {s.count} : {s.name}")
            else:
                print(f"  - AS{s.asn}: {s.count}")
        if len(res.asn_summary) > 20:
            print(f"  ...and {len(res.asn_summary) - 20} more")
        print("")


def main() -> int:
    p = argparse.ArgumentParser(
        prog="spfmap",
        description="Map and analyse SPF authorization paths, IP ranges, and network ownership.",
    )
    p.add_argument("domain", help="Domain to audit, e.g., example.com")
    p.add_argument("--nameserver", default=None, help="Optional DNS resolver IP, e.g., 1.1.1.1")
    p.add_argument("--timeout", type=float, default=4.0, help="DNS timeout seconds")
    p.add_argument("--max-depth", type=int, default=12, help="Max include/redirect depth")
    p.add_argument("--owner", action="store_true", help="Lookup ASN owner via Team Cymru DNS")
    p.add_argument("--json", dest="as_json", action="store_true", help="Output JSON")
    p.add_argument("--show-chain", action="store_true", help="Include include/redirect chain in output")
    p.add_argument("--only-includes", action="store_true", help="Exclude networks declared on the root domain")
    args = p.parse_args()

    res = audit_spf(
        domain=args.domain,
        nameserver=args.nameserver,
        timeout=args.timeout,
        max_depth=args.max_depth,
        owner_lookup=args.owner,
        include_root_ip=not args.only_includes,
    )

    if args.as_json:
        print(json.dumps(_result_to_dict(res, show_chain=args.show_chain), indent=2, sort_keys=True))
    else:
        _print_human(res, owner=args.owner, show_chain=args.show_chain)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
