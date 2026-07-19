#!/usr/bin/env python3
"""Deterministic pass/fail gate over a ZAP API-scan JSON report.

zap-api-scan.py's own exit code fails the job on ANY warning-level alert not
explicitly IGNORE'd in its -c config. Active-scanning a JSON API surfaces a
rotating cast of LOW-confidence false positives that land on a different rule
and parameter each run, so a strict per-rule allowlist alone turns the gate
into whack-a-mole.

This gate combines two filters:

  1. The curated per-rule allowlist (the same .zap/*.conf the scan loads): any
     rule marked IGNORE is an accepted risk or a known false positive triaged by
     a human, and never blocks — regardless of risk/confidence.

  2. A confidence threshold on everything else: block only on findings ZAP itself
     rates risk >= Medium AND confidence >= Medium. A real Medium/High-confidence
     finding still reds the pipeline; low-confidence heuristic noise is recorded
     in the HTML/JSON artifacts for manual review but does not block the merge.

Nothing is disabled: non-ignored rules stay armed, the bar is on how sure ZAP is.

ZAP encodes both axes as numeric strings 0-3 on each alert: riskcode
(0 Informational, 1 Low, 2 Medium, 3 High) and confidence (0 False Positive,
1 Low, 2 Medium, 3 High).

Usage: zap-api-gate.py <zap-report.json> <zap-config.conf>
Exit 0 when clean, 1 when a blocking finding survives both filters.
"""
import json
import sys

MIN_RISK = 2        # Medium
MIN_CONFIDENCE = 2  # Medium


def load_alerts(path):
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            yield alert


def load_ignored_rules(path):
    """Plugin IDs the .conf marks IGNORE. Lines are '<ruleId>\\t<action>\\t<comment>'."""
    ignored = set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) >= 2 and fields[1].strip().upper() == "IGNORE":
                ignored.add(fields[0].strip())
    return ignored


def axis(alert, key):
    try:
        return int(alert.get(key, 0))
    except (TypeError, ValueError):
        return 0


def categorize(alerts, ignored):
    """Splits alerts into (blocking, accepted, below_bar) per the accept-list + confidence bar."""
    blocking, accepted, below_bar = [], [], []
    for alert in alerts:
        if alert.get("pluginid") in ignored:
            accepted.append(alert)
        elif axis(alert, "riskcode") >= MIN_RISK and axis(alert, "confidence") >= MIN_CONFIDENCE:
            blocking.append(alert)
        else:
            below_bar.append(alert)
    return blocking, accepted, below_bar


def print_alert_line(a):
    print(f"  - [{a.get('riskdesc')}] {a.get('alert')} "
          f"(plugin {a.get('pluginid')}, count {a.get('count')})")


def print_accepted(accepted, conf_path):
    if not accepted:
        return
    print(f"ZAP gate: {len(accepted)} finding(s) on the {conf_path} accept-list (triaged):")
    for a in accepted:
        print_alert_line(a)


def print_below_bar(below_bar):
    if not below_bar:
        return
    print(f"ZAP gate: {len(below_bar)} finding(s) below the risk>=Medium AND "
          "confidence>=Medium bar (advisory — see the report artifact):")
    for a in below_bar:
        print_alert_line(a)


def print_blocking(blocking):
    print(f"\nZAP gate FAILED: {len(blocking)} finding(s) at risk>=Medium and "
          "confidence>=Medium (not on the accept-list):")
    for a in blocking:
        print(f"  [{a.get('riskdesc')}] {a.get('alert')} (plugin {a.get('pluginid')}, "
              f"count {a.get('count')})")
        for inst in a.get("instances", [])[:10]:
            print(f"     {inst.get('method')} {inst.get('uri')} "
                  f"param={inst.get('param')!r} attack={inst.get('attack')!r}")


def main(argv):
    if len(argv) != 3:
        print("usage: zap-api-gate.py <zap-report.json> <zap-config.conf>", file=sys.stderr)
        return 2

    ignored = load_ignored_rules(argv[2])
    blocking, accepted, below_bar = categorize(load_alerts(argv[1]), ignored)

    print_accepted(accepted, argv[2])
    print_below_bar(below_bar)

    if not blocking:
        print("ZAP gate PASSED: no un-accepted finding at risk>=Medium and confidence>=Medium.")
        return 0

    print_blocking(blocking)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
