#!/usr/bin/env python3
"""Datadog canary verify for Cloud Deploy (HBNXT-359 / HBNXT-2108).

Runs as a skaffold `verify` action during the Cloud Deploy canary phase. Queries
Datadog for the newly-deployed Cloud Run revision's HTTP 5xx error rate over a
short window and FAILS (non-zero exit) when it breaches the threshold — which
trips the Cloud Deploy automation rollback rule and reverts the canary.

Datadog is the authoritative signal (per the 2026-06-12 incident review). Metrics
come from the Datadog GCP integration's per-revision `gcp.run.request_count`,
tagged by {service_name, revision_name, response_code_class}.

Config is via env (only SERVICE is required; the rest default sanely):
  DD_API_KEY, DD_APP_KEY  Datadog credentials (injected from Secret Manager).
  DD_SITE                 Datadog site (default: datadoghq.com).
  SERVICE                 Cloud Run service, e.g. hello-canary-stg (required).
  REVISION                Revision to judge; default = newest revision of SERVICE
                          (looked up via gcloud).
  REGION, PROJECT         Cloud Run location/project for the revision lookup.
  ERROR_RATE_THRESHOLD    Max acceptable 5xx fraction (default: 0.05 = 5%).
  MIN_REQUESTS            Min requests in-window to judge; below this the check
                          SKIPS (passes) so a no-traffic canary (hello-canary,
                          storybook) is never gated on absent signal (default: 20).
  WINDOW_SECONDS          Look-back window (default: 300).

Exit codes: 0 = pass (or skipped, no signal); 1 = breach (roll back);
2 = config/credential error (treated as a verify failure by Cloud Deploy).
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


class ConfigError(Exception):
    """Missing/invalid configuration or credentials."""


def _env(name, default=None, required=False):
    val = os.environ.get(name, default)
    if required and not val:
        raise ConfigError(f"missing required env {name}")
    return val


def newest_revision(service, region, project):
    """Newest revision name for a Cloud Run service (via gcloud)."""
    out = subprocess.check_output(
        ["gcloud", "run", "revisions", "list",
         "--service", service, "--region", region, "--project", project,
         "--sort-by", "~metadata.creationTimestamp", "--limit", "1",
         "--format", "value(metadata.name)"],
        text=True,
    )
    rev = out.strip().splitlines()[0] if out.strip() else ""
    if not rev:
        raise ConfigError(f"no revisions found for {service} in {project}/{region}")
    return rev


def query_metric(site, api_key, app_key, query, frm, to):
    """Run a Datadog v1 timeseries query; return the summed point value."""
    url = (f"https://api.{site}/api/v1/query"
           f"?from={frm}&to={to}&query={urllib.parse.quote(query)}")
    req = urllib.request.Request(url, headers={
        "DD-API-KEY": api_key,
        "DD-APPLICATION-KEY": app_key,
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise ConfigError(f"Datadog query failed ({e.code}): {e.read().decode()[:200]}")
    except urllib.error.URLError as e:
        # Network/TLS/DNS failure — can't measure the canary, so fail safe (don't promote
        # something we can't verify). Surfaced as a config error => non-zero exit => rollback.
        raise ConfigError(f"Datadog unreachable: {e.reason}")
    return _sum_series(body)


def _sum_series(body):
    """Sum every point across every returned series (0.0 if none)."""
    total = 0.0
    for series in body.get("series", []) or []:
        for point in series.get("pointlist", []) or []:
            # pointlist entries are [timestamp_ms, value]; value may be null.
            if len(point) == 2 and point[1] is not None:
                total += point[1]
    return total


def evaluate(total_requests, error_requests, threshold, min_requests):
    """Pure decision logic — returns (passed: bool, reason: str)."""
    if total_requests < min_requests:
        return True, (f"SKIP — only {total_requests:.0f} requests in window "
                      f"(< MIN_REQUESTS={min_requests}); no signal to gate on")
    rate = (error_requests / total_requests) if total_requests else 0.0
    if rate > threshold:
        return False, (f"FAIL — 5xx rate {rate:.2%} over {total_requests:.0f} "
                       f"requests exceeds threshold {threshold:.2%}")
    return True, (f"PASS — 5xx rate {rate:.2%} over {total_requests:.0f} "
                  f"requests within threshold {threshold:.2%}")


def main():
    try:
        service = _env("SERVICE", required=True)
        site = _env("DD_SITE", "datadoghq.com")
        api_key = _env("DD_API_KEY", required=True)
        app_key = _env("DD_APP_KEY", required=True)
        region = _env("REGION", "us-central1")
        project = _env("PROJECT", "humblebundle-stg")
        threshold = float(_env("ERROR_RATE_THRESHOLD", "0.05"))
        min_requests = float(_env("MIN_REQUESTS", "20"))
        window = int(_env("WINDOW_SECONDS", "300"))

        revision = _env("REVISION") or newest_revision(service, region, project)
        to = int(time.time())
        frm = to - window
        scope = f"service_name:{service},revision_name:{revision}"

        total = query_metric(site, api_key, app_key,
                             f"sum:gcp.run.request_count{{{scope}}}.as_count()", frm, to)
        errors = query_metric(site, api_key, app_key,
                             f"sum:gcp.run.request_count{{{scope},response_code_class:5xx}}.as_count()",
                             frm, to)

        passed, reason = evaluate(total, errors, threshold, min_requests)
        print(f"[canary-verify] {service}@{revision}: {reason}")
        sys.exit(0 if passed else 1)
    except ConfigError as e:
        print(f"[canary-verify] config/credential error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
