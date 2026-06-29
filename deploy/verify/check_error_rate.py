#!/usr/bin/env python3
"""Canary verify for Cloud Deploy (HBNXT-359 / HBNXT-2108).

Runs as a skaffold `verify` action during the Cloud Deploy canary phase. Queries
Cloud Monitoring for the newly-deployed Cloud Run revision's HTTP 5xx error rate over
a short window and FAILS (non-zero exit) when it breaches the threshold — which trips
the Cloud Deploy auto-rollback automation.

Why Cloud Monitoring and not Datadog: Datadog's GCP-integration ingestion lag (>7 min
observed) is too slow to gate the early canary phase — the bad revision advances before
the metric arrives. Cloud Monitoring's native `run.googleapis.com/request_count` lags
only ~1-2 min. Datadog stays authoritative for the dashboard + alerting (separate).

Config is via env (only SERVICE is required; the rest default sanely):
  SERVICE                 Cloud Run service, e.g. hello-canary-stg (required).
  CANARY_PROJECT_ID       Project ID for the lookups (preferred; PROJECT is overridden by
                          Cloud Deploy with the numeric project number). Falls back to
                          humblebundle-stg.
  REGION                  Cloud Run location (default us-central1).
  REVISION                Revision to judge; default = newest revision of SERVICE.
  ERROR_RATE_THRESHOLD    Max acceptable 5xx fraction (default 0.05 = 5%).
  MIN_REQUESTS            Min requests in-window to judge; below this -> SKIP (pass) so a
                          no-traffic canary isn't gated on absent signal (default 10).
  WINDOW_SECONDS          Look-back window (default 300).
  BAKE_SECONDS            Initial soak before polling (default 30).
  POLL_TIMEOUT            Max seconds to wait for metrics to settle before judging; poll
                          until >= MIN_REQUESTS or this timeout (default 240). No data by
                          the timeout => SKIP.
  POLL_INTERVAL           Seconds between polls (default 30).

Exit codes: 0 = pass (or SKIP, no signal); 1 = breach (roll back);
2 = config/credential error (treated as a verify failure by Cloud Deploy).
"""
import datetime
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


def pick_project(canary_project_id, project_env, default="humblebundle-stg"):
    """Resolve the project ID for gcloud/Monitoring lookups.

    Cloud Deploy injects PROJECT as the numeric project NUMBER, which `gcloud run`
    rejects — so prefer CANARY_PROJECT_ID and never trust a numeric/empty value.
    """
    p = canary_project_id or project_env or ""
    return default if (not p or p.isdigit()) else p


def newest_revision(service, region, project):
    """Newest revision name for a Cloud Run service (via gcloud)."""
    try:
        out = subprocess.check_output(
            ["gcloud", "run", "revisions", "list",
             "--service", service, "--region", region, "--project", project,
             "--sort-by", "~metadata.creationTimestamp", "--limit", "1",
             "--format", "value(metadata.name)"],
            text=True, stderr=subprocess.STDOUT,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        out = getattr(e, "output", "") or ""
        raise ConfigError(f"could not list revisions for {service} in {project}/{region}: {out.strip() or e}")
    rev = out.strip().splitlines()[0] if out.strip() else ""
    if not rev:
        raise ConfigError(f"no revisions found for {service} in {project}/{region}")
    return rev


def access_token():
    """OAuth access token for the execution SA (via gcloud / ADC)."""
    try:
        return subprocess.check_output(
            ["gcloud", "auth", "print-access-token"], text=True, stderr=subprocess.STDOUT).strip()
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        out = getattr(e, "output", "") or ""
        raise ConfigError(f"could not get access token: {out.strip() or e}")


def _rfc3339(epoch):
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def request_count(project, token, service, revision, frm, to, window, only_5xx=False):
    """Summed Cloud Run request_count for a revision over [frm, to] (optionally 5xx only)."""
    flt = ('metric.type="run.googleapis.com/request_count" '
           'resource.type="cloud_run_revision" '
           f'resource.labels.service_name="{service}" '
           f'resource.labels.revision_name="{revision}"')
    if only_5xx:
        flt += ' metric.labels.response_code_class="5xx"'
    params = {
        "filter": flt,
        "interval.startTime": _rfc3339(frm),
        "interval.endTime": _rfc3339(to),
        "aggregation.alignmentPeriod": f"{window}s",
        "aggregation.perSeriesAligner": "ALIGN_SUM",
        "aggregation.crossSeriesReducer": "REDUCE_SUM",
        "view": "FULL",
    }
    url = (f"https://monitoring.googleapis.com/v3/projects/{project}/timeSeries?"
           + urllib.parse.urlencode(params))
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise ConfigError(f"Cloud Monitoring query failed ({e.code}): {e.read().decode()[:200]}")
    except urllib.error.URLError as e:
        # Can't measure the canary -> fail safe (non-zero exit -> rollback).
        raise ConfigError(f"Cloud Monitoring unreachable: {e.reason}")
    return _sum_points(body)


def _sum_points(body):
    """Sum every point across every returned timeseries (0.0 if none)."""
    total = 0.0
    for series in body.get("timeSeries", []) or []:
        for pt in series.get("points", []) or []:
            v = pt.get("value", {})
            val = v.get("int64Value", v.get("doubleValue"))
            if val is not None:
                total += float(val)
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
        region = _env("REGION", "us-central1")
        project = pick_project(os.environ.get("CANARY_PROJECT_ID"), os.environ.get("PROJECT"))
        threshold = float(_env("ERROR_RATE_THRESHOLD", "0.05"))
        min_requests = float(_env("MIN_REQUESTS", "10"))
        window = int(_env("WINDOW_SECONDS", "300"))
        bake = int(_env("BAKE_SECONDS", "30"))
        poll_timeout = int(_env("POLL_TIMEOUT", "240"))
        poll_interval = int(_env("POLL_INTERVAL", "30"))

        revision = _env("REVISION") or newest_revision(service, region, project)
        token = access_token()
        if bake > 0:
            print(f"[canary-verify] initial soak {bake}s...")
            time.sleep(bake)

        # Poll until Cloud Monitoring has ingested enough data to judge (~1-2 min lag) or
        # the timeout elapses, then judge. No data by timeout => SKIP (no-traffic canary).
        deadline = time.time() + poll_timeout
        total = errors = 0.0
        while True:
            to = int(time.time())
            frm = to - window
            total = request_count(project, token, service, revision, frm, to, window)
            if total >= min_requests:
                errors = request_count(project, token, service, revision, frm, to, window, only_5xx=True)
                break
            if time.time() >= deadline:
                break
            print(f"[canary-verify] {total:.0f} requests so far (need {min_requests:.0f}); "
                  f"waiting {poll_interval}s for metrics to settle...")
            time.sleep(poll_interval)
            token = access_token()  # refresh in case of a long poll

        passed, reason = evaluate(total, errors, threshold, min_requests)
        print(f"[canary-verify] {service}@{revision}: {reason}")
        sys.exit(0 if passed else 1)
    except ConfigError as e:
        print(f"[canary-verify] config/credential error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
