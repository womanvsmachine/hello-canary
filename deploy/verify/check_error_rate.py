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
  DD_API_KEY, DD_APP_KEY  Datadog credentials. If unset, they are read from Secret
                          Manager (DD_API_KEY_SECRET / DD_APP_KEY_SECRET in PROJECT,
                          defaulting to humble-shared-stg-datadog-{api,app}key) — the
                          Cloud Deploy execution SA fetches them at verify time.
  DD_SITE                 Datadog site (default: datadoghq.com).
  SERVICE                 Cloud Run service, e.g. hello-canary-stg (required).
  REVISION                Revision to judge; default = newest revision of SERVICE
                          (looked up via gcloud).
  REGION                  Cloud Run location for the revision lookup (default us-central1).
  CANARY_PROJECT_ID       Project ID for revision/secret lookups. Preferred over PROJECT,
                          which Cloud Deploy overrides with the numeric project NUMBER
                          (gcloud run rejects numbers). Falls back to humblebundle-stg.
  ERROR_RATE_THRESHOLD    Max acceptable 5xx fraction (default: 0.05 = 5%).
  MIN_REQUESTS            Min requests in-window to judge; below this the check
                          SKIPS (passes) so a no-traffic canary (hello-canary,
                          storybook) is never gated on absent signal (default: 20).
  WINDOW_SECONDS          Look-back window (default: 300).
  BAKE_SECONDS            Initial soak before polling starts (default: 30).
  POLL_TIMEOUT            Max seconds to wait for Datadog to ingest enough data before
                          judging. The GCP integration lags several minutes, so a single
                          query after a short bake can read an empty window and false-pass;
                          instead we poll until there are >= MIN_REQUESTS or this timeout
                          (default: 420). No data by the timeout => SKIP (no-traffic canary).
  POLL_INTERVAL           Seconds between polls while waiting for data (default: 30).

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


def pick_project(canary_project_id, project_env, default="humblebundle-stg"):
    """Resolve the project ID for gcloud lookups.

    Cloud Deploy injects PROJECT as the numeric project NUMBER, which `gcloud run`
    rejects — so prefer CANARY_PROJECT_ID and never trust a numeric/empty value.
    """
    p = canary_project_id or project_env or ""
    return default if (not p or p.isdigit()) else p


def _fetch_secret(secret, project):
    """Latest enabled version of a Secret Manager secret (via gcloud)."""
    return subprocess.check_output(
        ["gcloud", "secrets", "versions", "access", "latest",
         "--secret", secret, "--project", project],
        text=True,
    ).strip()


def resolve_key(env_name, secret_env, default_secret, project):
    """A Datadog key from its env var, else from Secret Manager."""
    val = os.environ.get(env_name)
    if val:
        return val
    secret = os.environ.get(secret_env, default_secret)
    try:
        key = _fetch_secret(secret, project)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        raise ConfigError(f"{env_name} not set and Secret Manager fetch of {secret} failed: {e}")
    if not key:
        raise ConfigError(f"{env_name} not set and secret {secret} is empty")
    return key


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
        region = _env("REGION", "us-central1")
        project = pick_project(os.environ.get("CANARY_PROJECT_ID"), os.environ.get("PROJECT"))
        api_key = resolve_key("DD_API_KEY", "DD_API_KEY_SECRET",
                              "humble-shared-stg-datadog-apikey", project)
        app_key = resolve_key("DD_APP_KEY", "DD_APP_KEY_SECRET",
                              "humble-shared-stg-datadog-appkey", project)
        threshold = float(_env("ERROR_RATE_THRESHOLD", "0.05"))
        min_requests = float(_env("MIN_REQUESTS", "20"))
        window = int(_env("WINDOW_SECONDS", "300"))

        revision = _env("REVISION") or newest_revision(service, region, project)
        scope = f"service_name:{service},revision_name:{revision}"

        bake = int(_env("BAKE_SECONDS", "30"))
        poll_timeout = int(_env("POLL_TIMEOUT", "420"))
        poll_interval = int(_env("POLL_INTERVAL", "30"))
        if bake > 0:
            print(f"[canary-verify] initial soak {bake}s...")
            time.sleep(bake)

        # Poll until Datadog has ingested enough data to judge (the GCP integration lags
        # several minutes) or the timeout elapses — THEN judge. A single query after a fixed
        # bake can read an empty window and false-pass a broken canary. Once there are enough
        # requests we stop early; if none arrive by the timeout, evaluate() returns SKIP.
        deadline = time.time() + poll_timeout
        total = errors = 0.0
        while True:
            to = int(time.time())
            frm = to - window
            total = query_metric(site, api_key, app_key,
                                 f"sum:gcp.run.request_count{{{scope}}}.as_count()", frm, to)
            if total >= min_requests:
                errors = query_metric(site, api_key, app_key,
                    f"sum:gcp.run.request_count{{{scope},response_code_class:5xx}}.as_count()", frm, to)
                break
            if time.time() >= deadline:
                break
            print(f"[canary-verify] {total:.0f} requests so far (need {min_requests:.0f}); "
                  f"waiting {poll_interval}s for Datadog to ingest...")
            time.sleep(poll_interval)

        passed, reason = evaluate(total, errors, threshold, min_requests)
        print(f"[canary-verify] {service}@{revision}: {reason}")
        sys.exit(0 if passed else 1)
    except ConfigError as e:
        print(f"[canary-verify] config/credential error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
