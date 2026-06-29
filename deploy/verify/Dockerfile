# Canary verify container (HBNXT-2108). Run as a Cloud Deploy / skaffold `verify`
# action: queries Datadog for the new revision's 5xx rate and exits non-zero on a
# breach, tripping the Cloud Deploy automation rollback rule.
# gcloud is needed for the default newest-revision lookup; the slim SDK image
# already bundles it and python3 (stdlib-only script — no pip deps).
FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:slim
WORKDIR /verify
COPY check_error_rate.py .
ENTRYPOINT ["python3", "check_error_rate.py"]
