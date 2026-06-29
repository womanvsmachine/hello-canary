"""Offline unit tests for the canary verify decision logic (HBNXT-2108)."""
import check_error_rate as cv


# --- project resolution ---
def test_pick_project_prefers_canary_id():
    assert cv.pick_project("humblebundle-stg", "631460809730") == "humblebundle-stg"


def test_pick_project_rejects_numeric_project():
    # Cloud Deploy injects the numeric project number into PROJECT — must fall back.
    assert cv.pick_project(None, "631460809730") == "humblebundle-stg"


def test_pick_project_uses_nonnumeric_project_env():
    assert cv.pick_project(None, "some-other-proj") == "some-other-proj"


def test_pick_project_empty_falls_back():
    assert cv.pick_project(None, None) == "humblebundle-stg"


# --- decision logic ---
def test_skip_below_min_requests():
    passed, reason = cv.evaluate(5, 5, threshold=0.05, min_requests=10)
    assert passed is True and "SKIP" in reason


def test_pass_within_threshold():
    passed, reason = cv.evaluate(1000, 10, threshold=0.05, min_requests=10)
    assert passed is True and "PASS" in reason


def test_fail_over_threshold():
    passed, reason = cv.evaluate(1000, 200, threshold=0.05, min_requests=10)
    assert passed is False and "FAIL" in reason


def test_boundary_equal_threshold_passes():
    passed, _ = cv.evaluate(100, 5, threshold=0.05, min_requests=10)
    assert passed is True


def test_zero_errors_passes():
    passed, reason = cv.evaluate(500, 0, threshold=0.05, min_requests=10)
    assert passed is True and "0.00%" in reason


# --- Cloud Monitoring response summing ---
def test_sum_points_int_and_double():
    body = {"timeSeries": [
        {"points": [{"value": {"int64Value": "3"}}, {"value": {"doubleValue": 4.0}}]},
        {"points": [{"value": {"int64Value": "5"}}]},
    ]}
    assert cv._sum_points(body) == 12.0


def test_sum_points_empty():
    assert cv._sum_points({"timeSeries": []}) == 0.0
    assert cv._sum_points({}) == 0.0
