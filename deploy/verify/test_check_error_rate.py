"""Offline unit tests for the canary verify decision logic (HBNXT-2108)."""
import check_error_rate as cv


def test_skip_below_min_requests():
    passed, reason = cv.evaluate(total_requests=5, error_requests=5,
                                 threshold=0.05, min_requests=20)
    assert passed is True
    assert "SKIP" in reason


def test_pass_within_threshold():
    passed, reason = cv.evaluate(total_requests=1000, error_requests=10,
                                 threshold=0.05, min_requests=20)
    assert passed is True
    assert "PASS" in reason


def test_fail_over_threshold():
    passed, reason = cv.evaluate(total_requests=1000, error_requests=200,
                                 threshold=0.05, min_requests=20)
    assert passed is False
    assert "FAIL" in reason


def test_boundary_equal_threshold_passes():
    # exactly at threshold is not a breach (> is the gate)
    passed, _ = cv.evaluate(total_requests=100, error_requests=5,
                            threshold=0.05, min_requests=20)
    assert passed is True


def test_zero_errors_passes():
    passed, reason = cv.evaluate(total_requests=500, error_requests=0,
                                 threshold=0.05, min_requests=20)
    assert passed is True
    assert "0.00%" in reason


def test_sum_series_handles_nulls_and_empty():
    body = {"series": [{"pointlist": [[1, 3.0], [2, None], [3, 4.0]]}]}
    assert cv._sum_series(body) == 7.0
    assert cv._sum_series({"series": []}) == 0.0
    assert cv._sum_series({}) == 0.0


def test_sum_series_multiple_series():
    body = {"series": [
        {"pointlist": [[1, 2.0]]},
        {"pointlist": [[1, 5.0], [2, 1.0]]},
    ]}
    assert cv._sum_series(body) == 8.0
