"""F2: lockout without DoS - per (user, client) throttle, global backoff, bounded size, persistence."""
import json
import approvers


def _add():
    approvers.add("erin", "erin-password-12")


def test_bad_attempts_from_one_ip_do_not_lock_user_elsewhere():
    _add()
    for _ in range(approvers.MAX_FAILS):
        assert approvers.verify_password("erin", "wrong", "10.0.0.1") is None
    assert approvers.verify_password("erin", "erin-password-12", "10.0.0.1") is None  # locked here
    assert approvers.verify_password("erin", "erin-password-12", "10.0.0.2")["user"] == "erin"


def test_global_backoff_across_many_ips():
    _add()
    n = 0
    ip = 0
    while n < approvers.GLOBAL_MAX_FAILS:
        for _ in range(approvers.MAX_FAILS - 1):  # stay under the per-IP limit
            if n >= approvers.GLOBAL_MAX_FAILS:
                break
            approvers.verify_password("erin", "wrong", f"10.1.0.{ip}")
            n += 1
        ip += 1
    assert approvers._throttled("erin", "10.9.9.9")
    assert approvers.verify_password("erin", "erin-password-12", "10.9.9.9") is None
    g = approvers._FAILS[approvers._gkey("erin")]
    assert approvers.GLOBAL_BASE_S - 2 <= g[1] - g[2] <= approvers.GLOBAL_CAP_S


def test_backoff_grows_and_is_capped():
    _add()
    for strike in range(1, 8):
        for _ in range(approvers.GLOBAL_MAX_FAILS):
            approvers._fail("erin", f"c{strike}-{_}")
        g = approvers._FAILS[approvers._gkey("erin")]
        assert g[3] == strike
        assert round(g[1] - g[2]) == min(approvers.GLOBAL_CAP_S, approvers.GLOBAL_BASE_S * 2 ** (strike - 1))


def test_fails_dict_is_bounded(monkeypatch):
    monkeypatch.setattr(approvers, "MAX_ENTRIES", 50)
    for i in range(300):
        approvers._fail(f"u{i}", "1.1.1.1")
    assert len(approvers._FAILS) <= 50


def test_counters_survive_restart():
    _add()
    for _ in range(approvers.MAX_FAILS):
        approvers.verify_password("erin", "wrong", "10.0.0.7")
    data = json.loads(approvers.throttle_path().read_text())
    assert any(k.startswith("erin|10.0.0.7") for k in data)
    approvers._FAILS.clear()
    approvers._LOADED["path"] = None  # simulate a fresh process
    assert approvers._throttled("erin", "10.0.0.7")
    assert not approvers._throttled("erin", "10.0.0.8")


def test_unreadable_throttle_file_starts_empty():
    approvers.throttle_path().write_text("{not json")
    approvers._LOADED["path"] = None
    assert not approvers._throttled("erin", "x")


def test_success_clears_only_that_client():
    _add()
    approvers.verify_password("erin", "wrong", "a")
    approvers.verify_password("erin", "wrong", "b")
    approvers.verify_password("erin", "erin-password-12", "a")
    assert approvers._key("erin", "a") not in approvers._FAILS
    assert approvers._FAILS[approvers._key("erin", "b")][0] == 1
