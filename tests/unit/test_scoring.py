from datetime import datetime, timezone, timedelta

from opensurity.delegation.scoring import compute_score
from opensurity.log.events import TrustEvent


def create_mock_event(outcome: str, cap: str, age_days: int) -> TrustEvent:
    timestamp = (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat().replace("+00:00", "Z")
    return TrustEvent(
        version="0.1",
        agent="agent-1",
        delegator="delegator-1",
        task_hash="hash",
        capability_used=cap,
        outcome=outcome,
        duration_ms=100,
        timestamp=timestamp,
        prev_cid=None
    )


def test_scoring_no_events():
    assert compute_score([], "cap-a") == 0.5


def test_scoring_perfect_recent():
    events = [
        create_mock_event("success", "cap-target", 10),
        create_mock_event("success", "cap-target", 20)
    ]
    # score = (2/2) * 1.0 (recency) * 1.0 (cap match) = 1.0
    assert compute_score(events, "cap-target") == 1.0


def test_scoring_perfect_but_wrong_capability():
    events = [
        create_mock_event("success", "cap-other", 10),
        create_mock_event("success", "cap-other", 20)
    ]
    # score = (2/2) * 1.0 (recency) * 0.7 (cap match) = 0.7
    assert compute_score(events, "cap-target") == 0.7


def test_scoring_with_failures():
    events = [
        create_mock_event("success", "cap-target", 10),
        create_mock_event("failure", "cap-target", 20)
    ]
    # score = (1/2) * 1.0 * 1.0 = 0.5
    assert compute_score(events, "cap-target") == 0.5


def test_scoring_decay():
    # 60 days old (past 30-day window) -> decay starts
    events = [
        create_mock_event("success", "cap-target", 60)
    ]
    # Age is 60. Window is 30. Decay period is 60.
    # decay = (60 - 30) / 60 = 0.5
    # weight = max(0.5, 1.0 - 0.5 * 0.5) = max(0.5, 0.75) = 0.75
    # score = (1/1) * 0.75 * 1.0 = 0.75
    score = compute_score(events, "cap-target")
    assert 0.74 < score < 0.76  # allow tiny float differences
