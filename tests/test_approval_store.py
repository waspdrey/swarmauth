from concurrent.futures import ThreadPoolExecutor

import pytest

import swarmauth


def test_sqlite_approval_store_survives_restart_and_is_single_use(tmp_path) -> None:
    path = str(tmp_path / "approvals.db")
    request = swarmauth.ApprovalRequest(
        request_id="req-1",
        action="deploy",
        capability="prod:deploy",
        subject="agent:release",
        requester="release",
        summary="Deploy",
        expires_at=200,
    )
    first = swarmauth.SQLiteApprovalStore(path)
    first.create(request)
    first.close()
    second = swarmauth.SQLiteApprovalStore(path)
    assert second.get("req-1") == request
    assert second.decide("req-1", "approved", "alice", 101).status == "approved"
    with pytest.raises(swarmauth.ApprovalStateError):
        second.decide("req-1", "rejected", "bob", 102)
    second.close()


def test_sqlite_approval_store_allows_only_one_concurrent_decision(tmp_path) -> None:
    path = str(tmp_path / "race.db")
    seed = swarmauth.SQLiteApprovalStore(path)
    seed.create(
        swarmauth.ApprovalRequest(
            request_id="race",
            action="deploy",
            capability="prod:deploy",
            subject="agent:release",
            requester="release",
            summary="Deploy",
            expires_at=200,
        )
    )
    seed.close()
    stores = [swarmauth.SQLiteApprovalStore(path), swarmauth.SQLiteApprovalStore(path)]

    def decide(index: int):
        try:
            return stores[index].decide("race", "approved", f"reviewer-{index}", 101)
        except swarmauth.ApprovalStateError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(decide, (0, 1)))
    assert sum(result is not None for result in results) == 1
    assert sum(result is None for result in results) == 1
    for store in stores:
        store.close()
