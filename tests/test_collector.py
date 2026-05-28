"""Tests for system snapshot collection."""

from collector import get_system_snapshot, snapshot_to_dict


def test_system_snapshot_contains_system_info_contract_fields():
    snapshot = snapshot_to_dict(get_system_snapshot())

    assert snapshot["hostname"]
    assert snapshot["platform"] in {"Linux", "Windows", "Darwin"}
    assert snapshot["os"]
    assert snapshot["kernel"]
    assert snapshot["uptime"] >= 0.0
