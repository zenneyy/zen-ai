"""Tests for the architecture (ordered request-path) sibling store."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

import zen.tools.detected_stack.tools as stack_mod


@pytest.fixture(autouse=True)
def _isolate_stores(tmp_path: Path) -> Iterator[None]:
    """Clear the architecture store and point persistence at a temp dir."""
    orig_arch = dict(stack_mod._DETECTED_ARCHITECTURE)
    orig_path = stack_mod._arch_store_path
    stack_mod._DETECTED_ARCHITECTURE.clear()
    stack_mod._arch_store_path = tmp_path / "detected_architecture.json"
    try:
        yield
    finally:
        stack_mod._DETECTED_ARCHITECTURE.clear()
        stack_mod._DETECTED_ARCHITECTURE.update(orig_arch)
        stack_mod._arch_store_path = orig_path


def _identity(target: str) -> str:
    """Derive the canonical identity the same way the store does."""
    from zen.tools.threat_model.tools import _resolve_target, _target_identity

    resolved, _ = _resolve_target(target, [target])
    assert resolved is not None
    return _target_identity(resolved)


# ── register + read ──────────────────────────────────────────────────


def test_register_and_read_preserves_order() -> None:
    hops = [
        {"name": "front", "role": "entry"},
        {"name": "middle", "role": "rewrite"},
        {"name": "back", "role": "handler"},
    ]
    result = stack_mod._register_architecture_impl(
        "https://example.com",
        hops=hops,
        scan_targets=["https://example.com"],
    )
    assert result["success"] is True
    assert result["depth"] == 3

    readback = stack_mod.read_architecture(
        "https://example.com",
        scan_targets=["https://example.com"],
    )
    assert readback == hops, "hop order must be preserved as a sequence"


def test_single_hop_depth_one() -> None:
    stack_mod._register_architecture_impl(
        "https://one.example.com",
        hops=[{"name": "only"}],
        scan_targets=["https://one.example.com"],
    )
    assert (
        stack_mod.architecture_depth(
            "https://one.example.com",
            scan_targets=["https://one.example.com"],
        )
        == 1
    )


def test_depth_equals_node_count() -> None:
    hops = [{"name": f"stage-{i}"} for i in range(5)]
    stack_mod._register_architecture_impl(
        "https://deep.example.com",
        hops=hops,
        scan_targets=["https://deep.example.com"],
    )
    assert (
        stack_mod.architecture_depth(
            "https://deep.example.com",
            scan_targets=["https://deep.example.com"],
        )
        == 5
    )


def test_unregistered_target_returns_empty() -> None:
    assert (
        stack_mod.read_architecture(
            "https://unknown.example.com",
            scan_targets=["https://unknown.example.com"],
        )
        == []
    )
    assert (
        stack_mod.architecture_depth(
            "https://unknown.example.com",
            scan_targets=["https://unknown.example.com"],
        )
        == 0
    )


# ── max_architecture_depth ───────────────────────────────────────────


def test_max_depth_across_targets() -> None:
    stack_mod._register_architecture_impl(
        "https://a.example.com",
        hops=[{"name": "solo"}],
        scan_targets=["https://a.example.com"],
    )
    stack_mod._register_architecture_impl(
        "https://b.example.com",
        hops=[{"name": "f"}, {"name": "m"}, {"name": "b"}],
        scan_targets=["https://b.example.com"],
    )
    targets = ["https://a.example.com", "https://b.example.com"]
    assert stack_mod.max_architecture_depth(targets) == 3


def test_max_depth_no_targets_returns_zero() -> None:
    assert stack_mod.max_architecture_depth([]) == 0


# ── persist + hydrate round-trip ─────────────────────────────────────


def test_persist_and_hydrate_round_trip(tmp_path: Path) -> None:
    hops = [
        {"name": "edge", "role": "tls termination"},
        {"name": "app", "role": "business logic"},
    ]
    stack_mod._arch_store_path = tmp_path / "detected_architecture.json"
    stack_mod._register_architecture_impl(
        "https://rt.example.com",
        hops=hops,
        scan_targets=["https://rt.example.com"],
    )

    saved = json.loads(stack_mod._arch_store_path.read_text(encoding="utf-8"))
    identity = _identity("https://rt.example.com")
    assert identity in saved
    assert saved[identity] == hops

    stack_mod._DETECTED_ARCHITECTURE.clear()
    assert stack_mod.read_architecture(
        "https://rt.example.com",
        scan_targets=["https://rt.example.com"],
    ) == []

    stack_mod.hydrate_architecture_from_disk(tmp_path)
    readback = stack_mod.read_architecture(
        "https://rt.example.com",
        scan_targets=["https://rt.example.com"],
    )
    assert readback == hops, "round-trip must preserve hop order and content"


# ── validation ───────────────────────────────────────────────────────


def test_reject_hops_without_name() -> None:
    result = stack_mod._register_architecture_impl(
        "https://bad.example.com",
        hops=[{"role": "no name field"}],
        scan_targets=["https://bad.example.com"],
    )
    assert result["success"] is False


def test_reject_empty_name() -> None:
    result = stack_mod._register_architecture_impl(
        "https://bad.example.com",
        hops=[{"name": "  "}],
        scan_targets=["https://bad.example.com"],
    )
    assert result["success"] is False


# ── depth gating boundary ────────────────────────────────────────────


def test_depth_gating_boundary() -> None:
    """depth <= 1 should NOT trigger gating; depth > 1 should."""
    stack_mod._register_architecture_impl(
        "https://single.example.com",
        hops=[{"name": "only"}],
        scan_targets=["https://single.example.com"],
    )
    assert stack_mod.max_architecture_depth(["https://single.example.com"]) <= 1

    stack_mod._register_architecture_impl(
        "https://multi.example.com",
        hops=[{"name": "a"}, {"name": "b"}],
        scan_targets=["https://multi.example.com"],
    )
    assert stack_mod.max_architecture_depth(["https://multi.example.com"]) > 1
