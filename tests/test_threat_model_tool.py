"""Tests for the run-scoped threat model store."""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from typing import TYPE_CHECKING

import pytest

from zen.agents.factory import _BASE_TOOLS
from zen.tools.threat_model import tools as threat_model_tools
from zen.tools.threat_model.tools import (
    _amend_impl,
    _get_impl,
    _save_impl,
    amend_threat_model,
    get_threat_model,
    hydrate_threat_models_from_disk,
    save_threat_model,
)


if TYPE_CHECKING:
    from pathlib import Path


_MODEL = """# Threat Model

## Overview
A multi-tenant billing API. Product code lives in `api/`; `scripts/` is
developer-only tooling and is not deployed.

## Architecture
Requests traverse a reverse proxy at the edge before reaching the application
server. The proxy terminates TLS and forwards the tenant-scoped session to
the application layer, which dispatches to per-resource handlers.

## Trust Boundaries and Assumptions
Requests arrive from untrusted tenants through `api/router.py`. The tenant id
is taken from the signed session, never from the request body. Operators
configure webhooks; developers control migrations.

## Observations
The public REST surface and the webhook receiver are attacker-reachable.
The tenant id is bound to the signed session and is not accepted from
request parameters. Local CLI tooling is not deployed.

## Hypotheses
A tenant may be able to read another tenant's invoices by manipulating
resource identifiers in API calls (grounded: the REST surface accepts
a resource id path parameter observed during enumeration). Local CLI
tooling is not a realistic attack surface (assumed: no evidence of
deployment).

## Severity Calibration
Critical: cross-tenant write. High: cross-tenant read. Medium: authenticated
self-scoped information leak. Low: verbose errors.
"""


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["/usr/bin/env", "git", *args], cwd=repo, check=True)  # noqa: S603


def _make_repo(tmp_path: Path, name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    (repo / "README.md").write_text("hi\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-qm", "init")
    return repo


@pytest.fixture(autouse=True)
def _empty_store() -> None:
    """Each test is its own run, so it starts with an empty, unmirrored store."""
    threat_model_tools._MODELS.clear()
    threat_model_tools._store_path = None


def test_missing_model_reports_not_found(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)

    result = _get_impl(str(repo))

    assert result["success"] is True
    assert result["found"] is False
    assert "save_threat_model" in result["message"]


def test_saved_model_round_trips(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)

    assert _save_impl(str(repo), _MODEL, "Zen")["success"] is True
    result = _get_impl(str(repo))

    assert result["found"] is True
    assert "multi-tenant billing API" in result["content"]


def test_nothing_is_written_outside_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The model must not outlive the scan, so nothing may land in the home dir."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    repo = _make_repo(tmp_path)

    _save_impl(str(repo), _MODEL, "root")
    _amend_impl(str(repo), _ADDENDUM, "agent-a")

    assert list(home.rglob("*")) == []


def test_a_new_run_starts_without_the_model(tmp_path: Path) -> None:
    """A later scan of the same target inherits nothing from this one."""
    repo = _make_repo(tmp_path)
    hydrate_threat_models_from_disk(tmp_path / "first-run")
    _save_impl(str(repo), _MODEL, "root")

    hydrate_threat_models_from_disk(tmp_path / "second-run")  # a different scan

    assert _get_impl(str(repo))["found"] is False


def test_resuming_the_same_run_keeps_the_model(tmp_path: Path) -> None:
    """A resumed scan is the same scan, so its agents keep the shared baseline."""
    state_dir = tmp_path / "state"
    repo = _make_repo(tmp_path)
    hydrate_threat_models_from_disk(state_dir)
    _save_impl(str(repo), _MODEL, "root")
    _amend_impl(str(repo), _ADDENDUM, "agent-a")

    threat_model_tools._MODELS.clear()  # what the resuming process starts from
    hydrate_threat_models_from_disk(state_dir)

    result = _get_impl(str(repo))
    assert result["found"] is True
    assert [a["content"] for a in result["amendments"]] == [_ADDENDUM]


def test_model_survives_a_new_revision_within_the_run(tmp_path: Path) -> None:
    """The model is not pinned to a revision; a commit mid-run does not drop it."""
    repo = _make_repo(tmp_path)
    _save_impl(str(repo), _MODEL, None)

    (repo / "next.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", "next.py")
    _git(repo, "commit", "-qm", "next")

    result = _get_impl(str(repo))

    assert result["found"] is True
    assert "multi-tenant billing API" in result["content"]


def test_store_is_keyed_per_repository(tmp_path: Path) -> None:
    first = _make_repo(tmp_path, "first")
    second = _make_repo(tmp_path, "second")
    _save_impl(str(first), _MODEL, None)

    assert _get_impl(str(second))["found"] is False


def test_rejects_model_missing_required_sections(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    thin = _MODEL.replace("## Severity Calibration", "## Notes")

    result = _save_impl(str(repo), thin, None)

    assert result["success"] is False
    assert "missing required section" in result["error"]
    assert "severity calibration" in result["error"]


def test_rejects_stub_model(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)

    result = _save_impl(str(repo), "overview trust boundaries attack surface hypotheses", None)

    assert result["success"] is False
    assert "too thin" in result["error"]


def test_rejects_empty_target() -> None:
    result = _get_impl("   ")
    assert result["success"] is False
    assert "target cannot be empty" in result["error"]


def test_tools_are_registered() -> None:
    assert get_threat_model in _BASE_TOOLS
    assert save_threat_model in _BASE_TOOLS


_ADDENDUM = (
    "The base model calls the webhook receiver operator-controlled. It is "
    "unauthenticated in `api/webhooks.py:31`, so treat its body as attacker-controlled."
)


def test_amendment_is_returned_with_the_model(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    _save_impl(str(repo), _MODEL, "root")

    assert _amend_impl(str(repo), _ADDENDUM, "webhook-agent")["success"] is True
    result = _get_impl(str(repo))

    assert result["content"] == _MODEL.strip()
    assert [a["content"] for a in result["amendments"]] == [_ADDENDUM]
    assert result["amendments"][0]["by"] == "webhook-agent"


def test_amendments_accumulate_without_overwriting(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    _save_impl(str(repo), _MODEL, "root")

    _amend_impl(str(repo), _ADDENDUM, "agent-a")
    second = "The `scripts/` directory ships in the container image; it is not dev-only."
    _amend_impl(str(repo), second + " See `Dockerfile:14`.", "agent-b")

    amendments = _get_impl(str(repo))["amendments"]
    assert len(amendments) == 2
    assert [a["by"] for a in amendments] == ["agent-a", "agent-b"]


def test_amend_requires_an_existing_model(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)

    result = _amend_impl(str(repo), _ADDENDUM, None)

    assert result["success"] is False
    assert "save_threat_model" in result["error"]


def test_amend_rejects_a_stub(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    _save_impl(str(repo), _MODEL, "root")

    assert _amend_impl(str(repo), "looks wrong", None)["success"] is False


def test_save_clears_amendments_and_says_so(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    _save_impl(str(repo), _MODEL, "root")
    _amend_impl(str(repo), _ADDENDUM, "agent-a")

    result = _save_impl(str(repo), _MODEL.replace("billing API", "billing service"), "root")

    assert result["amendments_cleared"] == 1
    assert "cleared" in result["message"]
    assert "amendments" not in _get_impl(str(repo))


def test_amend_tool_is_registered() -> None:
    assert amend_threat_model in _BASE_TOOLS


_BLACKBOX_MODEL = _MODEL.replace(
    "Product code lives in `api/`; `scripts/` is\ndeveloper-only tooling and is not deployed.",
    "Only the deployed surface is visible; no source. Inferred from recon.",
)


def test_blackbox_target_round_trips() -> None:
    target = "https://app.example.com"

    assert _save_impl(target, _BLACKBOX_MODEL, "recon")["success"] is True
    result = _get_impl(target)

    assert result["found"] is True
    assert "Inferred from recon" in result["content"]


def test_blackbox_target_spellings_share_one_model() -> None:
    _save_impl("https://App.Example.com:443/", _BLACKBOX_MODEL, "recon")

    for spelling in ("https://app.example.com", "app.example.com", "https://app.example.com/"):
        assert _get_impl(spelling)["found"] is True, spelling

    assert _get_impl("https://other.example.com")["found"] is False


def test_blackbox_target_can_be_amended() -> None:
    target = "https://app.example.com"
    _save_impl(target, _BLACKBOX_MODEL, "recon")

    addendum = (
        "The model infers /admin is IP-restricted. It is reachable with any "
        "authenticated session; the restriction is only on /admin/settings."
    )
    assert _amend_impl(target, addendum, "authz-agent")["success"] is True
    assert _get_impl(target)["amendments"][0]["content"] == addendum


def test_checkout_and_its_remote_are_the_same_target(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    _git(repo, "remote", "add", "origin", "https://github.com/acme/billing.git")
    _save_impl(str(repo), _MODEL, "root")

    clone = _make_repo(tmp_path, "clone")
    _git(clone, "remote", "add", "origin", "https://github.com/acme/billing.git")

    assert _get_impl(str(clone))["found"] is True


def test_path_on_a_known_host_resolves_to_the_scan_target() -> None:
    scan_targets = ["https://app.example.com"]
    _save_impl("https://app.example.com", _BLACKBOX_MODEL, "root", scan_targets)

    # An agent testing one page names that page, not the scan's target string.
    assert _get_impl("https://app.example.com/admin/login", scan_targets)["found"] is True


def test_two_scan_targets_on_one_host_stay_separate() -> None:
    scan_targets = ["https://example.com/tenant-a", "https://example.com/tenant-b"]
    _save_impl("https://example.com/tenant-a", _BLACKBOX_MODEL, "root", scan_targets)

    assert _get_impl("https://example.com/tenant-b", scan_targets)["found"] is False


def test_unknown_host_is_not_snapped_onto_the_scan_target() -> None:
    scan_targets = ["https://app.example.com"]
    _save_impl("https://app.example.com", _BLACKBOX_MODEL, "root", scan_targets)

    assert _get_impl("https://unrelated.test", scan_targets)["found"] is False


def test_empty_target_falls_back_to_a_single_scan_target() -> None:
    scan_targets = ["https://app.example.com"]
    _save_impl("", _BLACKBOX_MODEL, "root", scan_targets)

    assert _get_impl("", scan_targets)["found"] is True
    assert _get_impl("https://app.example.com")["found"] is True


def test_repository_subdirectory_shares_the_repository_model(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    (repo / "src").mkdir()
    _save_impl(str(repo), _MODEL, "root")

    assert _get_impl(str(repo / "src"))["found"] is True


def test_checkout_and_its_clone_url_are_one_identity(tmp_path: Path) -> None:
    """The model an agent saves inside the checkout must be visible to an agent
    that names the same repository by the URL it was cloned from."""
    repo = _make_repo(tmp_path)
    _git(repo, "remote", "add", "origin", "https://github.com/acme/billing.git")
    _save_impl(str(repo), _MODEL, "root")

    assert _get_impl("https://github.com/acme/billing")["found"] is True
    assert _get_impl("https://github.com/acme/billing.git")["found"] is True


def test_ssh_and_https_remotes_are_one_identity(tmp_path: Path) -> None:
    """One repository cloned over scp-style SSH and over HTTPS is one target."""
    over_ssh = _make_repo(tmp_path, "ssh-clone")
    _git(over_ssh, "remote", "add", "origin", "git@github.com:acme/billing.git")
    _save_impl(str(over_ssh), _MODEL, "root")

    over_https = _make_repo(tmp_path, "https-clone")
    _git(over_https, "remote", "add", "origin", "https://github.com/acme/billing.git")

    assert _get_impl(str(over_https))["found"] is True


def test_different_repositories_on_one_host_stay_separate(tmp_path: Path) -> None:
    first = _make_repo(tmp_path, "billing")
    _git(first, "remote", "add", "origin", "git@github.com:acme/billing.git")
    _save_impl(str(first), _MODEL, "root")

    second = _make_repo(tmp_path, "payments")
    _git(second, "remote", "add", "origin", "git@github.com:acme/payments.git")

    assert _get_impl(str(second))["found"] is False


# ── discovery gate for indirectly-reached services ──────────────────


@pytest.fixture()
def _isolate_command_and_arch_stores() -> Iterator[None]:
    """Clear the command log and architecture store for each gate test."""
    import zen.tools.command_log.tools as cmd_mod
    import zen.tools.detected_stack.tools as stack_mod

    orig_log = list(cmd_mod._COMMAND_LOG)
    orig_path = cmd_mod._store_path
    orig_arch = dict(stack_mod._DETECTED_ARCHITECTURE)
    orig_arch_path = stack_mod._arch_store_path

    cmd_mod._COMMAND_LOG.clear()
    cmd_mod._store_path = None
    stack_mod._DETECTED_ARCHITECTURE.clear()
    stack_mod._arch_store_path = None
    try:
        yield
    finally:
        cmd_mod._COMMAND_LOG.clear()
        cmd_mod._COMMAND_LOG.extend(orig_log)
        cmd_mod._store_path = orig_path
        stack_mod._DETECTED_ARCHITECTURE.clear()
        stack_mod._DETECTED_ARCHITECTURE.update(orig_arch)
        stack_mod._arch_store_path = orig_arch_path


_GATE_MODEL = """\
# Threat Model

## Overview
Only the deployed surface is visible; no source. Inferred from recon.

## Architecture
Requests traverse an edge service before reaching the application handler.

## Trust Boundaries and Assumptions
Requests arrive from untrusted clients through the edge service. Sessions
are validated at the edge; the internal backend trusts the forwarded identity.

## Observations
The public-facing edge service and its forwarded requests to the internal
backend are attacker-reachable. The edge service terminates TLS and
forwards tenant-scoped sessions to the backend.

## Hypotheses
An attacker may reach internal endpoints that the edge does not expose
directly by targeting the forwarding path (grounded: the multi-hop
architecture was observed during probing). Verbose error responses from
the backend may leak internal structure (assumed: not yet observed).

## Severity Calibration
Critical: unauthenticated access to internal services. High: data leakage
across trust boundaries. Medium: verbose errors exposing internals.
"""


def test_gate_rejects_when_indirect_service_has_no_discovery(
    _isolate_command_and_arch_stores: None,
) -> None:
    import zen.tools.detected_stack.tools as stack_mod

    # Rehomed from the original 2-hop [edge-service, internal-backend] shape:
    # there, hop[1] was the exempt primary application (edge-targeted discovery
    # covers its routes), not a genuine indirect backend, so it no longer
    # exercises the rejection path. internal-backend now sits AFTER the primary
    # application (app-service), where an unprobed indirect backend is flagged.
    stack_mod._register_architecture_impl(
        "https://app.example.com",
        hops=[
            {"name": "edge-service", "role": "entry point"},
            {"name": "app-service", "role": "application framework"},
            {"name": "internal-backend", "role": "backend service"},
        ],
        scan_targets=["https://app.example.com"],
    )

    result = _save_impl(
        "https://app.example.com", _GATE_MODEL, "root",
        scan_targets=["https://app.example.com"],
    )

    assert result["success"] is False
    assert "indirectly-reached service" in result["error"]


def test_gate_passes_when_discovery_command_was_run(
    _isolate_command_and_arch_stores: None,
) -> None:
    import zen.tools.command_log.tools as cmd_mod
    import zen.tools.detected_stack.tools as stack_mod

    stack_mod._register_architecture_impl(
        "https://app.example.com",
        hops=[
            {"name": "edge-service", "role": "entry point"},
            {"name": "internal-backend", "role": "application handler"},
        ],
        scan_targets=["https://app.example.com"],
    )
    cmd_mod.record_command(
        "feroxbuster -u http://internal-backend:8080 "
        "-w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
    )

    result = _save_impl(
        "https://app.example.com", _GATE_MODEL, "root",
        scan_targets=["https://app.example.com"],
    )

    assert result["success"] is True


def test_gate_ignores_single_hop_architecture(
    _isolate_command_and_arch_stores: None,
) -> None:
    import zen.tools.detected_stack.tools as stack_mod

    stack_mod._register_architecture_impl(
        "https://app.example.com",
        hops=[{"name": "only-service", "role": "standalone"}],
        scan_targets=["https://app.example.com"],
    )

    result = _save_impl(
        "https://app.example.com", _GATE_MODEL, "root",
        scan_targets=["https://app.example.com"],
    )

    assert result["success"] is True


# ── primary-application exemption (regression + audit cases) ─────────
#
# The discovery gate must exempt the primary application — the first
# non-infrastructure hop, whose route surface edge-targeted discovery
# already covers — while still flagging every genuine indirect backend
# behind it. These pin the four real-world architectures from the ee25
# audit plus the structural edges, asserting the exact list
# _unenumerated_indirect_services() returns ([] == the save is accepted).


def _flagged(hops: list[dict[str, str]]) -> list[str]:
    """Register *hops* as the sole architecture and return the gate's flag list."""
    import zen.tools.detected_stack.tools as stack_mod

    stack_mod._DETECTED_ARCHITECTURE.clear()
    stack_mod._DETECTED_ARCHITECTURE["https://app.example.com"] = hops
    return threat_model_tools._unenumerated_indirect_services()


def test_primary_app_misclassification_does_not_return(
    _isolate_command_and_arch_stores: None,
) -> None:
    """ee25 Arch 2 [apache, flask] (depth 2, empty command log) — and the
    regression guard for the bug this fix removes.

    apache is the edge reverse proxy; flask is the primary application. The
    original gate flagged flask because the literal "flask" never appears in
    the ffuf/curl commands run against the edge URL, which blocked the entire
    ee25 run. The primary application must now be exempt, so nothing is flagged
    and the save is accepted.
    """
    assert _flagged([
        {"name": "apache", "role": "reverse proxy"},
        {"name": "flask", "role": "application framework"},
    ]) == []


def test_gate_flags_backends_after_primary_app_ee25_arch1(
    _isolate_command_and_arch_stores: None,
) -> None:
    """ee25 Arch 1 (depth 6, empty command log): flask is exempt as the primary
    application; the two unprobed backends behind it stay flagged, while the
    intervening proxies (haproxy, mitmproxy) are infrastructure. flask must NOT
    appear in the list."""
    flagged = _flagged([
        {"name": "apache", "role": "reverse proxy"},
        {"name": "flask", "role": "application framework"},
        {"name": "curl-subprocess", "role": "server-side HTTP client"},
        {"name": "haproxy", "role": "load balancer"},
        {"name": "mitmproxy", "role": "intercepting proxy"},
        {"name": "wifi_chipset-backend", "role": "device backend service"},
    ])
    assert flagged == ["curl-subprocess", "wifi_chipset-backend"]
    assert "flask" not in flagged


def test_gate_flags_backends_after_primary_app_1b79(
    _isolate_command_and_arch_stores: None,
) -> None:
    """1b79 baseline (depth 6, flask-app at hop[1], empty command log): the
    primary application is exempt; the HTTP client and internal router behind
    it are flagged."""
    assert _flagged([
        {"name": "apache-edge", "role": "reverse proxy"},
        {"name": "flask-app", "role": "application framework"},
        {"name": "curl-client", "role": "server-side HTTP client"},
        {"name": "haproxy", "role": "load balancer"},
        {"name": "mitmproxy", "role": "intercepting proxy"},
        {"name": "internal.router", "role": "internal service router"},
    ]) == ["curl-client", "internal.router"]


def test_gate_flags_backend_after_leading_infra_chain_4f58(
    _isolate_command_and_arch_stores: None,
) -> None:
    """4f58 baseline (depth 5, three leading infra hops, flask-app at hop[3],
    empty command log): the leading run of infrastructure is skipped, flask-app
    is the exempt primary application, and only the internal router behind it is
    flagged."""
    assert _flagged([
        {"name": "apache-frontend", "role": "reverse proxy"},
        {"name": "haproxy", "role": "load balancer"},
        {"name": "mitmproxy", "role": "intercepting proxy"},
        {"name": "flask-app", "role": "application framework"},
        {"name": "internal.router", "role": "internal service router"},
    ]) == ["internal.router"]


def test_gate_accepts_architecture_of_only_infrastructure(
    _isolate_command_and_arch_stores: None,
) -> None:
    """No non-infrastructure hop exists, so there is no primary application and
    nothing to enumerate; the walk finds no primary and exits cleanly."""
    assert _flagged([
        {"name": "apache", "role": "reverse proxy"},
        {"name": "haproxy", "role": "load balancer"},
        {"name": "mitmproxy", "role": "intercepting proxy"},
    ]) == []


def test_gate_accepts_single_infrastructure_hop(
    _isolate_command_and_arch_stores: None,
) -> None:
    """A lone infrastructure hop has no primary application behind it, so
    nothing is flagged."""
    assert _flagged([{"name": "apache", "role": "reverse proxy"}]) == []


def test_gate_accepts_single_primary_application_hop(
    _isolate_command_and_arch_stores: None,
) -> None:
    """A lone non-infrastructure hop is itself the primary application; it is
    exempt and no hop follows it, so nothing is flagged."""
    assert _flagged([{"name": "flask", "role": "application framework"}]) == []
