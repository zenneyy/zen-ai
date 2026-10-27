"""Four-part structural invariant for the architecture-implied-classes capability.

Item 1.5's improvement is a guarantee that the capability cannot be quietly
removed by a future refactor. It stands on four parts, and this test asserts each
one independently, so deleting any single part fails the build:

* **OWNER** — recon owns *producing* an entry (hypothesis or reasoned dismissal)
  for every architecture-implied class; root owns *ranking* them. Both ownerships
  are carried in the shipped personas / generated CONTRACT.
* **FIELD** — ``inferred_from_architecture`` is a valid hypothesis basis, a
  hypothesis can *name* the class it covers (``vuln_class``, parsed by
  :func:`parse_hypotheses`), and a reasoned dismissal is parseable
  (:func:`parse_dismissed_classes`).
* **GATE** — the completeness-gate function exists and is wired into the
  threat-model save; the closure-gate function exists and is wired into
  ``finish_scan``.
* **PROBE** — the deterministic reasoning-regression probe exists, carries its
  1.6 seam note, and is collectable.

Everything here is class-agnostic.
"""

from __future__ import annotations

import importlib.util
import inspect
from pathlib import Path
from typing import get_args

from zen.agents.contract import render_contract
from zen.tools.agents_graph.contracts import HuntBasis
from zen.tools.finish import tool as finish_tool
from zen.tools.threat_model import tools as tm_tools
from zen.tools.threat_model.schema import (
    HYPOTHESIS_BASIS_VALUES,
    parse_dismissed_classes,
    parse_hypotheses,
)
from zen.utils.resource_paths import get_zen_resource_path


_COORDINATION = get_zen_resource_path("skills") / "coordination"
_PROBE_PATH = Path(__file__).parent / "test_reasoning_regression_probe.py"


# --- OWNER -----------------------------------------------------------------------


def _check_owner() -> None:
    recon_method = (_COORDINATION / "recon_agent.md").read_text(encoding="utf-8")
    root_method = (_COORDINATION / "root_agent.md").read_text(encoding="utf-8")
    recon_contract = render_contract("recon")

    # recon produces the enumeration (method + contract both carry it).
    assert "architecture-implied class" in recon_method
    assert "reasoned dismissal" in recon_method
    assert "architecture-implied class" in recon_contract

    # root ranks the implied classes.
    assert "architecture-implied" in root_method
    assert "ranking" in root_method
    assert "inferred_from_architecture" in root_method


def test_owner_part_present() -> None:
    _check_owner()


# --- FIELD -----------------------------------------------------------------------


def _check_field() -> None:
    # inferred_from_architecture is a valid basis (the grounding for an implied class).
    assert "inferred_from_architecture" in HYPOTHESIS_BASIS_VALUES
    assert "inferred_from_architecture" in get_args(HuntBasis)

    # A hypothesis can name its class, and the parser surfaces it.
    hyps, errors = parse_hypotheses(
        "## Hypotheses\n"
        "- id: H1 | basis: inferred_from_architecture | vuln_class: ssrf | inference_chain: a; b\n"
    )
    assert errors == []
    assert [h.vuln_class for h in hyps] == ["ssrf"]

    # A reasoned dismissal is parseable via the defined convention.
    dismissals, derrors = parse_dismissed_classes(
        "## Dismissed Implied Classes\n"
        "- vuln_class: idor | reason: no object references are exposed\n"
    )
    assert derrors == []
    assert [d.vuln_class for d in dismissals] == ["idor"]

    # An open/blocked hypothesis can carry an inline disposition, parsed and
    # surfaced — the field the finish-time closure gate reads.
    disposed, disp_errors = parse_hypotheses(
        "## Hypotheses\n- id: H1 | basis: assumed | state: blocked | disposition: deferred\n"
    )
    assert disp_errors == []
    assert [h.disposition for h in disposed] == ["deferred"]


def test_field_part_present() -> None:
    _check_field()


# --- GATE ------------------------------------------------------------------------


def _check_gate() -> None:
    # Completeness gate: function exists and is wired into the save path.
    assert callable(tm_tools.unaddressed_implied_classes)
    assert callable(tm_tools._unaddressed_implied_classes)
    assert "_unaddressed_implied_classes" in inspect.getsource(tm_tools._save_impl)

    # Closure gate: function exists and is wired into finish.
    assert callable(finish_tool._undisposed_open_hypotheses)
    assert callable(finish_tool._undisposed_hypotheses_across_run)
    assert "_undisposed_hypotheses_across_run" in inspect.getsource(finish_tool._do_finish)
    # ...and it honors the inline disposition a hypothesis can carry.
    assert "disposition" in inspect.getsource(finish_tool._undisposed_open_hypotheses)


def test_gate_part_present() -> None:
    _check_gate()


# --- PROBE -----------------------------------------------------------------------


def _load_probe() -> object:
    assert _PROBE_PATH.is_file(), "the reasoning-regression probe file must exist"
    spec = importlib.util.spec_from_file_location("zen_probe_under_test", _PROBE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _check_probe() -> None:
    module = _load_probe()
    # Collectable probe functions over real fixtures.
    assert getattr(module, "_PROBES", None), "the probe must define structural fixtures"
    assert callable(getattr(module, "test_structural_class_is_produced", None))
    assert callable(getattr(module, "test_a_model_omitting_the_structural_class_is_flagged", None))
    # The 1.6 seam is documented so it is not silently turned into a live check.
    doc = module.__doc__ or ""
    assert "1.6" in doc
    assert "pass^k" in doc


def test_probe_part_present() -> None:
    _check_probe()


# --- the single four-part invariant ----------------------------------------------


def test_architecture_implied_classes_invariant() -> None:
    """All four parts hold together; removing any one makes this fail."""
    _check_owner()
    _check_field()
    _check_gate()
    _check_probe()
