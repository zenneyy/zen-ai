"""Architecture → candidate vulnerability-class mapping (the forcing function).

Some attack classes are reachable only by *inference from structure* — the shape
of the system implies them, but no surface for them was ever directly observed.
A prior regression let exactly those classes fall out of the hypothesis set, so
they were never hunted. This module is the structural half of the fix: given the
documented architecture (the ordered component hops and the boundaries between
them), it enumerates the vulnerability-class families a senior researcher would
treat as *implied by that structure*, each tagged with the component or boundary
that implied it. The completeness gate (:mod:`zen.tools.threat_model.tools`) then
refuses to accept a threat model that neither hypothesizes nor explicitly
dismisses an implied class.

The mapping is **generic and class-agnostic**. It is not motivated by, and does
not special-case, any single technique, scenario, or target shape. It keys on
*structural kinds* only — what a component does to data passing through it, and
what transition each boundary between two adjacent components represents — and
draws every class name from :func:`zen.skills.get_vulnerability_class_names`
(the shipped catalog), never a hand-maintained list. The class slugs it emits
(``ssrf``, ``idor``, ``sql_injection``, …) are catalog identifiers used as data;
the human-readable *reasons* describe structure in general terms.

The structural properties it reasons over, each mapped to the class families a
researcher would infer from it:

* what a component does to a request/response as it passes through — parsing,
  normalization, decoding, rewriting, policy evaluation;
* what trust transition a boundary represents — a privilege, tenant,
  network-zone, or parser-authority change between two adjacent components that
  may interpret the same input differently, or where the downstream trusts an
  identity or decision the upstream forwarded;
* which components make authentication or authorization decisions;
* which components originate requests on behalf of a caller, or are reachable
  only indirectly through another component's server-side behavior;
* which components deserialize, template, or otherwise interpret
  caller-influenced data;
* which components front durable state.

``basis`` lives elsewhere: an implied class is carried as an
``inferred_from_architecture`` hypothesis, but that word is *evidentiary
grounding*, never a difficulty tier. Every implied class admits the full
spectrum of research depth, from a first-pass confirmation to original
technique; nothing here caps that.
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from zen.skills import get_vulnerability_class_names


# ── the structural reason attached to each implied class ─────────────────────


@dataclass(frozen=True)
class Reason:
    """Why a class is implied: the component or boundary, and the full sentence.

    ``source`` is the thing that implied the class — a component ``name`` or an
    ``"A <-> B"`` boundary label — so a gate rejection can name it. ``text`` is
    the complete structural sentence, phrased generically.
    """

    source: str
    text: str


# ── matching a hop's structural kind from its free-text name/role ────────────
#
# A hop is a dict with at least ``name`` and an optional ``role`` (see
# detected_stack._DETECTED_ARCHITECTURE). Recon writes those fields as free
# prose, so a structural kind is recognised by keywords over ``name + role``.
# Two match modes keep that recognition from misfiring on short, ambiguous
# fragments: a *phrase* (multi-word or distinctive stem) matches as a substring,
# while a short *token* (``db``, ``ai``, ``ci``) matches only as a whole word, so
# ``ai`` never fires on ``email`` and ``db`` never fires on ``adbx``.

_WORD_RE = re.compile(r"[a-z0-9]+")


def _hop_text(hop: Mapping[str, str]) -> str:
    name = str(hop.get("name", ""))
    role = str(hop.get("role", ""))
    return f"{name} {role}".lower()


def _matches(text: str, *, phrases: frozenset[str], tokens: frozenset[str]) -> bool:
    if any(phrase in text for phrase in phrases):
        return True
    if not tokens:
        return False
    words = set(_WORD_RE.findall(text))
    return bool(tokens & words)


@dataclass(frozen=True)
class _ComponentKind:
    """A structural kind recognised on a single component hop."""

    label: str
    phrases: frozenset[str]
    tokens: frozenset[str]
    classes: tuple[str, ...]
    reason: str  # "{component}" placeholder

    def implied(self, hop: Mapping[str, str]) -> bool:
        return _matches(_hop_text(hop), phrases=self.phrases, tokens=self.tokens)


@dataclass(frozen=True)
class _BoundaryKind:
    """A structural kind recognised on an ordered pair of adjacent components."""

    label: str
    classes: tuple[str, ...]
    reason: str  # "{upstream}"/"{downstream}" placeholders
    # How the boundary fires: ``upstream_transforms`` requires the upstream hop to
    # be a transforming/parsing intermediary (a parser-authority boundary);
    # ``downstream_handles`` requires the downstream hop to be a non-infrastructure
    # handler/store (a trust transition into something that enforces or interprets).
    upstream_transforms: bool = False
    downstream_handles: bool = False


# ── the transforming-intermediary predicate (shared) ─────────────────────────
#
# A component that parses, normalizes, decodes, rewrites, caches, or applies a
# policy to traffic passing *through* it. It is the "infrastructure" kind for the
# baseline gate (such a hop is not an application request-handler) and the
# upstream side of a parser-authority boundary.

_TRANSFORMING_PHRASES = frozenset({
    "reverse proxy",
    "forward proxy",
    "load balancer",
    "content delivery",
    "api gateway",
    "service mesh",
    "tls terminat",
    "ssl terminat",
    "terminat",
    "normaliz",
    "rewrit",
    "ingress",
    "egress gateway",
    "sidecar",
    "intercepting proxy",
})
_TRANSFORMING_TOKENS = frozenset({
    "proxy",
    "gateway",
    "cache",
    "caching",
    "cdn",
    "waf",
    "firewall",
    "balancer",
    "edge",
    "router",
    "routing",
    "forwarder",
    "forwarding",
    "decode",
    "decoder",
    "decoding",
    "filter",
})


def _is_transforming(hop: Mapping[str, str]) -> bool:
    return _matches(_hop_text(hop), phrases=_TRANSFORMING_PHRASES, tokens=_TRANSFORMING_TOKENS)


# ── the component kinds (data-driven; full catalog breadth across the table) ──
#
# Each kind maps a structural property to the class families a senior researcher
# infers from it. No single architecture implies the whole catalog — a given
# structure triggers only the kinds its components match — but the union across
# every kind spans the catalog, so the table is demonstrably not about one class.

_COMPONENT_KINDS: tuple[_ComponentKind, ...] = (
    _ComponentKind(
        label="transforming intermediary",
        phrases=_TRANSFORMING_PHRASES,
        tokens=_TRANSFORMING_TOKENS,
        classes=("web_cache_poisoning", "header_injection", "open_redirect"),
        reason="parses, normalizes, caches, or rewrites traffic passing through it",
    ),
    _ComponentKind(
        label="authentication/authorization decision point",
        phrases=frozenset({
            "access control",
            "authentic",
            "authoriz",
            "identity provider",
            "single sign",
            "session management",
            "policy engine",
        }),
        tokens=frozenset({
            "auth",
            "authn",
            "authz",
            "identity",
            "session",
            "login",
            "logon",
            "sso",
            "oauth",
            "oidc",
            "openid",
            "jwt",
            "token",
            "idp",
            "rbac",
            "abac",
            "permission",
            "permissions",
            "credential",
            "credentials",
        }),
        classes=(
            "authentication_jwt",
            "broken_function_level_authorization",
            "idor",
            "weak_password_detection",
            "csrf",
            "cors_misconfiguration",
            "cryptographic_failures",
        ),
        reason="makes authentication or authorization decisions",
    ),
    _ComponentKind(
        label="server-side request originator / indirectly-reached component",
        phrases=frozenset({
            "server-side request",
            "http client",
            "url preview",
            "url fetch",
            "outbound request",
            "backend service",
            "internal service",
            "service mesh",
        }),
        tokens=frozenset({
            "webhook",
            "callback",
            "fetcher",
            "fetch",
            "outbound",
            "egress",
            "connector",
            "integration",
            "importer",
            "crawler",
            "upstream",
            "internal",
            "microservice",
            "subprocess",
        }),
        classes=("ssrf", "open_redirect", "rce", "information_disclosure"),
        reason=(
            "originates requests on behalf of a caller, or is reachable only indirectly "
            "through another component's server-side behavior"
        ),
    ),
    _ComponentKind(
        label="deserializer / template / interpreter",
        phrases=frozenset({
            "deserializ",
            "serializ",
            "unmarshal",
            "templat",
            "view engine",
            "expression language",
            "script engine",
            "markup",
        }),
        tokens=frozenset({
            "render",
            "renderer",
            "rendering",
            "parser",
            "parse",
            "interpreter",
            "eval",
            "xml",
            "yaml",
            "xslt",
            "xpath",
            "transformer",
        }),
        classes=(
            "insecure_deserialization",
            "ssti",
            "ssji",
            "xxe",
            "xslt_injection",
            "xpath_injection",
            "prototype_pollution",
            "rce",
            "xss",
        ),
        reason="deserializes, templates, or interprets caller-influenced data",
    ),
    _ComponentKind(
        label="durable-state frontend",
        phrases=frozenset({
            "data store",
            "datastore",
            "object store",
            "file store",
            "file system",
            "filesystem",
            "message broker",
            "search index",
            "directory service",
            "active directory",
            "persistence",
            "persistent store",
            "block storage",
        }),
        tokens=frozenset({
            "database",
            "db",
            "store",
            "storage",
            "sql",
            "rdbms",
            "postgres",
            "postgresql",
            "mysql",
            "mariadb",
            "oracle",
            "nosql",
            "mongodb",
            "mongo",
            "dynamodb",
            "redis",
            "cassandra",
            "elasticsearch",
            "ldap",
            "queue",
            "kafka",
            "bucket",
            "blob",
            "repository",
        }),
        classes=(
            "sql_injection",
            "nosql_injection",
            "ldap_injection",
            "xpath_injection",
            "idor",
            "path_traversal_lfi_rfi",
            "insecure_file_uploads",
            "second_order_injection",
            "race_conditions",
            "mass_assignment",
        ),
        reason="fronts durable state",
    ),
    _ComponentKind(
        label="browser-facing surface",
        phrases=frozenset({
            "single-page",
            "single page",
            "client-side",
            "web ui",
            "user interface",
            "static asset",
            "static site",
        }),
        tokens=frozenset({
            "browser",
            "frontend",
            "spa",
            "html",
            "javascript",
            "webpage",
        }),
        classes=(
            "xss",
            "clickjacking",
            "csrf",
            "cors_misconfiguration",
            "browser_security",
            "open_redirect",
        ),
        reason="renders or serves content executed in a browser client",
    ),
    _ComponentKind(
        label="command/subprocess executor",
        phrases=frozenset({
            "job runner",
            "task runner",
            "script runner",
            "command execution",
            "batch processor",
        }),
        tokens=frozenset({
            "subprocess",
            "shell",
            "exec",
            "cli",
            "worker",
            "cron",
            "scheduler",
        }),
        classes=("rce", "argument_injection", "path_traversal_lfi_rfi", "dos_resource_exhaustion"),
        reason="invokes commands or subprocesses with caller-influenced arguments",
    ),
    _ComponentKind(
        label="mail / notification originator",
        phrases=frozenset({"mail server", "mail transfer", "notification service"}),
        tokens=frozenset({"mail", "smtp", "email", "notification", "notifications", "sms"}),
        classes=("email_header_injection", "header_injection", "ssrf", "information_disclosure"),
        reason="composes and sends mail or notifications from caller-influenced fields",
    ),
    _ComponentKind(
        label="LLM / agentic component",
        phrases=frozenset({
            "language model",
            "prompt template",
            "agent framework",
            "tool-calling",
            "retrieval augmented",
            "vector store",
        }),
        tokens=frozenset({"llm", "ai", "chatbot", "assistant", "inference", "prompt", "rag"}),
        classes=(
            "llm_prompt_injection",
            "agentic_system_security",
            "ssrf",
            "information_disclosure",
            "insecure_deserialization",
        ),
        reason="drives an LLM or autonomous agent from caller-influenced prompts",
    ),
    _ComponentKind(
        label="external-name / hostname binding",
        phrases=frozenset({"virtual host", "name resolution", "external hostname"}),
        tokens=frozenset({"dns", "subdomain", "cname", "vhost", "hostname"}),
        classes=("subdomain_takeover", "ssrf", "information_disclosure"),
        reason="resolves or binds external hostnames",
    ),
    _ComponentKind(
        label="build / dependency / supply input",
        phrases=frozenset({
            "build pipeline",
            "ci/cd",
            "artifact repository",
            "package registry",
            "dependency resolver",
            "supply chain",
        }),
        tokens=frozenset({"ci", "cd", "pipeline", "build", "dependency", "plugin", "vendor"}),
        classes=(
            "supply_chain_ci_integrity",
            "rce",
            "insecure_deserialization",
            "information_disclosure",
        ),
        reason="consumes build, dependency, or supply-chain inputs",
    ),
    _ComponentKind(
        label="logging / audit / observability",
        phrases=frozenset({"audit trail", "log aggregat", "observability"}),
        tokens=frozenset({"log", "logs", "logging", "audit", "siem", "telemetry", "metrics"}),
        classes=("logging_alerting_failures", "information_disclosure", "header_injection"),
        reason="records logs, audit trails, or telemetry from caller-influenced input",
    ),
)


# The baseline every non-infrastructure request handler structurally admits,
# regardless of any narrower behavioral signal. Deliberately small and
# defensible: any application that accepts caller input has logic that can be
# abused, can over-disclose in its responses, and exposes functions whose
# access it must enforce. Narrower classes come from the behavioral kinds above.
_APPLICATION_PHRASES = frozenset({
    "application handler",
    "application server",
    "application framework",
    "request handler",
    "business logic",
    "web application",
    "api server",
    "rest api",
    "graphql",
    "backend",
})
_APPLICATION_TOKENS = frozenset({
    "application",
    "app",
    "handler",
    "controller",
    "endpoint",
    "service",
    "api",
    "server",
    "monolith",
    "standalone",
})
_BASELINE_CLASSES: tuple[str, ...] = (
    "business_logic",
    "information_disclosure",
    "broken_function_level_authorization",
)
_BASELINE_REASON = "is an application request-handler accepting caller-controlled input"


def _is_application_handler(hop: Mapping[str, str]) -> bool:
    """A non-infrastructure component that handles caller input."""
    if _is_transforming(hop):
        return False
    return _matches(_hop_text(hop), phrases=_APPLICATION_PHRASES, tokens=_APPLICATION_TOKENS)


# ── the boundary kinds ───────────────────────────────────────────────────────

_BOUNDARY_KINDS: tuple[_BoundaryKind, ...] = (
    _BoundaryKind(
        label="parser-authority boundary",
        classes=("http_request_smuggling", "semantic_confusion", "web_cache_poisoning",
                 "header_injection"),
        reason=(
            "adjacent components that may parse or normalize the same input with different "
            "authority"
        ),
        upstream_transforms=True,
    ),
    _BoundaryKind(
        label="trust transition",
        classes=("broken_function_level_authorization", "idor", "ssrf", "business_logic"),
        reason=(
            "a trust transition where the downstream may trust an identity or decision the "
            "upstream forwarded"
        ),
        downstream_handles=True,
    ),
)


def _boundary_label(upstream: Mapping[str, str], downstream: Mapping[str, str]) -> str:
    up = str(upstream.get("name", "")).strip() or "<unnamed>"
    down = str(downstream.get("name", "")).strip() or "<unnamed>"
    return f"{up} <-> {down}"


def _add(
    out: dict[str, Reason],
    classes: Sequence[str],
    source: str,
    detail: str,
) -> None:
    """Record each class with the structure that implied it (first writer wins).

    First-writer-wins keeps the reason deterministic and names a single implying
    structure per class, even when several would imply it.
    """
    for class_name in classes:
        if class_name not in out:
            out[class_name] = Reason(source=source, text=f"{source} {detail}")


def implied_classes(
    architecture: Mapping[str, Sequence[Mapping[str, str]]],
) -> dict[str, Reason]:
    """Candidate vulnerability classes the architecture implies, with reasons.

    ``architecture`` is the detected-architecture store shape — target identity
    mapped to an ordered list of component hops. For each target, every component
    hop is matched against the component kinds and every adjacent pair against
    the boundary kinds. The result maps each implied class to the component or
    boundary that implied it.

    An empty architecture (nothing registered) yields an empty mapping — the
    no-op that mirrors the discovery gate's empty-input behavior, so the gate
    never fires on empty state. Class names are intersected with the live catalog
    so only shippable classes are ever implied.
    """
    out: dict[str, Reason] = {}
    for hops in architecture.values():
        hop_list = [h for h in hops if isinstance(h, Mapping)]
        for hop in hop_list:
            name = str(hop.get("name", "")).strip() or "<unnamed component>"
            for kind in _COMPONENT_KINDS:
                if kind.implied(hop):
                    _add(out, kind.classes, name, f"({kind.label}) {kind.reason}")
            if _is_application_handler(hop):
                _add(out, _BASELINE_CLASSES, name, f"(application handler) {_BASELINE_REASON}")
        for upstream, downstream in itertools.pairwise(hop_list):
            label = _boundary_label(upstream, downstream)
            for boundary in _BOUNDARY_KINDS:
                fires = (
                    (boundary.upstream_transforms and _is_transforming(upstream))
                    or (boundary.downstream_handles and not _is_transforming(downstream))
                )
                if fires:
                    _add(
                        out,
                        boundary.classes,
                        f"boundary {label}",
                        f"({boundary.label}) {boundary.reason}",
                    )

    allowed = get_vulnerability_class_names()
    if allowed:
        # Guard: never imply a name the shipped catalog does not carry.
        out = {name: reason for name, reason in out.items() if name in allowed}
    return out


# A single, importable description of what the completeness gate enforces. The
# save-time gate, the generated CONTRACT, and the reasoning-regression probe all
# read this so the text that teaches and the rule that enforces share one source.
IMPLIED_CLASS_GATE_DESCRIPTION = (
    "Every vulnerability class the registered architecture implies — through a component's "
    "role, or through a boundary between two adjacent components that may interpret the same "
    "input differently — is an architecture-implied class the threat model must address, even "
    "when no surface for it was directly observed."
)


__all__ = [
    "IMPLIED_CLASS_GATE_DESCRIPTION",
    "Reason",
    "implied_classes",
]
