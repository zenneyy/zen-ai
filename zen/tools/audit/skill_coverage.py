"""Loaded-vs-referenced skill coverage checker.

Offline post-run analysis. For a completed zen run, measure for each agent
which loaded skills were actually REFERENCED in that agent's outputs
(command text + notes/threat-models under .state/) using distinctive tokens.
Flags "loaded-but-never-referenced" skills — the 245K-prompt /
advanced-content-ignored failure mode.

Read-only. Stdlib-only. Writes to --out when given; otherwise prints a table
to stdout. Not imported by any live scan code path.

Example invocation (against an existing run):

    python zen/tools/audit/skill_coverage.py \\
        --run-dir /home/kali/Desktop/validation-benchmarks/benchmarks/XBEN-066-24/zen_runs/host-docker-internal-32864_d476 \\
        --log     /home/kali/Desktop/validation-benchmarks/benchmarks/XBEN-066-24/zen_runs/host-docker-internal-32864_d476/zen.log
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------- #
# Log parsing                                                                  #
# --------------------------------------------------------------------------- #

# "Loaded skill: <slug> -> <var_name>"
LOADED_SKILL_RE = re.compile(r"Loaded skill:\s+(\S+)\s+->\s+(\S+)")

# "load_skills: N skill(s) resolved"
LOAD_SUMMARY_RE = re.compile(r"load_skills:\s+(\d+)\s+skill\(s\) resolved")

# "agent.register <id> (<Name>) parent=<parent>"
AGENT_REGISTER_RE = re.compile(
    r"agent\.register\s+(\S+)\s+\(([^)]+)\)\s+parent=(\S+)"
)

# "agent command: [agent=<id> ]<cmd...>"   (CHANGE 1 prefix is optional)
AGENT_COMMAND_RE = re.compile(
    r"agent command:\s+(?:agent=(\S+)\s+)?(.*)$"
)

# "llm_request ... agent=<id> ..." (used only when the agent prefix is absent)
LLM_REQUEST_AGENT_RE = re.compile(r"\bllm_request\b.*?\bagent=(\S+)")

# "create_agent: spawned <id> ... requested=[...]"  (not relied on, but noted)
SPAWN_RE = re.compile(r"create_agent:\s+spawned\s+(\S+)")

# Token form used for skills and the agent corpus.
TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{1,}")


def extract_tokens(text: str, min_len: int) -> set[str]:
    """Lowercased alnum/._- tokens of length >= min_len."""
    return {t.lower() for t in TOKEN_RE.findall(text) if len(t) >= min_len}


def parse_log(log_path: Path) -> tuple[dict[str, dict[str, Any]], bool, dict[str, Any]]:
    """Walk the log once; return (agents, used_prefix, diagnostics).

    agents keyed by agent_id -> {name, parent, skills_loaded (var_name list),
    commands (list[str]), unprefixed_commands (int)}.

    used_prefix is True when at least one 'agent command:' line carried the
    CHANGE 1 'agent=<id>' prefix.

    diagnostics describes anything the parser noticed but could not place.
    """
    agents: dict[str, dict[str, Any]] = {}
    # Blocks of var_names collected between successive load_skills summaries.
    pending_block: list[str] = []
    closed_blocks: list[list[str]] = []
    recent_llm_agent: str | None = None
    used_prefix = False
    orphan_commands = 0
    unmatched_blocks = 0

    if not log_path.exists():
        return agents, used_prefix, {
            "log_missing": True,
            "orphan_commands": orphan_commands,
            "unmatched_blocks": unmatched_blocks,
        }

    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = LOADED_SKILL_RE.search(line)
            if m:
                pending_block.append(m.group(2))
                continue

            m = LOAD_SUMMARY_RE.search(line)
            if m:
                # Even an empty block (0 skills) must close a boundary so
                # subsequent agent.register picks up the right block.
                closed_blocks.append(list(pending_block))
                pending_block = []
                continue

            m = AGENT_REGISTER_RE.search(line)
            if m:
                agent_id, name, parent = m.group(1), m.group(2), m.group(3)
                skills = closed_blocks.pop(0) if closed_blocks else []
                if not closed_blocks and not skills:
                    # agent registered with no preceding load_skills block.
                    # Not fatal: just means skills_loaded is empty.
                    pass
                agents.setdefault(
                    agent_id,
                    {
                        "name": name,
                        "parent": parent,
                        "skills_loaded": skills,
                        "commands": [],
                        "unprefixed_commands": 0,
                    },
                )
                continue

            m = LLM_REQUEST_AGENT_RE.search(line)
            if m:
                recent_llm_agent = m.group(1)
                continue

            m = AGENT_COMMAND_RE.search(line)
            if m:
                aid = m.group(1)
                cmd = m.group(2)
                target: str | None
                if aid:
                    used_prefix = True
                    target = aid
                else:
                    target = recent_llm_agent
                if target and target in agents:
                    agents[target]["commands"].append(cmd)
                    if not aid:
                        agents[target]["unprefixed_commands"] += 1
                else:
                    orphan_commands += 1
                continue

    unmatched_blocks = len(closed_blocks)
    return (
        agents,
        used_prefix,
        {
            "log_missing": False,
            "orphan_commands": orphan_commands,
            "unmatched_blocks": unmatched_blocks,
        },
    )


# --------------------------------------------------------------------------- #
# Skills: load bodies and compute distinctive tokens                           #
# --------------------------------------------------------------------------- #


def collect_skills(skills_root: Path, min_len: int) -> dict[str, dict[str, Any]]:
    """Return per-skill info keyed by var_name (file stem).

    info = {path, size, tokens, family_base}.
    """
    skills: dict[str, dict[str, Any]] = {}
    if not skills_root.exists():
        return skills

    for md in skills_root.rglob("*.md"):
        try:
            content = md.read_text(encoding="utf-8", errors="replace")
            size = md.stat().st_size
        except OSError:
            continue
        var_name = md.stem
        if var_name in skills:
            # Duplicate stem across categories: keep the first; audit is diagnostic.
            continue
        skills[var_name] = {
            "path": str(md),
            "size": size,
            "tokens": extract_tokens(content, min_len),
            "family_base": var_name,  # overwritten below
        }

    _assign_family_bases(skills)
    return skills


def _assign_family_bases(skills: dict[str, dict[str, Any]]) -> None:
    """Peel trailing '_<topic>' chunks off deep siblings to find their base skill.

    Examples (names present in the repo):
      - asset_discovery_cloud_deep -> asset_discovery
      - application_enumeration_auth_multiservice_deep -> application_enumeration
      - ssrf_advanced_deep -> ssrf
      - ssrf_novel_deep -> ssrf
      - arjun, python, counterevidence, ... -> self (base)
    """
    for name, info in skills.items():
        stem = name
        for suffix in ("_deep",):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break
        candidate = stem
        base = name
        while "_" in candidate:
            candidate = candidate.rsplit("_", 1)[0]
            if candidate != name and candidate in skills:
                base = candidate
                break
        info["family_base"] = base


def compute_distinctive(
    skills: dict[str, dict[str, Any]], common_cap: int
) -> None:
    """Attach info['distinctive_tokens'] per skill.

    - Deep sibling (family_base != self): tokens in this skill but NOT in base.
    - Base skill: tokens whose document frequency across all skills is <= common_cap.
    """
    doc_freq: Counter[str] = Counter()
    for info in skills.values():
        for tok in info["tokens"]:
            doc_freq[tok] += 1

    for name, info in skills.items():
        base = info["family_base"]
        if base != name and base in skills:
            info["distinctive_tokens"] = info["tokens"] - skills[base]["tokens"]
        else:
            info["distinctive_tokens"] = {
                t for t in info["tokens"] if doc_freq[t] <= common_cap
            }


# --------------------------------------------------------------------------- #
# Agent output corpus (notes + threat models + command text)                   #
# --------------------------------------------------------------------------- #


def load_state_corpus(run_dir: Path) -> dict[str, str]:
    """Concatenate per-agent text from .state/*.json files.

    Walks any dict-shaped records looking for an 'agent_id' / 'author' /
    'owner' field; collects the surrounding record's JSON serialization for
    that agent. Unknown or missing files are skipped silently (defensive).
    """
    state = run_dir / ".state"
    corpora: dict[str, list[str]] = defaultdict(list)
    if not state.exists():
        return {}

    for name in ("notes.json", "threat_models.json", "coverage.json"):
        path = state / name
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        _attach_state(data, corpora)

    return {aid: "\n".join(parts) for aid, parts in corpora.items()}


def _attach_state(obj: Any, corpora: dict[str, list[str]]) -> None:
    if isinstance(obj, dict):
        aid = None
        for key in ("agent_id", "author", "owner", "created_by"):
            v = obj.get(key)
            if isinstance(v, str) and v:
                aid = v
                break
        if aid:
            try:
                corpora[aid].append(
                    json.dumps(obj, ensure_ascii=False, default=str)
                )
            except (TypeError, ValueError):
                corpora[aid].append(str(obj))
            # Recurse too — a parent record may wrap child records with their
            # own agent_id.
            for v in obj.values():
                _attach_state(v, corpora)
        else:
            for v in obj.values():
                _attach_state(v, corpora)
    elif isinstance(obj, list):
        for v in obj:
            _attach_state(v, corpora)


# --------------------------------------------------------------------------- #
# Analysis                                                                     #
# --------------------------------------------------------------------------- #


def analyze(
    agents: dict[str, dict[str, Any]],
    skills: dict[str, dict[str, Any]],
    corpora: dict[str, str],
    min_len: int,
) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for aid, info in agents.items():
        state_text = corpora.get(aid, "")
        cmd_text = "\n".join(info["commands"])
        corpus = f"{cmd_text}\n{state_text}".lower()
        corpus_tokens = extract_tokens(corpus, min_len)

        rows: list[dict[str, Any]] = []
        total_bytes = 0
        wasted_bytes = 0
        for var_name in info["skills_loaded"]:
            s = skills.get(var_name)
            if s is None:
                rows.append(
                    {
                        "skill": var_name,
                        "status": "MISSING",
                        "size": 0,
                        "distinctive": 0,
                        "referenced": 0,
                        "coverage": 0.0,
                    }
                )
                continue
            distinctive = s["distinctive_tokens"]
            total_bytes += s["size"]
            if not distinctive:
                rows.append(
                    {
                        "skill": var_name,
                        "status": "NO_DISTINCTIVE",
                        "size": s["size"],
                        "distinctive": 0,
                        "referenced": 0,
                        "coverage": 0.0,
                    }
                )
                continue
            hits = len(distinctive & corpus_tokens)
            coverage = hits / len(distinctive)
            status = "REFERENCED" if hits > 0 else "IGNORED"
            if status == "IGNORED":
                wasted_bytes += s["size"]
            rows.append(
                {
                    "skill": var_name,
                    "status": status,
                    "size": s["size"],
                    "distinctive": len(distinctive),
                    "referenced": hits,
                    "coverage": coverage,
                }
            )

        results[aid] = {
            "name": info["name"],
            "parent": info["parent"],
            "rows": rows,
            "total_bytes": total_bytes,
            "wasted_bytes": wasted_bytes,
            "command_count": len(info["commands"]),
            "unprefixed_commands": info["unprefixed_commands"],
            "state_corpus_bytes": len(state_text),
        }
    return results


# --------------------------------------------------------------------------- #
# Reporting                                                                    #
# --------------------------------------------------------------------------- #


def print_tables(
    results: dict[str, dict[str, Any]],
    diagnostics: dict[str, Any],
    used_prefix: bool,
) -> None:
    if diagnostics.get("log_missing"):
        print("[warn] log file not found; nothing to analyze")
        return
    if not used_prefix:
        print(
            "[note] no 'agent command:' line carried the CHANGE 1 'agent=<id>' "
            "prefix; attribution fell back to the preceding llm_request "
            "agent=<id> line (less reliable)."
        )
    if diagnostics.get("orphan_commands"):
        print(
            f"[note] {diagnostics['orphan_commands']} agent command line(s) "
            "could not be attributed to a known agent."
        )
    if diagnostics.get("unmatched_blocks"):
        print(
            f"[note] {diagnostics['unmatched_blocks']} load_skills block(s) "
            "had no following agent.register — build failed or log truncated."
        )
    if not results:
        print("[warn] no agents parsed from the log.")
        return

    grand_total = 0
    grand_wasted = 0
    for aid, info in results.items():
        print()
        print(
            f"=== agent {aid} ({info['name']}) parent={info['parent']} ==="
        )
        print(
            f"  commands={info['command_count']}  "
            f"unprefixed={info['unprefixed_commands']}  "
            f"state_bytes={info['state_corpus_bytes']}"
        )
        header = (
            f"  {'skill':<42} {'status':<14} "
            f"{'size':>8} {'dist':>5} {'ref':>5} {'cov':>6}"
        )
        print(header)
        print("  " + "-" * (len(header) - 2))
        # Sort: IGNORED first (loudest signal), then by size desc.
        order = sorted(
            info["rows"],
            key=lambda r: (
                0 if r["status"] == "IGNORED" else 1,
                -r["size"],
                r["skill"],
            ),
        )
        for r in order:
            print(
                f"  {r['skill']:<42} {r['status']:<14} "
                f"{r['size']:>8} {r['distinctive']:>5} "
                f"{r['referenced']:>5} {r['coverage']:>6.2f}"
            )
        pct = (
            100.0 * info["wasted_bytes"] / info["total_bytes"]
            if info["total_bytes"]
            else 0.0
        )
        print(
            f"  total skill-bytes={info['total_bytes']}  "
            f"wasted(IGNORED)={info['wasted_bytes']} ({pct:.1f}%)"
        )
        grand_total += info["total_bytes"]
        grand_wasted += info["wasted_bytes"]

    print()
    pct = 100.0 * grand_wasted / grand_total if grand_total else 0.0
    print(
        f"[run] total skill-bytes loaded={grand_total}  "
        f"wasted(IGNORED)={grand_wasted} ({pct:.1f}%)"
    )


def to_json(
    results: dict[str, dict[str, Any]],
    diagnostics: dict[str, Any],
    used_prefix: bool,
) -> dict[str, Any]:
    return {
        "used_agent_prefix": used_prefix,
        "diagnostics": diagnostics,
        "agents": results,
    }


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Measure loaded-vs-referenced skill coverage per agent in a "
            "completed zen run. Offline, read-only, stdlib-only."
        )
    )
    parser.add_argument("--run-dir", required=True, type=Path,
                        help="Zen run directory (has .state/ with notes etc.)")
    parser.add_argument("--log", required=True, type=Path,
                        help="Path to the zen.log file for that run")
    parser.add_argument(
        "--skills-root",
        type=Path,
        default=Path("/home/kali/Desktop/zen-ai/zen/skills"),
        help="Root of the skills tree (default: in-tree zen/skills)",
    )
    parser.add_argument("--min-token-len", type=int, default=5,
                        help="Minimum token length (default: 5)")
    parser.add_argument("--out", type=Path, default=None,
                        help="Optional JSON output path (default: print table)")
    parser.add_argument(
        "--common-cap",
        type=int,
        default=20,
        help=(
            "Base skills: tokens appearing in <= this many skills are "
            "considered distinctive (default: 20)."
        ),
    )
    args = parser.parse_args()

    agents, used_prefix, diagnostics = parse_log(args.log)
    skills = collect_skills(args.skills_root, args.min_token_len)
    compute_distinctive(skills, args.common_cap)
    corpora = load_state_corpus(args.run_dir)
    results = analyze(agents, skills, corpora, args.min_token_len)

    if args.out is not None:
        payload = to_json(results, diagnostics, used_prefix)
        args.out.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        print(f"wrote {args.out}")
    else:
        print_tables(results, diagnostics, used_prefix)


if __name__ == "__main__":
    main()
