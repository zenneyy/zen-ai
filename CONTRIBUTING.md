# Contributing to Zen

This guide covers local development setup, the contribution workflow, and the standards a change is expected to meet before it lands.

## 🚀 Development environment

### Toolchain requirements

- Python 3.12+
- Latest Go 1.24.x patch (required only when working on the Bubble Tea TUI or producing release artifacts)
- Docker, with the daemon running
- [uv](https://docs.astral.sh/uv/) (dependency and environment management)
- Git

### Local setup

1. **Clone the source**
   ```bash
   git clone https://github.com/zenneyy/zen-ai.git
   cd zen
   ```

2. **Install the dev toolchain**
   ```bash
   make setup-dev

   # or manually:
   uv sync
   uv run pre-commit install
   ```

3. **Point Zen at a provider**
   ```bash
   export ZEN_LLM="openai/gpt-5.4"
   export LLM_API_KEY="your-api-key"
   ```

4. **Run from source**
   ```bash
   uv run zen --target https://example.com
   ```

## 📚 Skill contributions

Skills are self-contained knowledge modules the agents load at runtime to extend what they can test. The format and conventions are documented in full at [zen/skills/README.md](zen/skills/README.md).

### Authoring checklist

1. **Pick the correct category** (`/vulnerabilities`, `/frameworks`, `/technologies`, etc.)
2. **Write the skill** as a `.md` file
3. **Ship runnable examples** - Payloads, commands, or test cases that actually execute
4. **Document verification** - How to confirm a finding is genuine and rule out false positives
5. **Open a PR** describing what the skill covers

## 🔧 Code contributions

### Submission workflow

1. **File an issue first** - State the defect or the capability you intend to add
2. **Fork and branch** - Cut your branch from `main`
3. **Implement the change** - Match the conventions already present in the files you touch
4. **Write or extend tests** - New behavior needs new assertions
5. **Verify locally** - `make check-all` must pass before you push
6. **Open the PR** - Reference the issue and explain the reasoning

### Review expectations

- **Clear description** - State what changed and why it changed
- **Small, focused changes** - One capability or one fix per pull request
- **Include examples** - Demonstrate the behavior before and after
- **Update documentation** - Any new surface area needs docs alongside it
- **Pass all checks** - Tests, lint, and type checking must be green

### Style conventions

- PEP 8, with lines capped at 100 characters
- Annotate every function signature with type hints
- Docstrings on anything public
- One responsibility per function; keep them short
- Name variables for what they actually hold

## 🐛 Defect reports

A useful defect report contains:

- Host OS and Python version
- The Zen version in use
- The models in use
- The complete traceback
- A minimal reproduction sequence
- Expected behavior against what actually occurred

## 💡 Feature proposals

Proposals are welcome. Before opening one:

- Search existing issues for prior discussion
- Describe the concrete use case driving it
- Explain who benefits and in what way
- Sketch a plausible implementation path
- Expect the design to be debated

## 🖥️ Viewer frontend

`zen view` serves a prebuilt web UI. Its source is a Vite + React project under
`zen/interface/viewer/frontend/`, and the compiled output is committed to
`zen/interface/viewer/static/` so it ships inside the package. End users never invoke a
JS toolchain. Any edit beneath `zen/interface/viewer/frontend/` therefore requires a
rebuild before it is committed:

```bash
make viewer   # or: cd zen/interface/viewer/frontend && npm ci && npm run build
```

The source change and the regenerated `zen/interface/viewer/static/` belong in the same commit.

## Build artifacts

Editable installs have no Go dependency; they execute the TUI directly from source via `go run`.

Wheels are platform-specific and always carry the matching Go sidecar:

```bash
make wheel
```

The build hook at `scripts/tui_sidecar_hook.py` compiles that sidecar, embeds it at
`zen/bin/zen-tui`, and stamps the current platform tag. Go 1.24.x or newer is mandatory,
and the hook fails outright rather than emitting a wheel with no sidecar. The same
strictness applies to `scripts/build.sh` and `zen.spec` for frozen PyInstaller releases.

## 🤝 Contact

- **Discord**: [Talk to the maintainers](https://discord.gg/v5dPr4wcTz)
- **Issues**: [GitHub issue tracker](https://github.com/zenneyy/zen-ai/issues)

## ✨ Attribution

Every merged contribution is credited. Contributors are:
- Named in the release notes
- Acknowledged on Discord
- Added to the contributors list (in progress)

---

**Stuck on something?** Ask on [Discord](https://discord.gg/v5dPr4wcTz) or open an issue, and someone will pick it up.
