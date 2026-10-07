---
name: primitive-taxonomy
description: Per-class grant/require pairs for all vulnerability classes — the node definitions that populate the attack-graph model in chain_construction.
---

# Primitive Taxonomy

Every vulnerability class is a node type in the attack-graph model
(`chaining/chain_construction`). This file canonicalizes the
postcondition (grant) and precondition (require) for each class,
aggregated from the 42 `vulnerabilities/` files. Use it to determine
whether two classes chain: does A's grant satisfy B's require on this
target?

The grant/require pairs are stated as concrete capabilities. The
controllables (what subset the attacker actually controls) and the
position (where the primitive executes) further constrain what chains
are reachable — see `chain_construction` for the full node model.

## How to Read This Taxonomy

Each entry states:

- **Grant**: what capability the class gives the attacker after
  successful exploitation.
- **Require**: what the attacker must already hold before this class
  is exploitable.
- **Chains-to**: the downstream classes this grant typically feeds.
- **Chains-from**: the upstream classes that typically provide this
  require.

"Typically" means the chain is structurally valid — the types match.
Whether the chain exists on a specific target depends on reachability
(see `chain_validation`).

---

## Injection Classes

### SQL Injection
- **Grant**: arbitrary SQL execution against the application database
  — data read/write, authentication bypass, file write (INTO
  OUTFILE, COPY TO PROGRAM), RCE (xp_cmdshell), SSRF via DB
  networking (dblink, UTL_HTTP). Identifier-position variant grants
  predicate-shape control (OR/NOT collapse).
- **Require**: user input reaching SQL sink — value-position
  concatenation or identifier-position ORM API accepting
  attacker-controlled names. Version fingerprint for CVE-tagged
  findings.
- **Chains-to**: authentication_jwt (auth bypass → session), rce
  (file write / COPY TO PROGRAM / xp_cmdshell), ssrf (dblink /
  UTL_HTTP → internal reach), idor (row read of unauthorized
  tables), xss (stored second-order XSS).
- **Chains-from**: reconnaissance (input surface + ORM ID),
  authentication_jwt (session to reach route), information_disclosure
  (version fingerprint, DB creds from config).

### NoSQL Injection
- **Grant**: authentication bypass, blind data extraction (password
  hashes, reset tokens, API keys), $where → Node.js RCE,
  cross-collection reads via $lookup, server-side code execution.
- **Require**: JSON body parser preserving operator keys, or
  query-string parser accepting bracket notation; ODM/framework
  passing user input to find/aggregate without operator-key
  filtering.
- **Chains-to**: authentication_jwt (auth bypass → session), rce
  ($where → exec), idor ($lookup → cross-collection disclosure).
- **Chains-from**: Express/Fastify JSON body parsing with qs
  defaults; ODM without operator sanitization.

### LDAP Injection
- **Grant**: authentication bypass (login as any user),
  group-membership bypass, directory enumeration, attribute
  extraction (hashed passwords, SSH keys), DN injection (admin
  provisioning).
- **Require**: application composing LDAP filter strings via
  concatenation; unescaped user input reaching filter parser.
- **Chains-to**: authentication_jwt (session from bypassed user),
  broken_function_level_authorization (bypassed user is privileged),
  information_disclosure (directory enumeration).
- **Chains-from**: user input reaching LDAP filter composition.

### XPath Injection
- **Grant**: auth bypass (tautological predicate), SAML
  signature-verification bypass → cross-user SSO impersonation,
  document enumeration, file read via unparsed-text(), SSRF via
  doc()/document(), RCE via jxpath reflection.
- **Require**: unescaped user input reaching XPath query evaluator;
  SAML/XMLDSig library using XPath for reference resolution.
- **Chains-to**: broken_function_level_authorization (auth bypass),
  ssrf (doc() → fetch), path_traversal_lfi_rfi (unparsed-text()),
  rce (jxpath → Runtime.exec).
- **Chains-from**: user input reaching XPath composition; SAML
  assertion processing.

### XSLT Injection
- **Grant**: full RCE via processor extension functions (Xalan Java
  reflection, Saxon java:*, libxslt-PHP php:function, .NET
  msxsl:script), arbitrary file read via document()/unparsed-text(),
  SSRF via document().
- **Require**: attacker-controlled XSLT stylesheet or fragment
  reaching processor; processor configured without
  FEATURE_SECURE_PROCESSING.
- **Chains-to**: rce (extension functions → exec), ssrf (document()
  → fetch), path_traversal_lfi_rfi (file read), xxe (shared
  TransformerFactory).
- **Chains-from**: insecure_file_uploads (uploaded XSLT/XML),
  path_traversal_lfi_rfi (view-name auto-resolution → stylesheet
  URI).

### Second-Order Injection
- **Grant**: the injection class reached by the firing path —
  SQL/XSS/LDAP/XPath/SSTI/RCE/SSRF; privilege-elevation by stored
  content.
- **Require**: storage path accepting user-controlled data; firing
  path that reads stored value and composes into a sink without
  re-escaping.
- **Chains-to**: the downstream class the firing-path sink belongs
  to.
- **Chains-from**: any storage path with user-controlled data.

### Argument Injection
- **Grant**: specific CLI capability — file write (--output), file
  read (--upload-file), subcommand access, interpreter selection,
  config file reparsing.
- **Require**: attacker-influenced data reaching a trusted
  command-line program's argv (even without shell involvement).
- **Chains-to**: rce (file write to cron/privileged path), ssrf
  (curl with user-controlled URL + options), information_disclosure
  (file read).
- **Chains-from**: user input reaching CLI invocation;
  semantic_confusion (parser boundary disagreement).

### Header Injection
- **Grant**: CRLF response splitting, cache poisoning via unkeyed
  headers, Host-header password-reset poisoning, cookie fixation,
  method-override.
- **Require**: user input echoed into response headers; request
  headers re-emitted into responses.
- **Chains-to**: open_redirect (Location injection), xss (cache
  poisoning → cross-user XSS), csrf (method-override widens
  surface), ssrf (X-Forwarded-* → outbound request).
- **Chains-from**: user input reaching response header composition;
  proxy configurations trusting forwarded headers.

### Email Header Injection
- **Grant**: covert recipient (Bcc addition), spam/phishing
  distribution via trusted domain, account-takeover via
  password-reset email copy, MIME-smuggling → phishing.
- **Require**: unvalidated form field reaching mail composition;
  CRLF not stripped from header fields.
- **Chains-to**: authentication_jwt (password-reset token theft via
  Bcc), information_disclosure (mail content exfil).
- **Chains-from**: user input reaching mail header composition.

## Server-Side Execution Classes

### SSRF
- **Grant**: attacker-chosen outbound request from server-side
  network position; internal-network reach; metadata-endpoint
  reach; protocol smuggling reach (gopher→Redis/FCGI); cross-service
  auth reuse. Controllables (scheme, host, port, path, headers,
  method+body) determine chain reach.
- **Require**: URL-fetching sink with attacker-controlled input.
- **Chains-to**: cloud/* (metadata credential extraction, gated by
  controllables), rce (protocol smuggling → shell),
  broken_function_level_authorization (cross-service auth reuse),
  information_disclosure (internal service data).
- **Chains-from**: reconnaissance (sink discovery), open_redirect
  (redirect-to-internal bypass), xxe (SYSTEM URI → HTTP fetch),
  sql_injection (dblink/UTL_HTTP), header_injection (X-Forwarded-*).

### SSTI
- **Grant**: RCE on render host (template engines evaluate
  expressions with host-language runtime access); file write to
  webroot; credential harvest; lateral SSRF via server-side HTTP
  client.
- **Require**: user input reaching template engine as syntax (not
  data); template-source-editing feature or user-controlled template
  name/path.
- **Chains-to**: rce (host code execution), cloud/* (metadata),
  information_disclosure (.env/config secrets), ssrf (compromised
  host → internal services).
- **Chains-from**: broken_function_level_authorization (access to
  template editor), llm_prompt_injection (prompt template with
  Environment()), insecure_file_uploads (uploaded template),
  path_traversal_lfi_rfi (template name traversal).

### SSJI
- **Grant**: host-realm JavaScript execution — require('child_process'),
  filesystem via require('fs'), outbound HTTP, process.env access
  (secrets, cloud credentials).
- **Require**: attacker-controlled text reaching server-side JS
  evaluator (Function/eval/node:vm/template-engine JS context) or
  pseudo-sandbox with escape.
- **Chains-to**: rce (host OS command execution),
  information_disclosure (process.env dump), cloud/* (Lambda
  credentials).
- **Chains-from**: prototype_pollution (polluted config key →
  Function sink), insecure_deserialization (reconstructor reaches
  vm.runInContext), ssrf (internal code-execution endpoint).

### RCE
- **Grant**: full server control — OS command execution, filesystem
  access, network access, credential extraction, lateral movement.
- **Require**: input reaching code execution primitive — OS command
  wrappers, dynamic evaluators, template engines, deserializers,
  media pipelines.
- **Chains-to**: cloud/* (metadata → credential theft), lateral
  movement, persistence.
- **Chains-from**: sql_injection (file write / COPY TO PROGRAM),
  ssti (template → RCE), insecure_deserialization (gadget chain),
  ssrf (protocol smuggling), argument_injection (file write to
  cron), prototype_pollution (universal gadgets), ssji (host-realm
  JS), path_traversal_lfi_rfi (LFI→eval, Zip-Slip),
  insecure_file_uploads (webshell), xslt_injection (extension
  functions).

### Insecure Deserialization
- **Grant**: arbitrary-object-construction; gadget-chain-driven RCE;
  auth bypass via forged session/role objects; privilege escalation
  via manipulated fields on trusted types.
- **Require**: unmarshaller accepting polymorphic type metadata;
  reachable classpath with a gadget chain to dangerous sink; magic
  method firing on unmarshal.
- **Chains-to**: rce (gadget chain → exec),
  broken_function_level_authorization (forged session/role), ssrf
  (JNDI outbound → metadata).
- **Chains-from**: insecure_file_uploads (upload with predictable
  path → PHAR trigger), information_disclosure (leaked signing key
  → forged blob), ssrf (internal RMI/JMX endpoint),
  prototype_pollution (polluted method → unmarshal path).

### Prototype Pollution
- **Grant**: shared prototype corruption — inject one key on
  Object.prototype → every plain object inherits it; downstream
  reads as config → auth/authz bypass, DOM XSS, Node.js RCE via
  universal-gadget chains, template SSTI.
- **Require**: reachable merge/set sink with __proto__ or
  constructor.prototype payload; parser preserving prototype keys.
- **Chains-to**: xss (DOM clobbering), rce (universal-gadget
  chains), ssti (template compile gadgets), nosql_injection
  (sanitizer collision), insecure_deserialization (pollution →
  unmarshal path).
- **Chains-from**: JSON body/GraphQL/WebSocket/postMessage payloads;
  URL-encoded nested objects.

## File and Data Access Classes

### Path Traversal / LFI / RFI
- **Grant**: arbitrary file read as process identity; source code
  disclosure; LFI-with-evaluation → RCE; archive-extraction write →
  code execution via resolver; config poisoning; SSRF pivot via
  http:// wrappers.
- **Require**: user-influenced file path/name reaching filesystem
  operations.
- **Chains-to**: information_disclosure (credential files),
  sql_injection (DB creds → direct connect), rce (LFI→eval,
  Zip-Slip), ssrf (http:// wrapper), ssti (template name traversal),
  cloud/* (SA token read).
- **Chains-from**: authentication_jwt (session to reach endpoint),
  ssrf (server-side URL fetch → RFI), insecure_file_uploads
  (writable path), xxe (file:// read).

### XXE
- **Grant**: arbitrary file read as process identity; SSRF-shaped
  reach (parser fetches http:// from SYSTEM URIs); DoS via entity
  expansion; RCE via XSLT/expect://jar:.
- **Require**: XML input reaching parser with external entity
  processing enabled; content-type coercion to XML; upload accepting
  XML-containing format.
- **Chains-to**: path_traversal_lfi_rfi (file disclosure), ssrf
  (SYSTEM URI → internal HTTP), rce (XSLT/expect://), cloud/*
  (metadata reachability).
- **Chains-from**: insecure_file_uploads (SVG/DOCX upload),
  content-type coercion, third-party XML integrations.

### Insecure File Uploads
- **Grant**: server-side execution (RCE via webshell), stored XSS,
  malware distribution, storage takeover, DoS.
- **Require**: upload surface (web/mobile/API, direct-to-cloud
  presigned, resumable/multipart); server-side processing.
- **Chains-to**: rce (webshell execution), xss (stored XSS),
  path_traversal_lfi_rfi (Zip-Slip), insecure_deserialization
  (PHAR metadata trigger).
- **Chains-from**: user-reachable upload endpoint; cloud storage
  presigned URL generation.

### Information Disclosure
- **Grant**: credential extraction (DVCS/config secrets);
  version-to-CVE mapping; path disclosure → filesystem layout;
  schema → hidden fields/endpoints; source code exposure.
- **Require**: reachable error pages, debug endpoints, DVCS
  artifacts, config files, API schemas, client bundles, response
  headers.
- **Chains-to**: sql_injection (DB creds), authentication_jwt (JWT
  secrets), path_traversal_lfi_rfi (filesystem layout),
  broken_function_level_authorization (hidden endpoints), cloud/*
  (cloud credentials).
- **Chains-from**: any endpoint leaking structured data; DVCS
  exposure.

## Authorization and Session Classes

### IDOR / BOLA
- **Grant**: cross-object read/write — horizontal (peer's objects),
  vertical (privileged objects), cross-tenant, cross-service access.
- **Require**: at least one authenticated identity (two for
  differential); knowledge of foreign object identifiers.
- **Chains-to**: information_disclosure (cross-account read),
  authentication_jwt (user record → credential theft → ATO), xss
  (stored content write → persistent XSS), ssrf (webhook
  registration), broken_function_level_authorization (BFLA + IDOR =
  full-tenant takeover).
- **Chains-from**: authentication_jwt (session for probing), ssrf
  (internal endpoint reachability), information_disclosure (foreign
  object IDs), path_traversal_lfi_rfi (object-key exposure).

### Broken Function-Level Authorization (BFLA)
- **Grant**: invocation of endpoints/mutations/admin tools the
  principal is not entitled to; admin-level actions from basic user.
- **Require**: at least one authenticated identity (low-privilege
  session); knowledge of admin/privileged endpoint paths.
- **Chains-to**: idor (privileged action + foreign object =
  full-tenant takeover), authentication_jwt (impersonate → session).
- **Chains-from**: authentication_jwt (any session), ssrf (internal
  admin endpoint reachability), mass_assignment (self-promoted role),
  information_disclosure (endpoint discovery).

### Mass Assignment
- **Grant**: unauthorized field binding — privilege escalation
  (role=admin), ownership takeover (ownerId swap), unauthorized state
  transitions.
- **Require**: REST/JSON/GraphQL/form input reaching model binding
  in controllers/resolvers; ORM create/update accepting unfiltered
  fields.
- **Chains-to**: broken_function_level_authorization (role
  escalation), idor (ownerId control → foreign resource).
- **Chains-from**: user input reaching framework model binder.

### Authentication / JWT
- **Grant**: token forgery, token confusion, cross-service
  acceptance, durable account takeover; session as any user.
- **Require**: JWT/OIDC authentication surface; access to token
  endpoints or token material.
- **Chains-to**: any authenticated-surface attack.
- **Chains-from**: xss (token theft), ssrf (private JWKS fetch),
  header_injection (OIDC redirect_uri poisoning), open_redirect
  (OAuth code interception), information_disclosure (JWT secrets).

### Weak Password Detection
- **Grant**: credential compromise — valid session via
  brute-forced/guessed/stuffed credentials; default credential
  access to admin/management interfaces.
- **Require**: login portal; weak password policy; default/hardcoded
  credentials; predictable reset tokens.
- **Chains-to**: authentication_jwt (valid session → all auth-gated
  endpoints), broken_function_level_authorization (admin credential).
- **Chains-from**: information_disclosure (leaked credential lists),
  reconnaissance (login endpoint discovery).

## Client-Side Classes

### XSS
- **Grant**: JavaScript execution in victim's browser context —
  session hijack (cookie/token theft), keylogging, phishing, DOM
  manipulation, service worker registration for persistence.
- **Require**: user-influenced string reaching HTML/JS/CSS/SVG
  rendering context without proper encoding; CSP/Trusted Types not
  enforced or bypassable.
- **Chains-to**: authentication_jwt (token theft → session replay),
  csrf (cookie injection), browser_security (SW registration).
- **Chains-from**: any user input reaching a rendering context;
  stored content from other classes (sql_injection, idor,
  mass_assignment).

### CSRF
- **Grant**: state change under victim's identity — password/email
  change, MFA disable, funds transfer; ambient authority transfer.
- **Require**: session cookie without SameSite=Strict;
  state-changing endpoint accepting ambient credentials.
- **Chains-to**: idor (force actions on other users' resources),
  authentication_jwt (OAuth account linking → persistent takeover).
- **Chains-from**: xss (cookie injection), subdomain_takeover
  (sibling subdomain foothold), http_request_smuggling (smuggled
  request).

### Clickjacking
- **Grant**: user interaction capture via UI redress — clicks,
  drags, keypresses delivered to target as legitimate interaction.
- **Require**: target URL renders without X-Frame-Options / CSP
  frame-ancestors; state-changing action at predictable position.
- **Chains-to**: csrf (CSRF-shape state changes),
  authentication_jwt (OAuth consent → token issuance).
- **Chains-from**: open_redirect (deliver victim to framing page).

### Open Redirect
- **Grant**: phishing pivot (trusted domain → attacker site);
  OAuth/OIDC code and token theft; allowlist bypass in server-side
  fetchers that follow redirects.
- **Require**: redirect target parameter controlled by attacker;
  server or client-side redirect mechanism.
- **Chains-to**: authentication_jwt (OAuth code/token interception),
  ssrf (server-side fetcher follows redirect to internal), csrf
  (deliver victim to attack page).
- **Chains-from**: user input reaching redirect target; OAuth
  redirect_uri parameter.

### Browser Security
- **Grant**: client-side path traversal (CSPT), postMessage trust
  abuse, XS-Leak oracles, service worker persistence, cross-origin
  isolation gaps, named-window reuse.
- **Require**: browser-mediated interaction with target; controlled
  browser profile or synthetic account.
- **Chains-to**: csrf (CSPT→CSRF), xss (postMessage→XSS), rce
  (Spectre-adjacent via isolation gap).
- **Chains-from**: xss (initial foothold for SW registration),
  open_redirect (navigation primitive).

### CORS Misconfiguration
- **Grant**: cross-origin authenticated read of response bodies;
  cross-origin authenticated write when preflight is permissive.
- **Require**: echoed/reflected Origin + Allow-Credentials: true +
  endpoint returning protected data under session auth.
- **Chains-to**: information_disclosure (cross-origin data exfil),
  csrf (cross-origin write).
- **Chains-from**: subdomain_takeover (takeover feeds allowlist),
  xss (same-origin trust circumvention).

### Subdomain Takeover
- **Grant**: serve content from trusted subdomain — phishing on
  trusted origin, cookie pivot, CORS allowlist feed, OAuth redirect
  abuse.
- **Require**: dangling DNS record pointing to claimable third-party
  resource; orphaned SaaS integrations.
- **Chains-to**: cors_misconfiguration (allowlist feed), csrf
  (sibling subdomain foothold), xss (content serving on trusted
  origin), authentication_jwt (OAuth redirect abuse).
- **Chains-from**: DNS misconfiguration; decommissioned services
  without DNS cleanup.

## Protocol and Transport Classes

### HTTP Request Smuggling
- **Grant**: front-end security control bypass; cross-user request
  capture (session hijack); cache poisoning; WebSocket handshake
  hijacking; response queue poisoning; HTTP/2 request tunnelling.
- **Require**: HTTP/2-to-HTTP/1 translating front-end; shared
  back-end connection pool; ambiguous parser at back-end.
- **Chains-to**: authentication_jwt (captured JWT → session hijack),
  xss (cache poisoning → XSS delivery),
  broken_function_level_authorization (bypass front-end auth →
  /admin).
- **Chains-from**: header_injection (CRLF reaches parser
  disagreement); HTTP/2 front-end configurations.

### Web Cache Poisoning
- **Grant**: stored XSS to every subsequent requester; cross-user
  redirection; cache-DoS; cross-user data leak via cached poisoned
  response.
- **Require**: unkeyed request component that modifies the response;
  intermediary HTTP cache serving the poisoned response.
- **Chains-to**: xss (cached XSS delivery), open_redirect (cached
  redirect), information_disclosure (cached cross-user data leak).
- **Chains-from**: header_injection (Host/X-Forwarded-* as unkeyed
  vectors), http_request_smuggling (smuggled request → poisoned
  cache), semantic_confusion (parser differentials).

### Semantic Confusion
- **Grant**: auth/ACL bypass, source disclosure, SSRF, local socket
  reach, unintended handler, attacker-controlled code resolution,
  client-side path traversal, XSS.
- **Require**: two or more components consuming the same
  attacker-influenced value with different semantic interpretation.
- **Chains-to**: the class the confusion enables — ssrf,
  path_traversal_lfi_rfi, http_request_smuggling, rce, xss.
- **Chains-from**: any multi-component processing chain with
  attacker-influenced input.

## Cryptographic and Logic Classes

### Cryptographic Failures
- **Grant**: padding oracle → session decrypt/hijack; ECB →
  attribute leak; nonce reuse → forgery; weak RNG → token
  prediction; hardcoded key → mass compromise; length extension →
  MAC forgery; timing → secret extraction.
- **Require**: endpoint that decrypts attacker-controlled ciphertext;
  static key material in source/binary/config; MAC comparison that
  short-circuits.
- **Chains-to**: authentication_jwt (session impersonation),
  broken_function_level_authorization (role-field forgery),
  information_disclosure (cross-user data leak).
- **Chains-from**: information_disclosure (leaked key material).

### Business Logic
- **Grant**: workflow bypass, state-machine abuse, domain invariant
  violation (conservation-of-value, uniqueness, monotonicity) —
  financial/entitlement impact.
- **Require**: model of the business domain; authenticated session.
- **Chains-to**: race_conditions (duplicate benefits), idor (operate
  on others' resources), broken_function_level_authorization (admin
  financial endpoints).
- **Chains-from**: race_conditions (concurrent invariant violation),
  idor (foreign resource operation).

### Race Conditions
- **Grant**: duplicate state changes, quota bypass, financial abuse,
  privilege errors, invariant violations under concurrent access.
- **Require**: read-modify-write without atomicity; multi-step
  workflow with observable intermediate state.
- **Chains-to**: idor (parallel reference creation), csrf (parallel
  victim actions), business_logic (conservation invariant violation),
  authentication_jwt (MFA bypass).
- **Chains-from**: any concurrent-accessible endpoint with
  non-atomic state transitions.

### DoS / Resource Exhaustion
- **Grant**: service unavailability, SLA breach, rate-limiter
  bypass, backend cascade.
- **Require**: user-reachable regex/decompression/GraphQL/XML/parser
  sink accepting attacker-controlled input.
- **Chains-to**: business_logic (state-exhaustion), cloud/*
  (cost-amplification), race_conditions (pipeline-under-load
  bypasses).
- **Chains-from**: any user input reaching a computationally
  expensive sink.

## AI/ML and Supply-Chain Classes

### LLM Prompt Injection
- **Grant**: model behavior change contrary to application policy;
  attacker-chosen tool arguments / HTML / SQL / shell / URL emitted
  by model; system prompt extraction.
- **Require**: LLM feature processing untrusted text;
  document/RAG/tool-metadata ingestion surface; model with tool-use
  capability.
- **Chains-to**: agentic_system_security (agent-authority
  propagation), xss (HTML output sink), sql_injection (SQL output
  sink), rce (shell/code output sink).
- **Chains-from**: document/RAG/tool-metadata ingestion;
  browser-rendered agent UIs.

### Agentic System Security
- **Grant**: confused-deputy tool invocation under the agent's
  effective authority (credentials, tools, resources, network,
  filesystem, delegated agents).
- **Require**: AI system with tool-selection capability; reachable
  tool/resource/prompt inventory.
- **Chains-to**: ssrf (via fetch_url tool), rce (via shell_exec
  tool), sql_injection (via SQL tool).
- **Chains-from**: llm_prompt_injection (instruction attack),
  information_disclosure (leaked tool inventory).

### Supply Chain / CI Integrity
- **Grant**: code execution on dev/CI via dependency install;
  secrets exfiltration from privileged runner; cloud credential
  theft via OIDC; production artifact substitution.
- **Require**: public-registry account (publish); phished/leaked
  maintainer account (hijack); pull_request_target misconfiguration.
- **Chains-to**: rce (code execution on every installer),
  information_disclosure (secrets exfil), cloud/* (OIDC →
  credentials).
- **Chains-from**: authentication_jwt (maintainer phishing/token
  leak).

## Operational Classes

### Logging / Alerting Failures
- **Grant**: extended attacker dwell time; impossible attribution;
  compound secret exposure via log leaks.
- **Require**: absent logging call; user-input sink reaching logger;
  permissive database role on audit tables.
- **Chains-to**: authentication_jwt (secrets-in-logs → credential
  recovery), information_disclosure (log-stored secrets).
- **Chains-from**: any application lacking security event logging.
