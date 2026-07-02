# Target Groups

AstraNull does not discover inventory. Customers create **target groups** manually or through CSV/API import.

## Target group purpose

A target group represents one business service or protected zone.

Examples:

- `Retail Checkout - Production`
- `Customer API Gateway - Production`
- `Public DNS - Primary Zone`
- `Gaming Edge - Europe`
- `VPN Gateway - Corporate`
- `Canary Behind Cloudflare - Origin Zone`

## Target group fields

| Field | Required | Description |
|---|---:|---|
| Name | Yes | Human-readable group name. |
| Environment | Yes | Prod, staging, pre-prod, lab. |
| Business criticality | Yes | Critical, high, medium, low. |
| Owner | Yes | Customer-side responsible person/team. |
| Emergency contact | Required for high-scale | Person reachable during test. |
| Timezone | Yes | Used for maintenance windows and schedules. |
| Default test window | Optional | Allowed safe-test schedule. |
| High-scale allowed | Optional | Whether customer may request SOC-gated test. |
| Notes | Optional | Architecture notes, protected path, known limits. |

## Target types

| Type | Required fields | Example |
|---|---|---|
| FQDN | hostname, expected protocol/port | `api.example.com:443` |
| URL | URL, method, expected behavior | `https://api.example.com/health` |
| IP/Port | IP, protocol, port | `203.0.113.10 TCP/443` |
| DNS service | domain, resolver/authoritative mode | `example.com` authoritative |
| Canary endpoint | hostname/IP/port/path, agent binding | `/astranull-canary/{nonce}` |
| Internal agent binding | agent ID, observation mode | `agent-prod-origin-01` |

## Expected behaviors

Expected behavior turns observations into verdicts.

| Expected behavior | Meaning |
|---|---|
| Must be blocked before origin | Traffic should not be observed by agent. |
| Must reach canary only through protected path | Agent should observe only protected-path nonce. |
| Must not expose direct IP | Direct IP request should fail and agent should not observe it. |
| Must challenge/rate-limit | External response should show configured challenge/block/limit behavior. |
| Must allow baseline health | Normal low-rate health request should succeed. |
| Must reject forbidden methods | Unwanted methods should be blocked or safely handled. |
| Must not respond on forbidden port | Port should be closed/filtered or blocked before agent. |

## Target group tabs

| Tab | Purpose |
|---|---|
| Overview | Readiness score, risk, latest test status, top findings. |
| Targets | Add/edit/delete FQDNs, IPs, ports, URLs, DNS services, canaries. |
| Expected Behavior | Define what should happen for each class of probe. |
| Agents | Bind agents/canaries to target group and verify placement. |
| Checks | Enable safe checks and request high-scale checks. |
| Runs | View historical test runs and evidence. |
| Findings | Active issues and remediation progress. |
| Settings | Owners, schedules, notification rules, high-scale permissions. |

## CSV import format

```csv
target_group,environment,target_type,target,protocol,port,expected_behavior,agent_id,criticality,owner
Retail Checkout,prod,url,https://shop.example.com/checkout,HTTPS,443,must_challenge_or_rate_limit,agent-123,critical,platform-team
Retail Checkout,prod,ip,203.0.113.10,TCP,443,must_be_blocked_before_origin,agent-123,critical,platform-team
```

## Completion criteria

Target groups are complete when:

- customers can create them manually,
- targets can be added/edited/deleted/imported,
- expected behavior is defined per target/check,
- agents can be bound,
- runs and findings are visible by group,
- high-scale request eligibility can be configured.
