# Gatekeeper

Trust and safety API platform in Node.js: a multi-tenant abuse-detection service that scores sign-ups, logins, messages and payment attempts with a versioned rules engine and a risk model, returns an `allow`, `challenge` or `block` decision in one request, and delivers every decision to the tenant by signed webhook through SNS, SQS and Lambda. Tenants authenticate with OAuth 2.0 client credentials issued by the platform itself and integrate through a generated TypeScript SDK.

The API is NestJS, the worker is Express, both live in an Nx monorepo with the rule language and the event contracts as shared packages. Events and decisions live in a sharded MongoDB cluster; velocity counters live in DynamoDB with TTL. The AWS pieces (API Gateway, SNS, SQS, Lambda, DynamoDB, CloudWatch) are provisioned by Terraform against LocalStack, so the whole platform runs on a laptop and in CI with no AWS account and no card. The README says so here, first, and the Terraform section says exactly what changes for a real account.

**Status.** Design complete, build not started. This README describes the target system; the phase list at the end records what has landed.

## Ten-minute tour

The intended path once Phase 6 lands:

```bash
docker compose up -d --wait                  # mongos 27018 (2 shards), Redis 6381, LocalStack 4566, Jaeger 16688
make infra                                   # tflocal apply: API Gateway, SNS, SQS + DLQ, Lambda, DynamoDB, CloudWatch
make dev                                     # api 3100, worker 3101, demo webhook receiver 3102
npm run seed                                 # 3 tenants, rulesets, 5,000 events with four planted abuse patterns
scripts/token.sh tenant-a                    # OAuth 2.0 client credentials -> 15-minute JWT
scripts/replay.sh credential-stuffing        # one ASN hammering logins: decisions flip to block on the 11th
scripts/replay.sh disposable-signups         # burst of mailinator sign-ups: challenge, then block
curl -s localhost:3100/decisions?outcome=block | jq '.items[0].reasons'
awslocal sqs receive-message --queue-url .../webhook-deliveries-dlq   # the always-failing endpoint's dead letters
curl -s -X POST localhost:3100/webhook-endpoints/ep_fail/dead-letters/redeliver
open http://localhost:16688                  # one trace: SDK call, gateway, api, worker publish, Lambda delivery
```

## Architecture

```
Tenant backend ── @methos237/gatekeeper-sdk ──► API Gateway (LocalStack, usage plan)
                                                  │ proxy
                                                  ▼
                 POST /oauth/token  ◄──── api (NestJS :3100) ────► Redis (token buckets)
                 POST /events            │  zod validation, tenant from JWT
                 GET  /decisions         │  velocity counters ── DynamoDB (TTL)
                 POST /rulesets, dry-run │  rules evaluator (packages/rules) + ONNX risk score
                 webhook-endpoints, DLQ  │  MongoDB sharded: events, decisions, outbox, rulesets, tenants
                                         ▼
                                  worker (Express :3101) ── outbox ──► SNS decisions ──► SQS webhook-deliveries
                                                                                              │
                                                                     Lambda webhook-dispatcher (TypeScript)
                                                                     HMAC-signed POST to the tenant endpoint
                                                                     redrive after 5 ──► SQS webhook-deliveries-dlq

Terraform (infra/) provisions API Gateway, SNS, SQS, DLQ, Lambda, DynamoDB, CloudWatch on LocalStack
OpenTelemetry from api and worker ──► Jaeger (compose) and the Datadog Agent (free tier, optional profile)
```

| Package | Stack | Role | Port |
|---|---|---|---|
| `apps/api` | NestJS, Mongoose, zod, `jose`, ioredis | OAuth 2.0 token endpoint, events, decisions, rulesets, webhook endpoints, OpenAPI | 3100 |
| `apps/worker` | Express 5 | Outbox relay to SNS, dead-letter reads, health and lag | 3101 |
| `apps/webhook-dispatcher` | TypeScript Lambda (esbuild) | Signs and delivers one decision, throws on non-2xx so SQS retries | – |
| `packages/rules` | Pure TypeScript | Rule language AST, zod parser, evaluator, fast-check properties | – |
| `packages/contracts` | zod | Event schemas and the feature spec shared with the SDK and the model | – |
| `packages/sdk` | Generated (`@hey-api/openapi-ts`) | Published to GitHub Packages as `@methos237/gatekeeper-sdk` | – |
| `infra/` | Terraform | Modules `api-gateway`, `messaging`, `lambda`, `dynamodb`, `cloudwatch` | – |
| `model/` | scikit-learn, skl2onnx | Placeholder trainer, ONNX file, model card, feature spec | – |

## Stack

Node 26 · TypeScript · Nx · NestJS · Express 5 · MongoDB 8 (sharded) · DynamoDB · Redis · AWS SDK v3 · Terraform · LocalStack · API Gateway · Lambda · SNS · SQS · CloudWatch · `jose` · zod · onnxruntime-node · OpenTelemetry · Datadog (free tier) · Vitest · Supertest · Testcontainers · fast-check · k6 · GitHub Actions · GitHub Packages

Prerequisites: Docker with Compose v2, Node 26, Terraform, the LocalStack CLI with `tflocal` and `awslocal`. Exact versions are pinned when Phase 0 lands.

## Authentication: the platform issues its own tokens

`POST /oauth/token` implements the OAuth 2.0 client credentials grant. Tenants hold clients with Argon2-hashed secrets and scopes (`events:write`, `decisions:read`, `rules:write`, `webhooks:write`). Tokens are RS256 JWTs with a `kid`, 15-minute expiry, published keys at `/.well-known/jwks.json`, and two keys active during rotation so a rollover never fails a request. The tenant on every other endpoint comes from the token, never from the body; a token from tenant A reading tenant B's decision gets 404.

**Rate limiting.** One Lua script in Redis implements a token bucket per client, atomically, and the response carries `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset`; a 429 is a problem detail with `Retry-After`. Default 600 requests per minute per client, per-tenant override. `/oauth/token` has a separate per-IP bucket as bot protection. API Gateway's usage plan adds a coarse second limit in front.

**Errors.** RFC 9457 problem details from one exception filter; zod validation errors arrive as an `errors[]` list naming each field.

## Decisions

```http
POST /events
Authorization: Bearer eyJ...
Content-Type: application/json

{"type": "signup", "occurred_at": "2026-11-03T14:02:00Z",
 "actor": {"email": "x@mailinator.com", "ip": "203.0.113.9", "user_agent": "...", "account_id": null},
 "context": {"asn": 14061, "country": "US"}, "attributes": {"plan": "free"}}
```

```json
{"decision": "challenge", "reasons": [{"rule": "disposable-email", "weight": 40}, {"rule": "signup-velocity-ip-10m", "weight": 30}],
 "score": 0.71, "model_version": "gatekeeper-risk-v1", "ruleset_version": 7, "latency_ms": 23}
```

One request does the whole synchronous path: validate, read velocity counters from DynamoDB, evaluate the active ruleset, score with the model, store the event and the decision, write the outbox record in the same MongoDB transaction, answer. Target p95 under 100 ms locally; the measured number goes in this README when Phase 2 lands.

### Rules engine

`packages/rules` defines a small JSON rule language:

```json
{"id": "signup-velocity-ip-10m", "when": {"and": [{"eq": ["type", "signup"]}, {"gt": [{"velocity": ["ip", "10m"]}, 5]}]},
 "then": "challenge", "weight": 30}
```

Expressions are a typed AST (`and`, `or`, `not`, comparisons, `in_list`, `matches`, `velocity(dimension, window)`), parsed and validated by zod and evaluated by a pure function. Decision precedence is `block` over `challenge` over `allow`. Rulesets are versioned per tenant and activated atomically. `POST /rulesets/{version}/dry-run` replays the last N events through a candidate ruleset and returns the decision diff, so a tenant sees what a rule change does before it is live. Built-in lists ship with the platform: disposable email domains, hosting ASNs, test IP ranges. fast-check properties guarantee the evaluator never throws on a valid AST and that precedence holds.

**Velocity counters.** DynamoDB table `velocity` keyed by `tenant#dimension#value` and window start, one atomic `ADD` per event per dimension (ip, email domain, account, ASN) over 1, 10 and 60-minute windows, TTL on every item. DynamoDB is the right shape for this: hot keys, tiny items, atomic increments, automatic expiry.

### Risk model

A logistic regression over velocity counts, disposable-domain and hosting-ASN flags, hour of day, account age and tenant attributes, trained in the companion project Sightline and exported to ONNX. The api loads it with `onnxruntime-node` and attaches a score and `model_version` to every decision in shadow mode; nothing changes until a ruleset references `score`. Feature extraction is one pure function with the same fixture test in TypeScript here and Python in Sightline. `model/MODEL_CARD.md` records data, features, metrics and limits. A model that fails to load degrades the platform to rules only, with a logged warning and a test proving it.

## Delivery: SNS, SQS, Lambda, dead letters

The decision is written to an `outbox` collection in the same MongoDB transaction as the decision itself. The worker publishes outbox records to the SNS topic `decisions` with message attributes for routing; the SQS queue `webhook-deliveries` is subscribed; the Lambda `webhook-dispatcher` consumes it, loads the endpoint secret, signs the body with `X-Gatekeeper-Signature: t=<timestamp>,v1=<hmac-sha256>` and POSTs with a five-second timeout. A non-2xx throws, SQS retries with visibility backoff, and after five receives the message redrives to `webhook-deliveries-dlq`. The api exposes the DLQ per endpoint and a redeliver action. `traceparent` rides in the SNS attributes so the Lambda span joins the trace that started in the SDK.

Signature verification for integrators is documented in `docs/webhooks.md` and tested against the demo receiver.

## Terraform on LocalStack

`infra/` has five modules: `api-gateway` (REST API, HTTP proxy integration to the api, usage plan, stage `v1`), `messaging` (topic, queue, dead-letter queue, redrive policy, subscription), `lambda` (dispatcher bundle, SQS event source mapping, log group), `dynamodb` (velocity table with TTL) and `cloudwatch` (log groups, a metric filter on delivery failures, an alarm). CI runs `terraform fmt -check`, `validate`, `tflint`, `checkov`, then `plan` and `apply` against a LocalStack service container and pushes one message end to end.

**What is different on a real account.** Remove the LocalStack endpoint overrides from the provider, add a remote state backend, set the account id and region, and attach real IAM policies in place of LocalStack's permissive defaults. The resources, the modules and the event source mapping are the same. LocalStack community edition was chosen over the AWS free tier because the free tier requires a card and this project has a zero-cost rule.

## SDK

`@methos237/gatekeeper-sdk` is generated from the api's OpenAPI document (which is itself snapshot-tested so drift fails the build) and wrapped with token acquisition and refresh, 429 retry honoring `Retry-After`, and typed errors from problem details. Published to GitHub Packages with npm provenance on `sdk-v*` tags.

```ts
import { Gatekeeper } from "@methos237/gatekeeper-sdk";

const gk = new Gatekeeper({ clientId, clientSecret, baseUrl });
const { decision, reasons } = await gk.events.create({ type: "login", actor: { email, ip }, context: { asn } });
if (decision === "block") return deny(reasons);
```

## Design decisions

- **NestJS for the api, Express for the worker.** The api benefits from Nest's guards, interceptors and OpenAPI integration; the worker is a loop over a queue and gains nothing from a framework. Showing both idioms side by side is the point.
- **Issue our own OAuth 2.0 tokens.** A tenant integrating a trust and safety API expects client credentials, scopes and a JWKS endpoint. Delegating that to Keycloak would hide the part worth demonstrating.
- **MongoDB for events, DynamoDB for counters.** Events are documents with tenant-specific attributes and are queried by tenant and time; a sharded collection on `(tenant_id, occurred_at)` fits. Counters are hot, tiny and expire; DynamoDB atomic increments with TTL fit. One store for both would be worse at one of the two jobs.
- **A real sharded MongoDB cluster in compose.** Four containers instead of one, so "sharding" on the resume is backed by `sh.status()` and not a flag.
- **Outbox plus SNS and SQS plus Lambda, not a direct HTTP call from the api.** The decision must be durable before anyone tries to deliver it, retries must not block the request path, and dead letters must be visible. The pipeline costs four moving parts and buys all three.
- **Dry-run before activate.** A rules change in a trust and safety system is a production change. The diff is the review.
- **Shadow mode before the model decides anything.** Scores are logged and compared with rule outcomes for a period before a ruleset is allowed to use them.
- **Terraform, not CDK or a serverless framework.** Terraform is what the postings name, and the modules read the same against LocalStack and a real account.
- **API only, no dashboard.** The console belongs to Tally and the Angular dashboard to Sightline; a third UI here would be padding.
- **Zero cost.** LocalStack community, Datadog free tier, GitHub Packages and Actions free for public repos. No AWS account is created for this project.

## Tests

Planned, enforced in CI from Phase 0:

| Level | Where | What |
|---|---|---|
| Property (fast-check) | `packages/rules` | evaluator never throws on a valid AST, precedence holds, dry-run diff is symmetric |
| Unit | api, worker, dispatcher | token issuance and validation, rotation, scope guard, rate limiter with a fake clock, signature recipe, feature extraction fixture shared with Sightline |
| Integration (Testcontainers) | api | MongoDB and LocalStack: tenant isolation, decisions on the seeded abuse patterns, DynamoDB counters, outbox in the same transaction |
| Infrastructure | `infra/` | fmt, validate, tflint, checkov, plan and apply on LocalStack, one message end to end through SNS, SQS and Lambda |
| Contract | `packages/sdk` | regenerated SDK must match the committed one; Supertest against the running api |
| Load (manual) | `load/` | k6 at 200 virtual users for two minutes; p95, error rate and 429 behaviour recorded here |

## Phases

Each phase is a branch merged by pull request and tracked as a GitHub issue.

- [ ] 0 Nx workspace, compose, CI
- [ ] 1 Tenants, OAuth 2.0 client credentials, rate limiting, event ingestion
- [ ] 2 Rules engine, velocity counters, decisions
- [ ] 3 Terraform on LocalStack: API Gateway, SNS, SQS, Lambda dispatcher, CloudWatch
- [ ] 4 Generated SDK on GitHub Packages, Datadog free tier
- [ ] 5 Risk model from Sightline, shadow mode, k6 load test
- [ ] 6 Observability, demo script, README polish
- [ ] 7 Stretch: SAML service provider, Temporal delivery workflow, Prisma side table, Kustomize manifests, GraphQL read API

## Out of scope, on purpose

A deployment to a real AWS account, a UI, SAML, billing, and any detection that needs real traffic data: every event in this repository is synthetic, including the four planted abuse patterns the seed ruleset must catch.

## License

Copyright (C) 2026 James Knox Polk

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. See [LICENSE](LICENSE).
