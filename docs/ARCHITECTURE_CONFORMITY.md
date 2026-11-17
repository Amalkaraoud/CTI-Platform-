# Architecture conformity review

This document compares the final architecture diagram and the PFE report
("Conception et developpement d'une plateforme CTI avec surveillance
automatisee du Dark Web") with the code in this repository. Every statement
below was checked against the source. Nothing is marked as working unless a
test or command actually ran.

Status legend: **Conform** (present and consistent), **Fixed** (gap closed in
this change), **Added, unwired** (library code plus tests, not yet connected
to the runtime), **Divergent** (code differs from the documents; a decision is
needed), **Unverified** (cannot be run in the review environment).

## 1. Matrix

| Area | Documents say | Repository state | Status |
|---|---|---|---|
| API | FastAPI, OpenAPI | FastAPI app, Swagger at `/api/docs` | Conform |
| Auth | JWT, RBAC | JWT, roles enforced by dependencies | Conform |
| Users, RBAC, audit in PostgreSQL | Report section 6 | `onyx_core/services/user_store.py` (tables `onyx_users`, `onyx_audit_log`); bootstrap accounts inserted once; loaded at API start when `POSTGRES_URL` is set, in-memory fallback otherwise | Fixed; tested on SQLite, not on PostgreSQL |
| Rate limiting | Per-client limits (6.2) | `RateLimitAuditMiddleware` (sliding window, strict budget on auth paths, 429 + `Retry-After`) | Fixed; wiring not run |
| Audit log | Structured trail (6.3) | JSON lines, secret scrubbing, optional file, PostgreSQL handler | Fixed; wiring not run |
| Celery | Workers and beat | Tasks registered (`onyx_api/tasks.py`), beat schedule resolves, worker and beat compose services | Fixed; not run (no Celery here) |
| Persistence worker | Redis Stream to Elasticsearch | Worker existed but nothing started it; `ioc-persister` compose service added | Fixed; not run |
| Neo4j relationship graph | Relationships in Neo4j | Persister projects each IOC (indicator, malware, actor, ATT&CK technique) into Neo4j through whitelisted Cypher; best effort, MongoDB traversal remains the fallback | Fixed; planning logic tested, writes not run |
| GraphQL (Strawberry) | Annex 6 | Schema at `/graphql`, JWT required, depth-limited, no IDE | Added; Strawberry absent, not executed |
| YARA / Sigma generation | 4.3, annex 4 | `onyx_analyzers/rules.py`, `POST /api/v1/rules/generate` | Fixed; YARA compilation not run |
| MISP / OpenCTI / Splunk export | SIEM / TIP integration | `export.py` plus `dispatch.py`, scheduled by Celery every 15 min, destinations from environment only; OpenCTI and Elastic through TAXII 2.1 | Fixed; tested against stand-in servers only |
| Wazuh export | Listed in the report | No connector | Not implemented |
| Scrapy collection | Scrapy + Playwright + BS4 | Declared in the crawler `pyproject.toml` but unused. `scrapy_spider.py` added (Privoxy/Tor proxy, one request per domain, UA rotation, kill switch); extraction in `page_extract.py` | Fixed; extraction tested, Scrapy crawl not run |
| Tor | NEWNYM, per-domain circuits, UA rotation | `circuit_rotator`, `tor_manager`; `tor-proxy` compose service on its own egress network | Conform in code; container not run |
| Data services in Compose | MongoDB, Elasticsearch, Qdrant, Redis, Postgres, Neo4j | All six added/present with the `infra/` configs; backend start does not hard-depend on the new ones | Fixed; YAML parsed, `docker compose up` not run |
| TLS 1.3 | Transport security | `infra/nginx/nginx.conf` (TLSv1.3 only, HSTS), compose profile `tls` | Added; not run |
| `x_onyx_` STIX properties | Custom properties | `onyx_source` / `onyx_tags` serialise as `x_onyx_source` / `x_onyx_tags` (by alias, used for MongoDB writes); legacy names still accepted on input | Fixed; tested |
| Decay worker | VALID/DEGRADING/STALE/OBSOLETE | Engine conform; the batch recalculation was disabled unless an env flag was set, now `true` by default in compose | Conform |
| TAXII 2.1, WebSocket + Redis pub/sub, 4-level degradation, refanging | As described | Present | Conform |
| SciBERT 768-d + Qdrant | NER, similarity | `ttp_mapper` loads SciBERT with keyword fallback, no weights shipped; RAG embeddings use Gemini (3072-d) | Divergent, see below |
| Dashboard libraries | Zod, force-graph, @google/genai | Absent. The assistant runs server-side in Python; `react-force-graph-3d` is used | Divergent; Zod not added (see below) |

## 2. Remaining divergences and why

1. **SciBERT versus Gemini embeddings.** The Qdrant collection is sized for Gemini vectors and replacing it would change retrieval behaviour and require model weights that cannot be downloaded here. The report should say that SciBERT serves NER and TTP mapping, and Gemini serves retrieval; or a second 768-d collection can be added once weights are available.
2. **Zod.** Adding `zod` to `package.json` without regenerating `package-lock.json` would break the Docker build (`npm ci`). Run `npm install zod` in `onyx-dashboard`, then validate the `/engines` responses in `src/lib/engines.ts`.
3. **Wazuh.** The report lists it; there is no connector. Wazuh ingests through its own decoders or CDB lists, which needs a decision on the integration mode.
4. **Users in memory without `POSTGRES_URL`.** Intentional for standalone mode (the 4-level degradation story).

## 3. Verification

Run in the review environment (Python 3.13): **116 tests passed** across `onyx-core/tests/unit` (without the two `hypothesis` files), `onyx-api/tests`, `onyx-analyzers/tests`, `onyx-connectors/tests`, `onyx-crawlers/tests`. YAML of `docker-compose.yml` and of the CI workflow parses.

Did not run: `test_decay_engine.py` and `test_confidence_composite.py` (need `hypothesis`, absent here, same before these changes); FastAPI start-up with the middleware and routers; Strawberry; Celery; Neo4j and PostgreSQL against real servers; Scrapy and Tor crawling; YARA compilation; real MISP, OpenCTI, Splunk; nginx TLS; `next build`; Docker builds and `docker compose up`.
