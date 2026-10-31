# Study and reading list

Only well-known references; no links are given where the exact URL was not verified. Search by title.

## Access control and gate design (api.py, governance, policy)
- Saltzer and Schroeder, "The Protection of Information in Computer Systems" (1975): fail-safe defaults, complete mediation, least privilege, separation of privilege.
- OWASP Application Security Verification Standard (ASVS): access control and authentication chapters.
- OWASP Top 10 for Large Language Model Applications: prompt injection, excessive agency.

## Approver identity and sessions (approvers.py, coordinator sessions)
- NIST SP 800-63B, Digital Identity Guidelines: Authentication and Lifecycle Management (memorized secrets, throttling).
- RFC 7914, The scrypt Password-Based Key Derivation Function.
- OWASP Session Management Cheat Sheet; OWASP Cross-Site Request Forgery Prevention Cheat Sheet.
- RFC 2104, HMAC (signed links).

## Audit log (audit.py)
- Schneier and Kelsey, "Secure Audit Logs to Support Computer Forensics" (ACM TISSEC, 1999).
- Crosby and Wallach, "Efficient Data Structures for Tamper-Evident Logging" (USENIX Security 2009).
- RFC 6962, Certificate Transparency (Merkle-tree logs, signed tree heads); topic: Sigstore Rekor transparency log.

## Approval fatigue and human oversight
- Bainbridge, "Ironies of Automation" (Automatica, 1983).
- Parasuraman and Riley, "Humans and Automation: Use, Misuse, Disuse, Abuse" (Human Factors, 1997).
- Topic: alert fatigue in clinical decision support and security operations.

## Ingestion, queues, idempotency, HA (design/ingestion.md)
- Kleppmann, *Designing Data-Intensive Applications* (O'Reilly, 2017): logs, replication, exactly-once myths.
- Nygard, *Release It!* (Pragmatic Bookshelf): timeouts, bulkheads, circuit breakers.
- Beyer et al., *Site Reliability Engineering* (O'Reilly, 2016): handling overload, cascading failures.
- Topics: transactional outbox pattern; idempotency keys in payment APIs (Stripe documents its `Idempotency-Key` header); exponential backoff with jitter; SQLite WAL mode (SQLite documentation); Postgres `SKIP LOCKED`.
- Ongaro and Ousterhout, "In Search of an Understandable Consensus Algorithm" (Raft, USENIX ATC 2014), if moving to replicated state.
- JSON Schema specification; Pydantic documentation (strict models, `extra="forbid"`).

## Architecture records
- Michael Nygard, "Documenting Architecture Decisions" (2011 blog post introducing ADRs).

## Frontend (ui/coordinator)
- React and Vite official documentation; MDN on `SameSite` cookies and `HttpOnly`.
