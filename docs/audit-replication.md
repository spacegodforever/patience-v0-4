# Audit log replication (C1)

The audit log is append-only and tamper-evident (SHA-256 hash chain, `.head` file, local
checkpoint). Local checks alone cannot catch an attacker who rewrites the log, head and
checkpoint consistently. Replication adds a copy the attacker is assumed not to control,
plus a signed checkpoint of the newest record. It is not an immutability guarantee.

## Configure
| Env | Meaning |
|---|---|
| `PATIENCE_AUDIT_SIGNING_KEY` | `hmac:<secret ≥32 chars>` or `ed25519:<base64 32-byte seed>`. Set in the environment or an untracked `.env`; never commit it. |
| `PATIENCE_AUDIT_VERIFY_KEY` | Optional `ed25519:<base64 public key>` so a verifier needs no private key. |
| `PATIENCE_AUDIT_REPLICA_DIR` | Replica directory, ideally on another host (NFS/SMB/sshfs mount). |
| `PATIENCE_AUDIT_REPLICA_REQUIRED` | `1` makes `audit.append` raise when replication fails. The local line is already written at that point, so the replica lags and `verify` reports it. Default is best effort. |

Generate an HMAC key: `python -c "import secrets;print('hmac:'+secrets.token_urlsafe(48))"`.
With HMAC, anyone holding the key can forge checkpoints; prefer Ed25519 and keep the seed off the
audited host where possible.

## Commands
    python audit_replica.py verify   # 0 = local log matches replica and signed checkpoint
    python audit_replica.py sync     # backfill missing records; refuses if logs diverge

`verify` fails on: bad checkpoint signature, replica shorter than / disagreeing with its
checkpoint, any local line differing from the replica (rewrite), local log shorter than
the replica (truncation), or a broken local chain. Records not yet replicated show as `lag`.

## Sink interface (S3, remote append API)
Implement and install with `audit_replica.set_sink(MySink())`:

```python
class ReplicaSink(Protocol):
    def append_lines(self, lines: list[str]) -> None   # append-only; never overwrite
    def read_lines(self) -> list[str]
    def put_checkpoint(self, blob: bytes) -> None      # latest signed checkpoint JSON
    def get_checkpoint(self) -> bytes | None
```

- **S3:** write each line as its own object (`log/<seq:012d>.json`) in a bucket with Object Lock
  (compliance or governance mode) and versioning. `read_lines` lists keys in order, and the
  checkpoint goes to `checkpoint.json`. The credentials on the audited host should allow only `PutObject`.
- **Remote append API:** `POST /append` with the lines; the server rejects any seq that is not
  `last+1` or any prev that does not match. `GET /lines` and `GET/PUT /checkpoint`. Authenticate with a
  key that cannot delete.

Neither of these is implemented here; only `DirectorySink` ships.
