"""SQLite store for Oracle Intelligence (own file; the dev gate and other stores are untouched).

Forward migrations (`MIGRATIONS[i]` upgrades version i -> i+1, same pattern as dev_governance/store.py);
a DB newer than this code is refused. Raw records live in `intelligence_records` (UPDATE and DELETE are
blocked by triggers); processed observations/documents and the search index are separate tables.
"""
from __future__ import annotations
import os
import sqlite3
import threading
from typing import Optional

from dev_governance import fsperm as _fsperm

SCHEMA_VERSION = 3

M1 = [
    "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)",
    """CREATE TABLE intelligence_sources (
        source_id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, category TEXT NOT NULL, kind TEXT NOT NULL,
        uri TEXT, description TEXT NOT NULL, license_note TEXT NOT NULL, authorized_by TEXT NOT NULL,
        allowed_callers TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL)""",
    """CREATE TABLE intelligence_records (
        record_id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES intelligence_sources(source_id),
        batch_id TEXT NOT NULL, raw_text TEXT NOT NULL, raw_format TEXT NOT NULL, content_hash TEXT NOT NULL,
        provenance_hash TEXT NOT NULL, retrieved_at TEXT NOT NULL, published_at TEXT, ingested_by TEXT NOT NULL,
        quarantined INTEGER NOT NULL DEFAULT 0, quarantine_reason TEXT,
        UNIQUE (source_id, content_hash))""",
    """CREATE TRIGGER intelligence_records_no_update BEFORE UPDATE ON intelligence_records
       BEGIN SELECT RAISE(ABORT, 'intelligence_records is write-once (update blocked)'); END""",
    """CREATE TRIGGER intelligence_records_no_delete BEFORE DELETE ON intelligence_records
       BEGIN SELECT RAISE(ABORT, 'intelligence_records is write-once (delete blocked)'); END""",
    """CREATE TABLE intelligence_processed (
        record_id TEXT PRIMARY KEY REFERENCES intelligence_records(record_id), kind TEXT NOT NULL,
        entity TEXT, metric TEXT, obs_date TEXT, value REAL, unit TEXT, title TEXT, text TEXT NOT NULL,
        classification TEXT NOT NULL, tags TEXT NOT NULL, processor_version TEXT NOT NULL, processed_at TEXT NOT NULL)""",
    "CREATE INDEX idx_processed_series ON intelligence_processed(entity, metric, obs_date)",
    "CREATE TABLE intelligence_terms (term TEXT NOT NULL, record_id TEXT NOT NULL, PRIMARY KEY (term, record_id))",
    """CREATE TABLE intelligence_entities (
        entity_id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, entity_type TEXT NOT NULL,
        first_seen_record TEXT NOT NULL, created_at TEXT NOT NULL)""",
    """CREATE TABLE entity_relationships (
        from_entity TEXT NOT NULL, to_entity TEXT NOT NULL, rel_type TEXT NOT NULL, record_id TEXT NOT NULL,
        PRIMARY KEY (from_entity, to_entity, rel_type, record_id))""",
]
M2 = [
    """CREATE TABLE analytical_queries (
        query_id TEXT PRIMARY KEY, asked_by TEXT NOT NULL, question TEXT NOT NULL, question_hash TEXT NOT NULL,
        params TEXT NOT NULL, created_at TEXT NOT NULL, status TEXT NOT NULL, data_snapshot_hash TEXT,
        report_id TEXT)""",
    """CREATE TABLE hypotheses (
        hypothesis_id TEXT PRIMARY KEY, query_id TEXT NOT NULL REFERENCES analytical_queries(query_id),
        statement TEXT NOT NULL, body TEXT NOT NULL, review_date TEXT NOT NULL, status TEXT NOT NULL,
        created_at TEXT NOT NULL)""",
    """CREATE TABLE forecasts (
        forecast_id TEXT PRIMARY KEY, hypothesis_id TEXT, query_id TEXT, target TEXT NOT NULL, method TEXT NOT NULL,
        method_doc TEXT NOT NULL, horizon_days INTEGER NOT NULL, issued_at TEXT NOT NULL, params TEXT NOT NULL,
        point_value REAL, interval_low REAL, interval_high REAL, probability REAL, probability_method TEXT,
        status TEXT NOT NULL)""",
    """CREATE TABLE forecast_outcomes (
        outcome_id TEXT PRIMARY KEY, forecast_id TEXT NOT NULL REFERENCES forecasts(forecast_id),
        observed_value REAL NOT NULL, observed_at TEXT NOT NULL, record_id TEXT, error REAL, recorded_at TEXT NOT NULL)""",
    """CREATE TABLE intelligence_reports (
        report_id TEXT PRIMARY KEY, query_id TEXT NOT NULL REFERENCES analytical_queries(query_id),
        created_at TEXT NOT NULL, created_by TEXT NOT NULL, schema_version TEXT NOT NULL, report_hash TEXT NOT NULL,
        body TEXT NOT NULL)""",
]
M3 = [
    # connector source policy (license / terms / rate / robots) stored with the source; the policy text is frozen
    # (trigger), only the approver-controlled live switch may change.
    """CREATE TABLE intelligence_source_policies (
        source_id TEXT PRIMARY KEY REFERENCES intelligence_sources(source_id), connector TEXT NOT NULL,
        policy_json TEXT NOT NULL, policy_hash TEXT NOT NULL, recorded_by TEXT NOT NULL, recorded_at TEXT NOT NULL,
        live_enabled INTEGER NOT NULL DEFAULT 0, live_changed_by TEXT, live_changed_at TEXT)""",
    """CREATE TRIGGER intelligence_source_policies_frozen BEFORE UPDATE OF source_id, connector, policy_json, policy_hash,
       recorded_by, recorded_at ON intelligence_source_policies
       BEGIN SELECT RAISE(ABORT, 'intelligence_source_policies policy text is write-once (update blocked)'); END""",
    """CREATE TRIGGER intelligence_source_policies_no_delete BEFORE DELETE ON intelligence_source_policies
       BEGIN SELECT RAISE(ABORT, 'intelligence_source_policies is write-once (delete blocked)'); END""",
    # raw fetched responses, exactly as received (zlib-compressed), write-once, deduplicated by content hash
    """CREATE TABLE intelligence_raw_fetches (
        fetch_id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES intelligence_sources(source_id), dataset TEXT NOT NULL,
        cik TEXT NOT NULL, url TEXT NOT NULL, fetched_at TEXT NOT NULL, http_status INTEGER NOT NULL, content_type TEXT,
        size_bytes INTEGER NOT NULL, content_hash TEXT NOT NULL, raw_z BLOB NOT NULL, fetched_by TEXT NOT NULL,
        UNIQUE (source_id, content_hash))""",
    """CREATE TRIGGER intelligence_raw_fetches_no_update BEFORE UPDATE ON intelligence_raw_fetches
       BEGIN SELECT RAISE(ABORT, 'intelligence_raw_fetches is write-once (update blocked)'); END""",
    """CREATE TRIGGER intelligence_raw_fetches_no_delete BEFORE DELETE ON intelligence_raw_fetches
       BEGIN SELECT RAISE(ABORT, 'intelligence_raw_fetches is write-once (delete blocked)'); END""",
    # which ingest batch a stored response produced (absent link = stored but not yet ingested; safe to retry)
    """CREATE TABLE intelligence_fetch_links (
        fetch_id TEXT PRIMARY KEY REFERENCES intelligence_raw_fetches(fetch_id), batch_id TEXT, mapped_json TEXT NOT NULL,
        created_at TEXT NOT NULL)""",
    """CREATE TRIGGER intelligence_fetch_links_no_update BEFORE UPDATE ON intelligence_fetch_links
       BEGIN SELECT RAISE(ABORT, 'intelligence_fetch_links is write-once (update blocked)'); END""",
    """CREATE TRIGGER intelligence_fetch_links_no_delete BEFORE DELETE ON intelligence_fetch_links
       BEGIN SELECT RAISE(ABORT, 'intelligence_fetch_links is write-once (delete blocked)'); END""",
    # structured provenance for connector-derived records (accession number, form, fiscal period, filing date ...)
    """CREATE TABLE intelligence_edgar_provenance (
        record_id TEXT NOT NULL REFERENCES intelligence_records(record_id), fetch_id TEXT NOT NULL, kind TEXT NOT NULL,
        cik TEXT NOT NULL, concept TEXT, accession TEXT, form TEXT, fiscal_year INTEGER, fiscal_period TEXT,
        period_start TEXT, period_end TEXT, filed TEXT, frame TEXT, PRIMARY KEY (record_id, fetch_id))""",
    """CREATE TRIGGER intelligence_edgar_provenance_no_update BEFORE UPDATE ON intelligence_edgar_provenance
       BEGIN SELECT RAISE(ABORT, 'intelligence_edgar_provenance is write-once (update blocked)'); END""",
    """CREATE TRIGGER intelligence_edgar_provenance_no_delete BEFORE DELETE ON intelligence_edgar_provenance
       BEGIN SELECT RAISE(ABORT, 'intelligence_edgar_provenance is write-once (delete blocked)'); END""",
]
MIGRATIONS = [M1, M2, M3]


class Store:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._mem = sqlite3.connect(":memory:", check_same_thread=False) if path == ":memory:" else None
        if self._mem is not None:
            self._mem.isolation_level = None
        c = self.conn()
        try:
            c.execute("BEGIN IMMEDIATE")
            c.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
            row = c.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()
            ver = int(row[0]) if row else 0
            if ver > SCHEMA_VERSION:
                c.execute("ROLLBACK")
                raise RuntimeError(f"intelligence DB schema {ver} is newer than this code ({SCHEMA_VERSION})")
            for i in range(ver, SCHEMA_VERSION):
                for stmt in MIGRATIONS[i]:
                    c.execute(stmt)
            c.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
            c.execute("COMMIT")
        finally:
            self.release(c)
        if path != ":memory:":
            _fsperm.secure_file(path)

    def conn(self) -> sqlite3.Connection:
        if self._mem is not None:
            return self._mem
        c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        c.execute("PRAGMA foreign_keys=ON")
        return c

    def release(self, c) -> None:
        if c is not self._mem:
            c.close()

    def schema_version(self) -> int:
        c = self.conn()
        try:
            return int(c.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()[0])
        finally:
            self.release(c)

    # --- helpers used by the pipeline: every call opens/closes its own connection (file DB)
    def query(self, sql: str, args: tuple = ()) -> list:
        with self._lock:
            c = self.conn()
            try:
                return c.execute(sql, args).fetchall()
            finally:
                self.release(c)

    def execute(self, sql: str, args: tuple = ()) -> None:
        with self._lock:
            c = self.conn()
            try:
                c.execute(sql, args)
            finally:
                self.release(c)

    def transaction(self):
        return _Tx(self)

    def counts(self, source_ids: Optional[list] = None) -> dict:
        """Row counts. With `source_ids`, only records/queries/reports touching those sources are counted."""
        if source_ids is None:
            q = lambda sql: self.query(sql)[0][0]  # noqa: E731
            return {"sources": q("SELECT COUNT(*) FROM intelligence_sources WHERE enabled=1"),
                    "records": q("SELECT COUNT(*) FROM intelligence_records"),
                    "quarantined": q("SELECT COUNT(*) FROM intelligence_records WHERE quarantined=1"),
                    "queries": q("SELECT COUNT(*) FROM analytical_queries"),
                    "hypotheses": q("SELECT COUNT(*) FROM hypotheses"),
                    "reports": q("SELECT COUNT(*) FROM intelligence_reports")}
        ids = list(source_ids)
        ph = ",".join("?" * len(ids)) or "''"
        q = lambda sql: self.query(sql, tuple(ids))[0][0]  # noqa: E731
        return {"sources": len(ids),
                "records": q(f"SELECT COUNT(*) FROM intelligence_records WHERE source_id IN ({ph})"),
                "quarantined": q(f"SELECT COUNT(*) FROM intelligence_records WHERE quarantined=1 AND source_id IN ({ph})"),
                "queries": None, "hypotheses": None, "reports": None}


class _Tx:
    """BEGIN IMMEDIATE ... COMMIT; any exception (including a failed audit write) rolls back."""
    def __init__(self, store: Store):
        self.s = store

    def __enter__(self):
        self.s._lock.acquire()
        self.c = self.s.conn()
        self.c.execute("BEGIN IMMEDIATE")
        return self.c

    def __exit__(self, et, ev, tb):
        try:
            if et is None:
                self.c.execute("COMMIT")
            else:
                self.c.execute("ROLLBACK")
        finally:
            self.s.release(self.c)
            self.s._lock.release()
        return False


def default_store() -> Store:
    return Store(os.environ.get("PATIENCE_INTEL_DB", "patience_intelligence.db"))
