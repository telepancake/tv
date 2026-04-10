-- tv.sql — all static SQL for the tv process trace viewer.
--
-- Three sections, separated by the sentinel  --%%  on its own line:
--   1. SCHEMA  – base tables for trace ingest
--   2. SETUP   – indexes, UI state tables, pane tables
--   3. FTS     – full-text search index construction
--
-- main.c embeds this file (via tv_sql.h) and passes each section
-- to the engine as a const char*.

-- ── SCHEMA ────────────────────────────────────────────────────────────
CREATE TABLE processes(
    tgid INTEGER PRIMARY KEY, pid INT, nspid INT, nstgid INT,
    ppid INT, exe TEXT, cwd TEXT, argv TEXT, env TEXT, auxv TEXT,
    first_ts REAL, last_ts REAL);
CREATE TABLE events(
    id INTEGER PRIMARY KEY, tgid INT NOT NULL, ts REAL NOT NULL,
    event TEXT NOT NULL);
CREATE TABLE open_events(
    eid INTEGER PRIMARY KEY, path TEXT, flags TEXT, fd INT, err INT);
CREATE TABLE io_events(
    eid INTEGER PRIMARY KEY, stream TEXT NOT NULL, len INT, data TEXT);
CREATE TABLE exit_events(
    eid INTEGER PRIMARY KEY, status TEXT, code INT,
    signal INT, core_dumped INT, raw INT);
CREATE TABLE cwd_cache(tgid INTEGER PRIMARY KEY, cwd TEXT);
CREATE TABLE inbox(
    id INTEGER PRIMARY KEY, kind TEXT NOT NULL, data TEXT NOT NULL);

--%% SETUP
CREATE INDEX IF NOT EXISTS ix_ev_tg ON events(tgid);
CREATE INDEX IF NOT EXISTS ix_ev_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_op_pa ON open_events(path);
CREATE INDEX IF NOT EXISTS ix_ex_co ON exit_events(code);
CREATE INDEX IF NOT EXISTS ix_pr_pp ON processes(ppid);
CREATE TABLE IF NOT EXISTS expanded(
    id TEXT PRIMARY KEY, ex INT DEFAULT 1);
INSERT OR IGNORE INTO expanded(id,ex)
    SELECT CAST(tgid AS TEXT),1 FROM processes;
CREATE TABLE IF NOT EXISTS state(
    cursor INT DEFAULT 0, scroll INT DEFAULT 0,
    focus INT DEFAULT 0, dcursor INT DEFAULT 0, dscroll INT DEFAULT 0,
    ts_mode INT DEFAULT 0, sort_key INT DEFAULT 0, grouped INT DEFAULT 1,
    search TEXT DEFAULT '', evfilt TEXT DEFAULT '',
    rows INT DEFAULT 24, cols INT DEFAULT 80,
    base_ts REAL DEFAULT 0, has_fts INT DEFAULT 0, mode INT DEFAULT 0,
    lp_filter INT DEFAULT 0, dep_filter INT DEFAULT 0,
    dep_root TEXT DEFAULT '', status TEXT DEFAULT '');
INSERT OR IGNORE INTO state(base_ts)
    VALUES((SELECT COALESCE(MIN(ts),0) FROM events));
CREATE TABLE IF NOT EXISTS lpane(
    rownum INTEGER PRIMARY KEY, id TEXT NOT NULL,
    parent_id TEXT, style TEXT DEFAULT 'normal',
    text TEXT NOT NULL, visible INT DEFAULT 1);
CREATE TABLE IF NOT EXISTS rpane(
    rownum INTEGER PRIMARY KEY, style TEXT DEFAULT 'normal',
    text TEXT NOT NULL, link_mode INT DEFAULT -1,
    link_id TEXT DEFAULT '', section TEXT DEFAULT '',
    visible INT DEFAULT 1);
CREATE TABLE IF NOT EXISTS search_hits(id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS outbox(
    id INTEGER PRIMARY KEY CHECK(id=1),
    rl INT DEFAULT 0, rr INT DEFAULT 0);
INSERT OR IGNORE INTO outbox VALUES(1,0,0);

--%% FTS
CREATE VIRTUAL TABLE fts USING fts5(
    id UNINDEXED, source, content, tokenize='unicode61');
INSERT INTO fts(id,source,content)
    SELECT tgid,'argv',argv FROM processes WHERE argv IS NOT NULL;
INSERT INTO fts(id,source,content)
    SELECT tgid,'env',env FROM processes WHERE env IS NOT NULL;
INSERT INTO fts(id,source,content)
    SELECT e.tgid,'io',i.data FROM io_events i
    JOIN events e ON e.id=i.eid WHERE i.data IS NOT NULL;
INSERT INTO fts(id,source,content)
    SELECT tgid,'open',GROUP_CONCAT(path,char(10))
    FROM(SELECT DISTINCT e.tgid,o.path
         FROM open_events o JOIN events e ON e.id=o.eid)
    GROUP BY tgid;
UPDATE state SET has_fts=1;
