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

CREATE TABLE IF NOT EXISTS _config(key TEXT PRIMARY KEY, val TEXT);
CREATE TABLE IF NOT EXISTS expanded(id TEXT PRIMARY KEY, ex INT DEFAULT 1);

--%% INGEST
WITH src AS (
    SELECT DISTINCT
        CAST(json_extract(data,'$.tgid') AS INT) AS tgid,
        CAST(json_extract(data,'$.pid') AS INT) AS pid,
        CAST(json_extract(data,'$.ppid') AS INT) AS ppid,
        CAST(json_extract(data,'$.nspid') AS INT) AS nspid,
        CAST(json_extract(data,'$.nstgid') AS INT) AS nstgid,
        CAST(json_extract(data,'$.ts') AS REAL) AS ts
    FROM inbox
    WHERE kind='trace'
      AND json_extract(data,'$.event') IS NOT NULL
      AND json_extract(data,'$.tgid') IS NOT NULL
      AND CAST(json_extract(data,'$.tgid') AS TEXT)
          != COALESCE((SELECT val FROM _config WHERE key='own_tgid'),'')
)
INSERT OR IGNORE INTO processes(tgid,pid,ppid,nspid,nstgid,first_ts,last_ts)
    SELECT tgid,pid,ppid,nspid,nstgid,ts,ts FROM src;
WITH src AS (
    SELECT DISTINCT CAST(json_extract(data,'$.tgid') AS TEXT) AS id
    FROM inbox
    WHERE kind='trace'
      AND json_extract(data,'$.event') IS NOT NULL
      AND json_extract(data,'$.tgid') IS NOT NULL
      AND CAST(json_extract(data,'$.tgid') AS TEXT)
          != COALESCE((SELECT val FROM _config WHERE key='own_tgid'),'')
)
INSERT OR IGNORE INTO expanded(id,ex)
    SELECT id,1 FROM src;
WITH src AS (
    SELECT id,
           CAST(json_extract(data,'$.tgid') AS INT) AS tgid,
           json_extract(data,'$.path') AS path
    FROM inbox
    WHERE kind='trace'
      AND json_extract(data,'$.event')='CWD'
), last_cwd AS (
    SELECT s.tgid, s.path
    FROM src s
    WHERE s.id = (SELECT MAX(s2.id) FROM src s2 WHERE s2.tgid=s.tgid)
)
INSERT OR REPLACE INTO cwd_cache(tgid,cwd)
    SELECT tgid,path FROM last_cwd;
WITH src AS (
    SELECT id,
           CAST(json_extract(data,'$.tgid') AS INT) AS tgid,
           json_extract(data,'$.path') AS path
    FROM inbox
    WHERE kind='trace'
      AND json_extract(data,'$.event')='CWD'
), last_cwd AS (
    SELECT s.tgid, s.path
    FROM src s
    WHERE s.id = (SELECT MAX(s2.id) FROM src s2 WHERE s2.tgid=s.tgid)
)
UPDATE processes
SET cwd=(SELECT path FROM last_cwd WHERE tgid=processes.tgid)
WHERE tgid IN (SELECT tgid FROM last_cwd);
WITH src AS (
    SELECT id,
           CAST(json_extract(data,'$.tgid') AS INT) AS tgid,
           data
    FROM inbox
    WHERE kind='trace'
      AND json_extract(data,'$.event')='EXEC'
), last_exec AS (
    SELECT s.tgid, s.data
    FROM src s
    WHERE s.id = (SELECT MAX(s2.id) FROM src s2 WHERE s2.tgid=s.tgid)
)
UPDATE processes
SET exe=(SELECT json_extract(data,'$.exe') FROM last_exec WHERE tgid=processes.tgid),
    argv=(SELECT CASE WHEN json_type(data,'$.argv')='array' THEN
                (SELECT GROUP_CONCAT(value,char(10)) FROM json_each(json_extract(data,'$.argv')))
                ELSE NULL END
          FROM last_exec WHERE tgid=processes.tgid),
    env=(SELECT CASE WHEN json_type(data,'$.env')='object' THEN
                (SELECT GROUP_CONCAT(key||'='||value,char(10)) FROM json_each(json_extract(data,'$.env')))
                ELSE NULL END
         FROM last_exec WHERE tgid=processes.tgid),
    auxv=(SELECT CASE WHEN json_type(data,'$.auxv')='object' THEN
                 (SELECT GROUP_CONCAT(key||'='||value,char(10)) FROM json_each(json_extract(data,'$.auxv')))
                 ELSE NULL END
          FROM last_exec WHERE tgid=processes.tgid)
WHERE tgid IN (SELECT tgid FROM last_exec);
CREATE TEMP TABLE IF NOT EXISTS _trace_event_ids(
    inbox_id INTEGER PRIMARY KEY,
    eid INTEGER NOT NULL
);
DELETE FROM _trace_event_ids;
WITH event_rows AS (
    SELECT id
    FROM inbox
    WHERE kind='trace'
      AND json_extract(data,'$.event') IN ('EXEC','EXIT','STDOUT','STDERR')
    UNION ALL
    SELECT s.id
    FROM inbox s
    WHERE s.kind='trace'
      AND json_extract(s.data,'$.event')='OPEN'
      AND NOT is_sys_path(
          resolve_path(
              json_extract(s.data,'$.path'),
              COALESCE(
                  (SELECT json_extract(c.data,'$.path')
                   FROM inbox c
                   WHERE c.kind='trace'
                     AND json_extract(c.data,'$.event')='CWD'
                     AND CAST(json_extract(c.data,'$.tgid') AS INT)=CAST(json_extract(s.data,'$.tgid') AS INT)
                     AND c.id<=s.id
                   ORDER BY c.id DESC LIMIT 1),
                  (SELECT cwd FROM cwd_cache WHERE tgid=CAST(json_extract(s.data,'$.tgid') AS INT))
              )
          ),
          COALESCE(json_extract(s.data,'$.flags[0]'),'O_RDONLY')
      )
)
INSERT INTO _trace_event_ids(inbox_id,eid)
    SELECT id,
           COALESCE((SELECT MAX(id) FROM events),0) + ROW_NUMBER()OVER(ORDER BY id)
    FROM event_rows;
WITH src AS (
    SELECT id,
           CAST(json_extract(data,'$.tgid') AS INT) AS tgid,
           CAST(json_extract(data,'$.ts') AS REAL) AS ts,
           json_extract(data,'$.event') AS event
    FROM inbox
    WHERE kind='trace'
      AND json_extract(data,'$.event') IN ('EXEC','EXIT','STDOUT','STDERR')
    UNION ALL
    SELECT s.id,
           CAST(json_extract(s.data,'$.tgid') AS INT),
           CAST(json_extract(s.data,'$.ts') AS REAL),
           'OPEN'
    FROM inbox s
    WHERE s.kind='trace'
      AND json_extract(s.data,'$.event')='OPEN'
      AND EXISTS(SELECT 1 FROM _trace_event_ids m WHERE m.inbox_id=s.id)
)
INSERT INTO events(id,tgid,ts,event)
    SELECT m.eid, src.tgid, src.ts, src.event
    FROM src
    JOIN _trace_event_ids m ON m.inbox_id=src.id;
WITH src AS (
    SELECT s.id,
           resolve_path(
               json_extract(s.data,'$.path'),
               COALESCE(
                   (SELECT json_extract(c.data,'$.path')
                    FROM inbox c
                    WHERE c.kind='trace'
                      AND json_extract(c.data,'$.event')='CWD'
                      AND CAST(json_extract(c.data,'$.tgid') AS INT)=CAST(json_extract(s.data,'$.tgid') AS INT)
                      AND c.id<=s.id
                    ORDER BY c.id DESC LIMIT 1),
                   (SELECT cwd FROM cwd_cache WHERE tgid=CAST(json_extract(s.data,'$.tgid') AS INT))
               )
           ) AS path,
           COALESCE(json_extract(s.data,'$.flags[0]'),'O_RDONLY') AS flag0,
           s.data
    FROM inbox s
    WHERE s.kind='trace'
      AND json_extract(s.data,'$.event')='OPEN'
)
INSERT INTO open_events(eid,path,flags,fd,err)
    SELECT m.eid,
           path,
           CASE WHEN json_type(data,'$.flags')='array' THEN
               (SELECT GROUP_CONCAT(value,'|') FROM json_each(json_extract(data,'$.flags')))
               ELSE NULL END,
           json_extract(data,'$.fd'),
           json_extract(data,'$.err')
    FROM src
    JOIN _trace_event_ids m ON m.inbox_id=src.id
    WHERE NOT is_sys_path(path, flag0);
WITH src AS (
    SELECT id,data
    FROM inbox
    WHERE kind='trace'
      AND json_extract(data,'$.event')='EXIT'
)
INSERT INTO exit_events(eid,status,code,signal,core_dumped,raw)
    SELECT m.eid,
           json_extract(data,'$.status'),
           json_extract(data,'$.code'),
           json_extract(data,'$.signal'),
           json_extract(data,'$.core_dumped'),
           json_extract(data,'$.raw')
    FROM src
    JOIN _trace_event_ids m ON m.inbox_id=src.id;
WITH src AS (
    SELECT id,data
    FROM inbox
    WHERE kind='trace'
      AND json_extract(data,'$.event') IN ('STDOUT','STDERR')
)
INSERT INTO io_events(eid,stream,len,data)
    SELECT m.eid,
           json_extract(data,'$.event'),
           json_extract(data,'$.len'),
           json_extract(data,'$.data')
    FROM src
    JOIN _trace_event_ids m ON m.inbox_id=src.id;
WITH src AS (
    SELECT CAST(json_extract(data,'$.tgid') AS INT) AS tgid,
           MIN(CAST(json_extract(data,'$.ts') AS REAL)) AS min_ts,
           MAX(CAST(json_extract(data,'$.ts') AS REAL)) AS max_ts
    FROM inbox
    WHERE kind='trace'
      AND json_extract(data,'$.event') IS NOT NULL
      AND json_extract(data,'$.tgid') IS NOT NULL
    GROUP BY CAST(json_extract(data,'$.tgid') AS INT)
)
UPDATE processes
SET first_ts=MIN(first_ts, (SELECT min_ts FROM src WHERE tgid=processes.tgid)),
    last_ts=MAX(last_ts, (SELECT max_ts FROM src WHERE tgid=processes.tgid))
WHERE tgid IN (SELECT tgid FROM src);
DELETE FROM inbox WHERE kind='trace';

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
    dep_root TEXT DEFAULT '', status TEXT DEFAULT '',
    cursor_id TEXT DEFAULT '');
INSERT OR IGNORE INTO state(base_ts)
    VALUES((SELECT COALESCE(MIN(ts),0) FROM events));
CREATE TABLE IF NOT EXISTS search_hits(id TEXT PRIMARY KEY);
-- Temp table for file tree (mode=1), populated by build_ftree() SQL function.
CREATE TEMP TABLE IF NOT EXISTS _ftree(
    rownum INTEGER PRIMARY KEY, id TEXT NOT NULL,
    parent_id TEXT, style TEXT DEFAULT 'normal', text TEXT NOT NULL);

-- ── Layout definition (read by engine via tui_load_layout) ────────────
CREATE TEMP TABLE IF NOT EXISTS _layout(
    id INTEGER PRIMARY KEY,
    parent_id INT,
    type TEXT NOT NULL,
    name TEXT,
    weight INT DEFAULT 1,
    min_size INT DEFAULT 0,
    flags INT DEFAULT 0,
    col_name TEXT,
    col_width INT DEFAULT -1,
    col_align INT DEFAULT 0,
    col_overflow INT DEFAULT 1);
INSERT INTO _layout VALUES(1, NULL, 'hbox', NULL,  1, 0, 0, NULL, -1, 0, 1);
INSERT INTO _layout VALUES(2, 1,    'panel','lpane',1, 0, 1, 'text', -1, 0, 1);
INSERT INTO _layout VALUES(3, 1,    'panel','rpane',1, 0, 3, 'text', -1, 0, 1);

-- ── Dependency edge VIEW (used by modes 3-6) ─────────────────────────
-- Each row: (src=reader, dst=writer) for the same process group.
CREATE TEMP VIEW _dep_edges AS
    SELECT DISTINCT er.tgid,
        r.path AS src, w.path AS dst
    FROM open_events r JOIN events er ON er.id=r.eid
    JOIN open_events w JOIN events ew ON ew.id=w.eid
    WHERE er.tgid=ew.tgid
        AND r.path IS NOT NULL AND w.path IS NOT NULL
        AND r.path != w.path
        AND (r.flags LIKE 'O_RDONLY%' OR r.flags LIKE 'O_RDWR%')
        AND (w.flags LIKE 'O_WRONLY%' OR w.flags LIKE 'O_RDWR%'
             OR w.flags LIKE 'O_WRONLY,%' OR w.flags LIKE 'O_RDWR,%');

-- ── lpane VIEW for mode=0: process tree (grouped) ────────────────────
CREATE TEMP VIEW _lp_procs_tree AS
    WITH RECURSIVE flat(tgid, depth, sk) AS (
        SELECT p.tgid, 0,
            CASE (SELECT sort_key FROM state)
                WHEN 1 THEN p.first_ts WHEN 2 THEN p.last_ts
                ELSE CAST(p.tgid AS REAL) END
        FROM processes p
        WHERE (p.ppid IS NULL OR p.ppid NOT IN(SELECT tgid FROM processes))
        UNION ALL
        SELECT c.tgid, flat.depth+1,
            CASE (SELECT sort_key FROM state)
                WHEN 1 THEN c.first_ts WHEN 2 THEN c.last_ts
                ELSE CAST(c.tgid AS REAL) END
        FROM processes c JOIN flat ON c.ppid=flat.tgid
        JOIN expanded ex ON ex.id=CAST(flat.tgid AS TEXT) WHERE ex.ex=1
        ORDER BY 3
    )
    SELECT ROW_NUMBER()OVER()-1 AS rownum,
        CAST(f.tgid AS TEXT) AS id, CAST(p.ppid AS TEXT) AS parent_id,
        CASE WHEN f.tgid IN(SELECT CAST(id AS INT) FROM search_hits) THEN 'search'
             WHEN x.code IS NOT NULL AND x.code!=0 THEN 'error'
             WHEN x.signal IS NOT NULL THEN 'error' ELSE 'normal' END AS style,
        printf('%*s%s[%d] %s%s%s %s', f.depth*2, '',
            CASE WHEN NOT EXISTS(SELECT 1 FROM processes WHERE ppid=f.tgid) THEN '  '
                 WHEN COALESCE((SELECT ex FROM expanded WHERE id=CAST(f.tgid AS TEXT)),1) THEN '▼ '
                 ELSE '▶ ' END,
            f.tgid,
            COALESCE(REPLACE(p.exe,RTRIM(p.exe,REPLACE(p.exe,'/','')),''),'?'),
            CASE WHEN x.code IS NOT NULL AND x.code!=0 THEN ' ✗'
                 WHEN x.signal IS NOT NULL THEN printf(' ⚡%d',x.signal)
                 WHEN x.code IS NOT NULL THEN ' ✓' ELSE '' END,
            CASE WHEN (SELECT COUNT(*) FROM processes WHERE ppid=f.tgid)>0
                 THEN printf(' (%d)',(WITH RECURSIVE d(t) AS(
                     SELECT tgid FROM processes WHERE ppid=f.tgid
                     UNION ALL SELECT c2.tgid FROM processes c2 JOIN d ON c2.ppid=d.t)
                     SELECT COUNT(*) FROM d))
                 ELSE '' END,
            CASE WHEN p.last_ts-p.first_ts>=1 THEN printf('%.2fs',p.last_ts-p.first_ts)
                 WHEN p.last_ts-p.first_ts>=.001 THEN printf('%.1fms',(p.last_ts-p.first_ts)*1e3)
                 WHEN p.last_ts-p.first_ts>0 THEN printf('%.0fµs',(p.last_ts-p.first_ts)*1e6)
                 ELSE '' END) AS text
    FROM flat f
    JOIN processes p ON p.tgid=f.tgid
    LEFT JOIN events ev ON ev.tgid=f.tgid AND ev.event='EXIT'
    LEFT JOIN exit_events x ON x.eid=ev.id
    WHERE ((SELECT lp_filter FROM state)=0
        OR ((SELECT lp_filter FROM state)=1 AND f.tgid IN (
            WITH RECURSIVE
            failed(tgid) AS (
                SELECT p2.tgid FROM processes p2
                JOIN events ev2 ON ev2.tgid=p2.tgid AND ev2.event='EXIT'
                JOIN exit_events x2 ON x2.eid=ev2.id
                WHERE x2.signal IS NOT NULL
                   OR (x2.code IS NOT NULL AND x2.code!=0
                       AND EXISTS(SELECT 1 FROM open_events o2 JOIN events e2 ON e2.id=o2.eid
                                  WHERE e2.tgid=p2.tgid
                                    AND (o2.flags LIKE 'O_WRONLY%' OR o2.flags LIKE 'O_RDWR%')))
            ),
            visible(tgid) AS (
                SELECT tgid FROM failed
                UNION SELECT p3.ppid FROM processes p3 JOIN visible v ON p3.tgid=v.tgid
                WHERE p3.ppid IS NOT NULL AND p3.ppid IN(SELECT tgid FROM processes)
            )
            SELECT tgid FROM visible))
        OR ((SELECT lp_filter FROM state)=2 AND f.tgid IN (
            WITH RECURSIVE
            running(tgid) AS (
                SELECT tgid FROM processes WHERE NOT EXISTS(
                    SELECT 1 FROM events WHERE events.tgid=processes.tgid AND events.event='EXIT')
            ),
            visible2(tgid) AS (
                SELECT tgid FROM running
                UNION SELECT p3.ppid FROM processes p3 JOIN visible2 v ON p3.tgid=v.tgid
                WHERE p3.ppid IS NOT NULL AND p3.ppid IN(SELECT tgid FROM processes)
            )
            SELECT tgid FROM visible2)));

-- ── lpane VIEW for mode=0: process list (flat) ───────────────────────
CREATE TEMP VIEW _lp_procs_flat AS
    SELECT ROW_NUMBER()OVER(ORDER BY
            CASE (SELECT sort_key FROM state)
                WHEN 1 THEN p.first_ts WHEN 2 THEN p.last_ts
                ELSE CAST(p.tgid AS REAL) END
        )-1 AS rownum,
        CAST(p.tgid AS TEXT) AS id, CAST(p.ppid AS TEXT) AS parent_id,
        CASE WHEN p.tgid IN(SELECT CAST(id AS INT) FROM search_hits) THEN 'search'
             WHEN x.code IS NOT NULL AND x.code!=0 THEN 'error'
             WHEN x.signal IS NOT NULL THEN 'error' ELSE 'normal' END AS style,
        printf('[%d] %s%s %s', p.tgid,
            COALESCE(REPLACE(p.exe,RTRIM(p.exe,REPLACE(p.exe,'/','')),''),'?'),
            CASE WHEN x.code IS NOT NULL AND x.code!=0 THEN ' ✗'
                 WHEN x.signal IS NOT NULL THEN printf(' ⚡%d',x.signal)
                 WHEN x.code IS NOT NULL THEN ' ✓' ELSE '' END,
            CASE WHEN p.last_ts-p.first_ts>=1 THEN printf('%.2fs',p.last_ts-p.first_ts)
                 WHEN p.last_ts-p.first_ts>=.001 THEN printf('%.1fms',(p.last_ts-p.first_ts)*1e3)
                 WHEN p.last_ts-p.first_ts>0 THEN printf('%.0fµs',(p.last_ts-p.first_ts)*1e6)
                 ELSE '' END) AS text
    FROM processes p
    LEFT JOIN events ev ON ev.tgid=p.tgid AND ev.event='EXIT'
    LEFT JOIN exit_events x ON x.eid=ev.id;

-- ── lpane VIEW for mode=2: I/O output lines (grouped) ─────────────────
CREATE TEMP VIEW _lp_outputs_grouped AS
    SELECT ROW_NUMBER()OVER(ORDER BY sub.g_ts, sub.s_ts)-1 AS rownum,
        sub.id, sub.par AS parent_id, sub.sty AS style, sub.txt AS text
    FROM (
        SELECT 'io_'||CAST(e.tgid AS TEXT) AS id, NULL AS par, 'cyan_bold' AS sty,
            printf('── PID %d %s (%d lines) ──', e.tgid,
                COALESCE(REPLACE(p.exe,RTRIM(p.exe,REPLACE(p.exe,'/','')),''),'?'),
                COUNT(*)) AS txt,
            MIN(e.ts) AS g_ts, 0.0 AS s_ts
        FROM io_events i JOIN events e ON e.id=i.eid
        JOIN processes p ON p.tgid=e.tgid
        GROUP BY e.tgid
        UNION ALL
        SELECT CAST(e.id AS TEXT), 'io_'||CAST(e.tgid AS TEXT),
            CASE WHEN i.stream='STDERR' THEN 'error' ELSE 'normal' END,
            printf('  %s %s', i.stream,
                SUBSTR(REPLACE(COALESCE(i.data,''),char(10),'↵'),1,200)),
            (SELECT MIN(e2.ts) FROM events e2 JOIN io_events i2 ON i2.eid=e2.id WHERE e2.tgid=e.tgid),
            e.ts
        FROM io_events i JOIN events e ON e.id=i.eid
        WHERE COALESCE((SELECT ex FROM expanded WHERE id='io_'||CAST(e.tgid AS TEXT)),1)=1
    ) sub;

-- ── lpane VIEW for mode=2: I/O output lines (flat) ────────────────────
CREATE TEMP VIEW _lp_outputs_flat AS
    SELECT ROW_NUMBER()OVER(ORDER BY e.ts)-1 AS rownum,
        CAST(e.id AS TEXT) AS id, NULL AS parent_id,
        CASE WHEN i.stream='STDERR' THEN 'error' ELSE 'normal' END AS style,
        printf('[%d] %s %s', e.tgid, i.stream,
            SUBSTR(REPLACE(COALESCE(i.data,''),char(10),'↵'),1,200)) AS text
    FROM io_events i JOIN events e ON e.id=i.eid;

-- ── lpane VIEWs for dep modes (3-6) using recursive transitive closure ─
CREATE TEMP VIEW _lp_dep3 AS
    WITH RECURSIVE dc(path, depth) AS (
        SELECT (SELECT dep_root FROM state), 0
        WHERE (SELECT dep_root FROM state)!=''
        UNION
        SELECT de.src, dc.depth+1
        FROM _dep_edges de JOIN dc ON dc.path=de.dst
    )
    SELECT ROW_NUMBER()OVER(ORDER BY depth, path)-1 AS rownum,
        path AS id, NULL AS parent_id,
        CASE WHEN depth=0 THEN 'cyan_bold'
             WHEN path IN(SELECT id FROM search_hits) THEN 'search'
             ELSE 'normal' END AS style,
        printf('%*s%s', depth*2, '',
            REPLACE(path,RTRIM(path,REPLACE(path,'/','')),'')) AS text
    FROM dc
    WHERE ((SELECT dep_filter FROM state)=0
        OR EXISTS(SELECT 1 FROM open_events o2 JOIN events e2 ON e2.id=o2.eid
                  WHERE o2.path=dc.path
                    AND (o2.flags LIKE 'O_WRONLY%' OR o2.flags LIKE 'O_RDWR%'
                         OR o2.flags LIKE 'O_WRONLY,%' OR o2.flags LIKE 'O_RDWR,%')));

CREATE TEMP VIEW _lp_dep4 AS
    WITH RECURSIVE dc(path, depth) AS (
        SELECT (SELECT dep_root FROM state), 0
        WHERE (SELECT dep_root FROM state)!=''
        UNION
        SELECT de.dst, dc.depth+1
        FROM _dep_edges de JOIN dc ON dc.path=de.src
    )
    SELECT ROW_NUMBER()OVER(ORDER BY depth, path)-1 AS rownum,
        path AS id, NULL AS parent_id,
        CASE WHEN depth=0 THEN 'cyan_bold'
             WHEN path IN(SELECT id FROM search_hits) THEN 'search'
             ELSE 'normal' END AS style,
        printf('%*s%s', depth*2, '',
            REPLACE(path,RTRIM(path,REPLACE(path,'/','')),'')) AS text
    FROM dc
    WHERE ((SELECT dep_filter FROM state)=0
        OR EXISTS(SELECT 1 FROM open_events o2 JOIN events e2 ON e2.id=o2.eid
                  WHERE o2.path=dc.path
                    AND (o2.flags LIKE 'O_WRONLY%' OR o2.flags LIKE 'O_RDWR%'
                         OR o2.flags LIKE 'O_WRONLY,%' OR o2.flags LIKE 'O_RDWR,%')));

CREATE TEMP VIEW _lp_dep5 AS
    WITH RECURSIVE dc(path, depth) AS (
        SELECT (SELECT dep_root FROM state), 0
        WHERE (SELECT dep_root FROM state)!=''
        UNION
        SELECT de.src, dc.depth+1
        FROM _dep_edges de JOIN dc ON dc.path=de.dst
    )
    SELECT ROW_NUMBER()OVER(ORDER BY p.last_ts DESC)-1 AS rownum,
        CAST(p.tgid AS TEXT) AS id, NULL AS parent_id,
        CASE WHEN p.tgid IN(SELECT CAST(id AS INT) FROM search_hits) THEN 'search'
             WHEN x.code IS NOT NULL AND x.code!=0 THEN 'error'
             WHEN x.signal IS NOT NULL THEN 'error' ELSE 'normal' END AS style,
        printf('[%d] %s%s %s', p.tgid,
            COALESCE(REPLACE(p.exe,RTRIM(p.exe,REPLACE(p.exe,'/','')),''),'?'),
            CASE WHEN x.code IS NOT NULL AND x.code!=0 THEN ' ✗'
                 WHEN x.signal IS NOT NULL THEN printf(' ⚡%d',x.signal)
                 WHEN x.code IS NOT NULL THEN ' ✓' ELSE '' END,
            CASE WHEN p.last_ts-p.first_ts>=1 THEN printf('%.2fs',p.last_ts-p.first_ts)
                 WHEN p.last_ts-p.first_ts>=.001 THEN printf('%.1fms',(p.last_ts-p.first_ts)*1e3)
                 WHEN p.last_ts-p.first_ts>0 THEN printf('%.0fµs',(p.last_ts-p.first_ts)*1e6)
                 ELSE '' END) AS text
    FROM processes p
    LEFT JOIN events ev ON ev.tgid=p.tgid AND ev.event='EXIT'
    LEFT JOIN exit_events x ON x.eid=ev.id
    WHERE p.tgid IN(
        SELECT DISTINCT e.tgid FROM _dep_edges de JOIN dc ON (de.dst=dc.path OR de.src=dc.path)
        JOIN events e ON e.tgid=de.tgid);

CREATE TEMP VIEW _lp_dep6 AS
    WITH RECURSIVE dc(path, depth) AS (
        SELECT (SELECT dep_root FROM state), 0
        WHERE (SELECT dep_root FROM state)!=''
        UNION
        SELECT de.dst, dc.depth+1
        FROM _dep_edges de JOIN dc ON dc.path=de.src
    )
    SELECT ROW_NUMBER()OVER(ORDER BY p.last_ts DESC)-1 AS rownum,
        CAST(p.tgid AS TEXT) AS id, NULL AS parent_id,
        CASE WHEN p.tgid IN(SELECT CAST(id AS INT) FROM search_hits) THEN 'search'
             WHEN x.code IS NOT NULL AND x.code!=0 THEN 'error'
             WHEN x.signal IS NOT NULL THEN 'error' ELSE 'normal' END AS style,
        printf('[%d] %s%s %s', p.tgid,
            COALESCE(REPLACE(p.exe,RTRIM(p.exe,REPLACE(p.exe,'/','')),''),'?'),
            CASE WHEN x.code IS NOT NULL AND x.code!=0 THEN ' ✗'
                 WHEN x.signal IS NOT NULL THEN printf(' ⚡%d',x.signal)
                 WHEN x.code IS NOT NULL THEN ' ✓' ELSE '' END,
            CASE WHEN p.last_ts-p.first_ts>=1 THEN printf('%.2fs',p.last_ts-p.first_ts)
                 WHEN p.last_ts-p.first_ts>=.001 THEN printf('%.1fms',(p.last_ts-p.first_ts)*1e3)
                 WHEN p.last_ts-p.first_ts>0 THEN printf('%.0fµs',(p.last_ts-p.first_ts)*1e6)
                 ELSE '' END) AS text
    FROM processes p
    LEFT JOIN events ev ON ev.tgid=p.tgid AND ev.event='EXIT'
    LEFT JOIN exit_events x ON x.eid=ev.id
    WHERE p.tgid IN(
        SELECT DISTINCT e.tgid FROM _dep_edges de JOIN dc ON (de.dst=dc.path OR de.src=dc.path)
        JOIN events e ON e.tgid=de.tgid);

-- ── lpane VIEW: dispatch to per-mode pane sources ─────────────────────
-- Mode=1 reads from _ftree (populated by C build_file_tree() on mode entry).
CREATE TEMP VIEW lpane AS
    SELECT rownum, id, parent_id, style, text FROM _lp_procs_tree
        WHERE (SELECT mode FROM state)=0 AND (SELECT grouped FROM state)=1
    UNION ALL
    SELECT rownum, id, parent_id, style, text FROM _lp_procs_flat
        WHERE (SELECT mode FROM state)=0 AND (SELECT grouped FROM state)=0
    UNION ALL
    SELECT rownum, id, parent_id, style, text FROM _ftree
        WHERE (SELECT mode FROM state)=1
    UNION ALL
    SELECT rownum, id, parent_id, style, text FROM _lp_outputs_grouped
        WHERE (SELECT mode FROM state)=2 AND (SELECT grouped FROM state)=1
    UNION ALL
    SELECT rownum, id, parent_id, style, text FROM _lp_outputs_flat
        WHERE (SELECT mode FROM state)=2 AND (SELECT grouped FROM state)=0
    UNION ALL
    SELECT rownum, id, parent_id, style, text FROM _lp_dep3
        WHERE (SELECT mode FROM state)=3
    UNION ALL
    SELECT rownum, id, parent_id, style, text FROM _lp_dep4
        WHERE (SELECT mode FROM state)=4
    UNION ALL
    SELECT rownum, id, parent_id, style, text FROM _lp_dep5
        WHERE (SELECT mode FROM state)=5
    UNION ALL
    SELECT rownum, id, parent_id, style, text FROM _lp_dep6
        WHERE (SELECT mode FROM state)=6;

-- ── rpane VIEW: process detail (modes 0, 5, 6) ───────────────────────
-- Reads cursor_id and ts_mode/base_ts/evfilt from state.
CREATE TEMP VIEW _rp_proc AS
    WITH
    cid(tgid) AS (SELECT CAST((SELECT cursor_id FROM state) AS INT)),
    ev_rows AS (
        SELECT e.id AS eid, e.ts, e.event,
            LAG(e.ts) OVER (ORDER BY e.ts) AS prev_ts
        FROM events e, cid
        WHERE e.tgid=cid.tgid
            AND ((SELECT evfilt FROM state)='' OR e.event=(SELECT evfilt FROM state))
        LIMIT 5000
    ),
    argv_lines(i, rest, line) AS (
        SELECT 0,
            SUBSTR(p.argv, INSTR(p.argv,char(10))+1),
            CASE WHEN INSTR(p.argv,char(10))>0 THEN SUBSTR(p.argv,1,INSTR(p.argv,char(10))-1) ELSE p.argv END
        FROM processes p, cid WHERE p.tgid=cid.tgid AND p.argv IS NOT NULL
            AND (SELECT mode FROM state) IN (0,5,6)
        UNION ALL
        SELECT i+1,
            CASE WHEN INSTR(rest,char(10))>0 THEN SUBSTR(rest,INSTR(rest,char(10))+1) ELSE '' END,
            CASE WHEN INSTR(rest,char(10))>0 THEN SUBSTR(rest,1,INSTR(rest,char(10))-1) ELSE rest END
        FROM argv_lines WHERE LENGTH(rest)>0
    ),
    base AS (
        SELECT 0 AS rownum, 'heading' AS style, '─── Process ───' AS text,
            -1 AS link_mode, '' AS link_id, 'process' AS section
        WHERE (SELECT mode FROM state) IN (0,5,6)
            AND EXISTS(SELECT 1 FROM processes p, cid WHERE p.tgid=cid.tgid)
        UNION ALL
        SELECT 1, 'cyan', printf('TGID:  %d', p.tgid), -1, '', 'process'
        FROM processes p, cid WHERE p.tgid=cid.tgid AND (SELECT mode FROM state) IN (0,5,6)
        UNION ALL
        SELECT 2, 'cyan', printf('PPID:  %d', p.ppid), 0, CAST(p.ppid AS TEXT), 'process'
        FROM processes p, cid WHERE p.tgid=cid.tgid AND p.ppid IS NOT NULL
            AND (SELECT mode FROM state) IN (0,5,6)
        UNION ALL
        SELECT 3, 'green', printf('EXE:   %s', COALESCE(p.exe,'?')), -1, '', 'process'
        FROM processes p, cid WHERE p.tgid=cid.tgid AND (SELECT mode FROM state) IN (0,5,6)
        UNION ALL
        SELECT 4, 'green', printf('CWD:   %s', COALESCE(p.cwd,'?')), -1, '', 'process'
        FROM processes p, cid WHERE p.tgid=cid.tgid AND (SELECT mode FROM state) IN (0,5,6)
        UNION ALL
        SELECT 10+i, 'normal', printf('  [%d] %s', i, line), -1, '', 'process'
        FROM argv_lines
        UNION ALL
        SELECT 200,
            CASE WHEN x.signal IS NOT NULL THEN 'error'
                 WHEN x.code!=0 THEN 'error' ELSE 'green' END,
            CASE WHEN x.signal IS NOT NULL
                 THEN printf('Exit: signal %d%s', x.signal,
                     CASE WHEN x.core_dumped THEN ' (core)' ELSE '' END)
                 ELSE printf('Exit: %s code=%d', COALESCE(x.status,'?'), COALESCE(x.code,-1)) END,
            -1, '', 'process'
        FROM events ev JOIN exit_events x ON x.eid=ev.id, cid
        WHERE ev.tgid=cid.tgid AND ev.event='EXIT'
            AND (SELECT mode FROM state) IN (0,5,6)
        UNION ALL
        SELECT 201, 'cyan',
            'Duration: '||CASE WHEN p.last_ts-p.first_ts>=1 THEN printf('%.2fs',p.last_ts-p.first_ts)
                               WHEN p.last_ts-p.first_ts>=.001 THEN printf('%.1fms',(p.last_ts-p.first_ts)*1e3)
                               WHEN p.last_ts-p.first_ts>0 THEN printf('%.0fµs',(p.last_ts-p.first_ts)*1e6)
                               ELSE '' END,
            -1, '', 'process'
        FROM processes p, cid WHERE p.tgid=cid.tgid AND (SELECT mode FROM state) IN (0,5,6)
        UNION ALL
        SELECT 300, 'heading',
            printf('─── Children (%d) ───',
                (SELECT COUNT(*) FROM processes cc, cid WHERE cc.ppid=cid.tgid)),
            -1, '', 'children'
        WHERE (SELECT mode FROM state) IN (0,5,6)
            AND EXISTS(SELECT 1 FROM processes p, cid WHERE p.tgid=cid.tgid)
        UNION ALL
        SELECT 300+ROW_NUMBER()OVER(ORDER BY c.first_ts), 'normal',
            printf('  [%d] %s', c.tgid,
                COALESCE(REPLACE(c.exe,RTRIM(c.exe,REPLACE(c.exe,'/','')),''),'?')),
            0, CAST(c.tgid AS TEXT), 'children'
        FROM processes c, cid WHERE c.ppid=cid.tgid
            AND (SELECT mode FROM state) IN (0,5,6)
        UNION ALL
        SELECT 500, 'heading',
            printf('─── Events (%d)%s ───',
                (SELECT COUNT(*) FROM events ec, cid WHERE ec.tgid=cid.tgid),
                CASE WHEN (SELECT evfilt FROM state)!=''
                     THEN printf(' [%s]',(SELECT evfilt FROM state)) ELSE '' END),
            -1, '', 'events'
        WHERE (SELECT mode FROM state) IN (0,5,6)
            AND EXISTS(SELECT 1 FROM processes p, cid WHERE p.tgid=cid.tgid)
        UNION ALL
        SELECT 501+ROW_NUMBER()OVER(ORDER BY er.ts),
            CASE WHEN er.event='EXEC' THEN 'cyan_bold'
                 WHEN er.event='EXIT' AND (COALESCE(x.code,0)!=0 OR x.signal IS NOT NULL) THEN 'error'
                 WHEN er.event='EXIT' THEN 'green'
                 WHEN er.event='OPEN' AND o.err IS NOT NULL THEN 'error'
                 WHEN er.event='OPEN' THEN 'green'
                 WHEN er.event IN('STDERR','STDOUT') THEN 'yellow' ELSE 'normal' END,
            printf('%s %-6s %s',
                CASE (SELECT ts_mode FROM state)
                    WHEN 0 THEN printf('%.6f', er.ts)
                    WHEN 1 THEN printf('+%.6f', er.ts-(SELECT base_ts FROM state))
                    ELSE printf('Δ%.6f', er.ts-COALESCE(ev_rows.prev_ts, er.ts)) END,
                er.event,
                CASE WHEN er.event='OPEN'
                     THEN printf('%s [%s]%s%s', COALESCE(o.path,'?'), COALESCE(o.flags,'?'),
                         CASE WHEN o.fd IS NOT NULL THEN printf(' fd=%d',o.fd) ELSE '' END,
                         CASE WHEN o.err IS NOT NULL THEN printf(' err=%d',o.err) ELSE '' END)
                     WHEN er.event IN('STDERR','STDOUT')
                     THEN SUBSTR(REPLACE(COALESCE(i.data,''),char(10),'↵'),1,200)
                     WHEN er.event='EXIT'
                     THEN CASE WHEN x.signal IS NOT NULL THEN printf('signal=%d',x.signal)
                               ELSE printf('%s code=%d',COALESCE(x.status,'?'),COALESCE(x.code,-1)) END
                     ELSE '' END),
            CASE WHEN er.event='OPEN' THEN 1
                 WHEN er.event IN('STDERR','STDOUT') THEN 2 ELSE -1 END,
            CASE WHEN er.event='OPEN' THEN COALESCE(o.path,'')
                 WHEN er.event IN('STDERR','STDOUT') THEN CAST(er.id AS TEXT)
                 ELSE '' END,
            'events'
        FROM ev_rows
        JOIN events er ON er.id=ev_rows.eid
        LEFT JOIN open_events o ON o.eid=er.id
        LEFT JOIN io_events i ON i.eid=er.id
        LEFT JOIN exit_events x ON x.eid=er.id
    ),
    collapsed_sects(section) AS (
        SELECT section FROM base WHERE style='heading'
            AND COALESCE((SELECT ex FROM expanded WHERE id='rp_'||base.section),1)=0
    )
    SELECT ROW_NUMBER()OVER(ORDER BY rownum)-1 AS rownum,
        style,
        CASE WHEN style='heading' AND section IN(SELECT section FROM collapsed_sects)
             THEN REPLACE(text,'───','▶──') ELSE text END AS text,
        link_mode, link_id, section,
        CAST(ROW_NUMBER()OVER(ORDER BY rownum)-1 AS TEXT) AS id
    FROM base
    WHERE style='heading' OR section NOT IN(SELECT section FROM collapsed_sects);

-- ── rpane VIEW: file detail (modes 1, 3, 4) ──────────────────────────
CREATE TEMP VIEW _rp_file AS
    WITH
    cid(path) AS (SELECT (SELECT cursor_id FROM state)),
    base AS (
        SELECT 0 AS rownum, 'heading' AS style, '─── File ───' AS text,
            -1 AS link_mode, '' AS link_id, 'file' AS section
        WHERE (SELECT mode FROM state) IN (1,3,4)
            AND EXISTS(SELECT 1 FROM open_events, cid WHERE open_events.path=cid.path)
        UNION ALL
        SELECT 1, 'green', printf('Path: %s', cid.path), -1, '', 'file'
        FROM cid WHERE (SELECT mode FROM state) IN (1,3,4)
        UNION ALL
        SELECT 2, 'cyan',
            printf('Opens: %d  Errors: %d  Procs: %d',
                COUNT(*), SUM(o.err IS NOT NULL), COUNT(DISTINCT e.tgid)),
            -1, '', 'file'
        FROM open_events o JOIN events e ON e.id=o.eid, cid
        WHERE o.path=cid.path AND (SELECT mode FROM state) IN (1,3,4)
        UNION ALL
        SELECT 10, 'heading', '─── Accesses ───', -1, '', 'accesses'
        WHERE (SELECT mode FROM state) IN (1,3,4)
            AND EXISTS(SELECT 1 FROM open_events, cid WHERE open_events.path=cid.path)
        UNION ALL
        SELECT 11+ROW_NUMBER()OVER(ORDER BY e.ts),
            CASE WHEN o.err IS NOT NULL THEN 'error' ELSE 'green' END,
            printf('%s  PID %d (%s)  [%s]%s%s',
                CASE (SELECT ts_mode FROM state)
                    WHEN 0 THEN printf('%.6f', e.ts)
                    WHEN 1 THEN printf('+%.6f', e.ts-(SELECT base_ts FROM state))
                    ELSE printf('Δ%.6f', e.ts-COALESCE(LAG(e.ts)OVER(ORDER BY e.ts),e.ts)) END,
                e.tgid,
                COALESCE(REPLACE(p.exe,RTRIM(p.exe,REPLACE(p.exe,'/','')),''),'?'),
                COALESCE(o.flags,'?'),
                CASE WHEN o.fd IS NOT NULL THEN printf(' fd=%d',o.fd) ELSE '' END,
                CASE WHEN o.err IS NOT NULL THEN printf(' err=%d',o.err) ELSE '' END),
            0, CAST(e.tgid AS TEXT), 'accesses'
        FROM open_events o JOIN events e ON e.id=o.eid
        JOIN processes p ON p.tgid=e.tgid, cid
        WHERE o.path=cid.path AND (SELECT mode FROM state) IN (1,3,4)
    ),
    collapsed_sects(section) AS (
        SELECT section FROM base WHERE style='heading'
            AND COALESCE((SELECT ex FROM expanded WHERE id='rp_'||base.section),1)=0
    )
    SELECT ROW_NUMBER()OVER(ORDER BY rownum)-1 AS rownum,
        style,
        CASE WHEN style='heading' AND section IN(SELECT section FROM collapsed_sects)
             THEN REPLACE(text,'───','▶──') ELSE text END AS text,
        link_mode, link_id, section,
        CAST(ROW_NUMBER()OVER(ORDER BY rownum)-1 AS TEXT) AS id
    FROM base
    WHERE style='heading' OR section NOT IN(SELECT section FROM collapsed_sects);

-- ── rpane VIEW: I/O output detail (mode 2) ───────────────────────────
-- cursor_id is either 'io_<tgid>' (process header) or '<event_id>' (single line).
CREATE TEMP VIEW _rp_output AS
    WITH
    cid(val) AS (SELECT (SELECT cursor_id FROM state)),
    is_proc(v) AS (SELECT val LIKE 'io_%' FROM cid),
    proc_tgid(tgid) AS (
        SELECT CAST(SUBSTR(val, 4) AS INT) FROM cid, is_proc WHERE is_proc.v=1
    ),
    ev_id(eid) AS (
        SELECT CAST(val AS INT) FROM cid, is_proc WHERE is_proc.v=0
    ),
    argv_lines(i, rest, line) AS (
        SELECT 0,
            SUBSTR(argv, INSTR(argv,char(10))+1),
            CASE WHEN INSTR(argv,char(10))>0 THEN SUBSTR(argv,1,INSTR(argv,char(10))-1) ELSE argv END
        FROM processes, proc_tgid WHERE processes.tgid=proc_tgid.tgid AND argv IS NOT NULL
            AND (SELECT mode FROM state)=2 AND (SELECT val FROM cid) LIKE 'io_%'
        UNION ALL
        SELECT i+1,
            CASE WHEN INSTR(rest,char(10))>0 THEN SUBSTR(rest,INSTR(rest,char(10))+1) ELSE '' END,
            CASE WHEN INSTR(rest,char(10))>0 THEN SUBSTR(rest,1,INSTR(rest,char(10))-1) ELSE rest END
        FROM argv_lines WHERE LENGTH(rest)>0
    ),
    io_lines(i, rest, line) AS (
        SELECT 0,
            SUBSTR(data, INSTR(data,char(10))+1),
            CASE WHEN INSTR(data,char(10))>0 THEN SUBSTR(data,1,INSTR(data,char(10))-1) ELSE data END
        FROM io_events, ev_id WHERE io_events.eid=ev_id.eid AND (SELECT mode FROM state)=2
            AND (SELECT val FROM cid) NOT LIKE 'io_%'
        UNION ALL
        SELECT i+1,
            CASE WHEN INSTR(rest,char(10))>0 THEN SUBSTR(rest,INSTR(rest,char(10))+1) ELSE '' END,
            CASE WHEN INSTR(rest,char(10))>0 THEN SUBSTR(rest,1,INSTR(rest,char(10))-1) ELSE rest END
        FROM io_lines WHERE LENGTH(rest)>0
    ),
    base AS (
        -- Process header view (io_<tgid>)
        SELECT 0 AS rownum, 'heading' AS style, '─── Process ───' AS text,
            -1 AS link_mode, '' AS link_id, 'process' AS section
        WHERE (SELECT mode FROM state)=2 AND (SELECT val FROM cid) LIKE 'io_%'
            AND EXISTS(SELECT 1 FROM proc_tgid JOIN processes USING(tgid))
        UNION ALL
        SELECT 1, 'cyan', printf('TGID:  %d', processes.tgid), -1, '', 'process'
        FROM processes, proc_tgid WHERE processes.tgid=proc_tgid.tgid
            AND (SELECT mode FROM state)=2 AND (SELECT val FROM cid) LIKE 'io_%'
        UNION ALL
        SELECT 3, 'green', printf('EXE:   %s', COALESCE(exe,'?')), -1, '', 'process'
        FROM processes, proc_tgid WHERE processes.tgid=proc_tgid.tgid
            AND (SELECT mode FROM state)=2 AND (SELECT val FROM cid) LIKE 'io_%'
        UNION ALL
        SELECT 10+i, 'normal', printf('  [%d] %s', i, line), -1, '', 'process'
        FROM argv_lines
        UNION ALL
        -- Single I/O event view (<eid>)
        SELECT 0, 'heading', '─── Output ───', -1, '', 'output'
        WHERE (SELECT mode FROM state)=2 AND (SELECT val FROM cid) NOT LIKE 'io_%'
            AND EXISTS(SELECT 1 FROM ev_id JOIN io_events USING(eid))
        UNION ALL
        SELECT 1, 'cyan',
            printf('Stream: %s  PID: %d', i.stream, e.tgid),
            0, CAST(e.tgid AS TEXT), 'output'
        FROM io_events i JOIN events e ON e.id=i.eid, ev_id WHERE i.eid=ev_id.eid
            AND (SELECT mode FROM state)=2 AND (SELECT val FROM cid) NOT LIKE 'io_%'
        UNION ALL
        SELECT 2, 'green',
            printf('Process: %s', COALESCE(REPLACE(p.exe,RTRIM(p.exe,REPLACE(p.exe,'/','')),''),'?')),
            0, CAST(p.tgid AS TEXT), 'output'
        FROM io_events i JOIN events e ON e.id=i.eid JOIN processes p ON p.tgid=e.tgid, ev_id
        WHERE i.eid=ev_id.eid AND (SELECT mode FROM state)=2
            AND (SELECT val FROM cid) NOT LIKE 'io_%'
        UNION ALL
        SELECT 5, 'heading', '─── Content ───', -1, '', 'content'
        WHERE (SELECT mode FROM state)=2 AND (SELECT val FROM cid) NOT LIKE 'io_%'
            AND EXISTS(SELECT 1 FROM ev_id JOIN io_events USING(eid))
        UNION ALL
        SELECT 10+i, 'normal', line, -1, '', 'content'
        FROM io_lines
    ),
    collapsed_sects(section) AS (
        SELECT section FROM base WHERE style='heading'
            AND COALESCE((SELECT ex FROM expanded WHERE id='rp_'||base.section),1)=0
    )
    SELECT ROW_NUMBER()OVER(ORDER BY rownum)-1 AS rownum,
        style,
        CASE WHEN style='heading' AND section IN(SELECT section FROM collapsed_sects)
             THEN REPLACE(text,'───','▶──') ELSE text END AS text,
        link_mode, link_id, section,
        CAST(ROW_NUMBER()OVER(ORDER BY rownum)-1 AS TEXT) AS id
    FROM base
    WHERE style='heading' OR section NOT IN(SELECT section FROM collapsed_sects);

-- ── rpane VIEW: union of all modes ────────────────────────────────────
CREATE TEMP VIEW rpane AS
    SELECT rownum, style, text, link_mode, link_id, section, id
    FROM _rp_proc WHERE (SELECT mode FROM state) IN (0,5,6)
    UNION ALL
    SELECT rownum, style, text, link_mode, link_id, section, id
    FROM _rp_file WHERE (SELECT mode FROM state) IN (1,3,4)
    UNION ALL
    SELECT rownum, style, text, link_mode, link_id, section, id
    FROM _rp_output WHERE (SELECT mode FROM state)=2;

-- ── Outbox table (read by C after trigger fires) ──────────────────────
-- Only for commands that require terminal interaction.
-- Commands: quit, prompt_search, prompt_filter, prompt_save, prompt_sql,
--           show_help, follow_link, build_ftree, do_search, jump_hit
CREATE TEMP TABLE IF NOT EXISTS _outbox(
    id INTEGER PRIMARY KEY, cmd TEXT NOT NULL, arg TEXT DEFAULT '');

-- ══════════════════════════════════════════════════════════════════════
-- Input dispatch triggers
-- ══════════════════════════════════════════════════════════════════════
-- Engine-owned navigation emits:
--   INSERT INTO inbox(kind,data) VALUES('cursor',
--     json_object('panel',<name>,'row_id',<text>))
--
-- Action keys emit:
--   INSERT INTO inbox(kind,data) VALUES('key',
--     json_object('key',<int>,'panel',<name>,'row_id',<text>))

-- ══════════════════════════════════════════════════════════════════════
-- Cursor dispatch trigger
-- ══════════════════════════════════════════════════════════════════════
CREATE TEMP TRIGGER _dispatch_cursor AFTER INSERT ON inbox WHEN NEW.kind='cursor'
BEGIN
    UPDATE state SET
        focus = 0,
        cursor = COALESCE(
            (SELECT rownum FROM lpane WHERE id = json_extract(NEW.data,'$.row_id')),
            0),
        cursor_id = COALESCE(json_extract(NEW.data,'$.row_id'), '')
        WHERE json_extract(NEW.data,'$.panel') = 'lpane';
    UPDATE state SET
        focus = 1,
        dcursor = COALESCE(
            (SELECT rownum FROM rpane WHERE id = json_extract(NEW.data,'$.row_id')),
            0)
        WHERE json_extract(NEW.data,'$.panel') = 'rpane';
    DELETE FROM inbox WHERE id = NEW.id;
END;

-- ══════════════════════════════════════════════════════════════════════
-- Key dispatch trigger
-- ══════════════════════════════════════════════════════════════════════
-- Fires on INSERT INTO inbox(kind,data) VALUES('key', json_object(...)).
-- JSON fields: key (int), panel (text), row_id (text).
--
-- Key code reference (from engine.h TUI_K_* constants):
--   256=UP  257=DOWN  258=LEFT  259=RIGHT  260=PGUP  261=PGDN
--   262=HOME  263=END  9=TAB  13=ENTER  27=ESC  127=BS
--   ASCII: 47='/'  49='1'..55='7'  63='?'  69='E'  70='F'  71='G'
--   78='N'  81='Q'  86='V'  87='W'  100='d'  101='e'  102='f'
--   103='g'  104='h'  106='j'  107='k'  108='l'  110='n'  113='q'
--   115='s'  116='t'  118='v'  120='x'

CREATE TEMP TRIGGER _dispatch_key AFTER INSERT ON inbox WHEN NEW.kind='key'
BEGIN
    -- ── quit ──
    INSERT INTO _outbox(cmd) SELECT 'quit'
        WHERE json_extract(NEW.data,'$.key') IN (113, 81);

    -- ── enter: lpane → switch to rpane; rpane → follow link ──
    UPDATE state SET focus = 1, dcursor = 0
        WHERE json_extract(NEW.data,'$.key') IN (13, 10)
          AND json_extract(NEW.data,'$.panel') = 'lpane';
    INSERT INTO _outbox(cmd,arg) SELECT 'follow_link',
        COALESCE(json_extract(NEW.data,'$.row_id'), '')
        WHERE json_extract(NEW.data,'$.key') IN (13, 10)
          AND json_extract(NEW.data,'$.panel') = 'rpane';

    -- ── G: toggle grouped ──
    UPDATE state SET grouped = 1 - grouped,
        cursor = 0, cursor_id = '', scroll = 0, dscroll = 0, dcursor = 0
        WHERE json_extract(NEW.data,'$.key') = 71;

    -- ── right/l: expand or enter detail ──
    -- If panel=rpane and cursor is on heading, toggle it
    INSERT OR REPLACE INTO expanded(id, ex)
        SELECT 'rp_' || section,
            CASE WHEN COALESCE((SELECT ex FROM expanded WHERE id='rp_'||section),1)
                 THEN 0 ELSE 1 END
        FROM rpane
        WHERE json_extract(NEW.data,'$.key') IN (259, 108)
          AND json_extract(NEW.data,'$.panel') = 'rpane'
          AND rpane.id = json_extract(NEW.data,'$.row_id')
          AND rpane.style = 'heading';
    -- If panel=rpane and cursor is NOT heading, follow link
    INSERT INTO _outbox(cmd,arg) SELECT 'follow_link',
        COALESCE(json_extract(NEW.data,'$.row_id'), '')
        WHERE json_extract(NEW.data,'$.key') IN (259, 108)
          AND json_extract(NEW.data,'$.panel') = 'rpane'
          AND NOT EXISTS(SELECT 1 FROM rpane
              WHERE id=json_extract(NEW.data,'$.row_id') AND style='heading');
    -- If panel=lpane, expand current node if it has children and is collapsed
    INSERT OR REPLACE INTO expanded(id, ex)
        SELECT json_extract(NEW.data,'$.row_id'), 1
        WHERE json_extract(NEW.data,'$.key') IN (259, 108)
          AND json_extract(NEW.data,'$.panel') = 'lpane'
          AND json_extract(NEW.data,'$.row_id') != ''
          AND (SELECT mode FROM state) IN (0, 1, 2)
          AND COALESCE((SELECT ex FROM expanded
              WHERE id=json_extract(NEW.data,'$.row_id')), 1) = 0;

    -- ── left/h: collapse or go to parent ──
    -- If panel=rpane, toggle rpane heading
    INSERT OR REPLACE INTO expanded(id, ex)
        SELECT 'rp_' || section,
            CASE WHEN COALESCE((SELECT ex FROM expanded WHERE id='rp_'||section),1)
                 THEN 0 ELSE 1 END
        FROM rpane
        WHERE json_extract(NEW.data,'$.key') IN (258, 104)
          AND json_extract(NEW.data,'$.panel') = 'rpane'
          AND rpane.id = json_extract(NEW.data,'$.row_id')
          AND rpane.style = 'heading';
    -- If panel=lpane, mode=0 (procs): collapse if expanded+has children
    UPDATE expanded SET ex = 0
        WHERE json_extract(NEW.data,'$.key') IN (258, 104)
          AND json_extract(NEW.data,'$.panel') = 'lpane'
          AND (SELECT mode FROM state) = 0
          AND id = json_extract(NEW.data,'$.row_id')
          AND ex = 1
          AND EXISTS(SELECT 1 FROM processes
              WHERE ppid = CAST(json_extract(NEW.data,'$.row_id') AS INT));
    -- If panel=lpane, mode=0, not expanded or no children → jump to parent
    UPDATE state SET cursor = COALESCE(
        (SELECT rownum FROM lpane WHERE id = CAST(
            (SELECT ppid FROM processes
             WHERE tgid = CAST(json_extract(NEW.data,'$.row_id') AS INT))
            AS TEXT)),
        cursor)
        WHERE json_extract(NEW.data,'$.key') IN (258, 104)
          AND json_extract(NEW.data,'$.panel') = 'lpane'
          AND (SELECT mode FROM state) = 0
          AND json_extract(NEW.data,'$.row_id') != ''
          AND (NOT EXISTS(SELECT 1 FROM processes
                  WHERE ppid = CAST(json_extract(NEW.data,'$.row_id') AS INT))
               OR COALESCE((SELECT ex FROM expanded
                    WHERE id = json_extract(NEW.data,'$.row_id')), 1) = 0);
    -- If panel=lpane, mode=1 (files): collapse if expanded dir
    INSERT OR REPLACE INTO expanded(id, ex)
        SELECT json_extract(NEW.data,'$.row_id'), 0
        WHERE json_extract(NEW.data,'$.key') IN (258, 104)
          AND json_extract(NEW.data,'$.panel') = 'lpane'
          AND (SELECT mode FROM state) = 1
          AND json_extract(NEW.data,'$.row_id') != ''
          AND COALESCE((SELECT ex FROM expanded
              WHERE id=json_extract(NEW.data,'$.row_id')), 1) = 1
          AND EXISTS(SELECT 1 FROM _ftree
              WHERE parent_id=json_extract(NEW.data,'$.row_id'));
    -- mode=1: if not expandable, go to parent
    UPDATE state SET cursor = COALESCE(
        (SELECT rownum FROM lpane WHERE id =
            (SELECT parent_id FROM _ftree
             WHERE id = json_extract(NEW.data,'$.row_id') LIMIT 1)),
        cursor)
        WHERE json_extract(NEW.data,'$.key') IN (258, 104)
          AND json_extract(NEW.data,'$.panel') = 'lpane'
          AND (SELECT mode FROM state) = 1
          AND json_extract(NEW.data,'$.row_id') != ''
          AND (NOT EXISTS(SELECT 1 FROM _ftree
                    WHERE parent_id=json_extract(NEW.data,'$.row_id'))
                OR COALESCE((SELECT ex FROM expanded
                    WHERE id=json_extract(NEW.data,'$.row_id')), 1) = 0);
    -- mode=2 (output): collapse io_ group or go to parent
    INSERT OR REPLACE INTO expanded(id, ex)
        SELECT json_extract(NEW.data,'$.row_id'), 0
        WHERE json_extract(NEW.data,'$.key') IN (258, 104)
          AND json_extract(NEW.data,'$.panel') = 'lpane'
          AND (SELECT mode FROM state) = 2
          AND json_extract(NEW.data,'$.row_id') LIKE 'io_%';
    UPDATE state SET cursor = COALESCE(
        (SELECT rownum FROM lpane
         WHERE id = (SELECT parent_id FROM lpane
                     WHERE id = json_extract(NEW.data,'$.row_id'))),
        cursor)
        WHERE json_extract(NEW.data,'$.key') IN (258, 104)
          AND json_extract(NEW.data,'$.panel') = 'lpane'
          AND (SELECT mode FROM state) = 2
          AND json_extract(NEW.data,'$.row_id') NOT LIKE 'io_%'
          AND json_extract(NEW.data,'$.row_id') != '';

    -- Sync cursor_id after left/right
    UPDATE state SET cursor_id = COALESCE(
        (SELECT id FROM lpane WHERE rownum=(SELECT cursor FROM state)), '')
        WHERE json_extract(NEW.data,'$.key') IN (258,259,104,108);

    -- ── e/E: expand/collapse all descendants (mode=0) ──
    UPDATE expanded SET ex = 1
        WHERE json_extract(NEW.data,'$.key') = 101
          AND (SELECT mode FROM state) = 0
          AND id IN (
            WITH RECURSIVE d(t) AS (
                SELECT CAST(json_extract(NEW.data,'$.row_id') AS INT)
                UNION ALL
                SELECT c.tgid FROM processes c JOIN d ON c.ppid = d.t
            ) SELECT CAST(t AS TEXT) FROM d);
    UPDATE expanded SET ex = 0
        WHERE json_extract(NEW.data,'$.key') = 69
          AND (SELECT mode FROM state) = 0
          AND id IN (
            WITH RECURSIVE d(t) AS (
                SELECT CAST(json_extract(NEW.data,'$.row_id') AS INT)
                UNION ALL
                SELECT c.tgid FROM processes c JOIN d ON c.ppid = d.t
            ) SELECT CAST(t AS TEXT) FROM d);

    -- ── mode switches 1-7 ──
    -- First capture dep_root for modes 3-6
    UPDATE state SET dep_root = COALESCE(
        (SELECT id FROM lpane WHERE rownum = (SELECT cursor FROM state)), '')
        WHERE json_extract(NEW.data,'$.key') IN (52, 53, 54, 55);
    -- Switch mode, reset cursors
    UPDATE state SET
        mode = json_extract(NEW.data,'$.key') - 49,
        cursor = 0, cursor_id = '', scroll = 0,
        dscroll = 0, dcursor = 0, focus = 0,
        sort_key = CASE WHEN json_extract(NEW.data,'$.key') <= 51
                        THEN 0 ELSE sort_key END
        WHERE json_extract(NEW.data,'$.key') IN (49, 50, 51, 52, 53, 54, 55);

    -- ── d: toggle dep filter ──
    UPDATE state SET dep_filter = 1 - dep_filter, cursor = 0, scroll = 0
        WHERE json_extract(NEW.data,'$.key') = 100;

    -- ── s: cycle sort ──
    UPDATE state SET sort_key = (sort_key + 1) % 3, cursor = 0, scroll = 0
        WHERE json_extract(NEW.data,'$.key') = 115;

    -- ── t: cycle timestamp mode ──
    UPDATE state SET ts_mode = (ts_mode + 1) % 3
        WHERE json_extract(NEW.data,'$.key') = 116;

    -- ── v: cycle proc filter ──
    UPDATE state SET lp_filter = (lp_filter + 1) % 3, cursor = 0, scroll = 0
        WHERE json_extract(NEW.data,'$.key') = 118;
    -- ── V: clear proc filter ──
    UPDATE state SET lp_filter = 0, cursor = 0, scroll = 0
        WHERE json_extract(NEW.data,'$.key') = 86;
    -- ── F: clear event filter ──
    UPDATE state SET evfilt = ''
        WHERE json_extract(NEW.data,'$.key') = 70;

    -- ── n: next search hit ──
    UPDATE state SET cursor = COALESCE(
        (SELECT MIN(rownum) FROM lpane
         WHERE id IN (SELECT id FROM search_hits)
           AND rownum > (SELECT cursor FROM state)),
        (SELECT MIN(rownum) FROM lpane
         WHERE id IN (SELECT id FROM search_hits)),
        (SELECT cursor FROM state)),
        dscroll = 0, dcursor = 0
        WHERE json_extract(NEW.data,'$.key') = 110;
    -- ── N: prev search hit ──
    UPDATE state SET cursor = COALESCE(
        (SELECT MAX(rownum) FROM lpane
         WHERE id IN (SELECT id FROM search_hits)
           AND rownum < (SELECT cursor FROM state)),
        (SELECT MAX(rownum) FROM lpane
         WHERE id IN (SELECT id FROM search_hits)),
        (SELECT cursor FROM state)),
        dscroll = 0, dcursor = 0
        WHERE json_extract(NEW.data,'$.key') = 78;
    -- Sync cursor_id after n/N
    UPDATE state SET cursor_id = COALESCE(
        (SELECT id FROM lpane WHERE rownum=(SELECT cursor FROM state)), '')
        WHERE json_extract(NEW.data,'$.key') IN (110, 78);

    -- ── Interactive commands → outbox only ──
    INSERT INTO _outbox(cmd) SELECT 'prompt_search'
        WHERE json_extract(NEW.data,'$.key') = 47;
    INSERT INTO _outbox(cmd) SELECT 'prompt_filter'
        WHERE json_extract(NEW.data,'$.key') = 102;
    INSERT INTO _outbox(cmd) SELECT 'prompt_save'
        WHERE json_extract(NEW.data,'$.key') = 87;
    INSERT INTO _outbox(cmd) SELECT 'prompt_sql'
        WHERE json_extract(NEW.data,'$.key') = 120;
    INSERT INTO _outbox(cmd) SELECT 'show_help'
        WHERE json_extract(NEW.data,'$.key') = 63;

    -- ── build_ftree after any change that affects file tree ────────────
    -- Mode switch to file mode (key '2'=50), G toggle (71),
    -- expand/collapse in file mode (right/l=259,108  left/h=258,104)
    SELECT build_ftree()
        WHERE (SELECT mode FROM state) = 1
          AND json_extract(NEW.data,'$.key') IN (50, 71, 258, 259, 104, 108);

    -- ── Clean up inbox ──
    DELETE FROM inbox WHERE id = NEW.id;
END;

-- ── Input dispatch trigger ────────────────────────────────────────────
-- Handles: resize, select, search, evfilt, print
CREATE TEMP TRIGGER _dispatch_input AFTER INSERT ON inbox WHEN NEW.kind='input'
BEGIN
    -- resize
    UPDATE state SET
        rows = json_extract(NEW.data,'$.rows'),
        cols = json_extract(NEW.data,'$.cols')
        WHERE json_extract(NEW.data,'$.input') = 'resize'
          AND json_extract(NEW.data,'$.rows') > 0
          AND json_extract(NEW.data,'$.cols') > 0;

    -- select: move cursor to row with given id
    UPDATE state SET
        cursor = COALESCE(
            (SELECT rownum FROM lpane WHERE id = json_extract(NEW.data,'$.id')),
            cursor),
        cursor_id = COALESCE(json_extract(NEW.data,'$.id'), cursor_id),
        dscroll = 0, dcursor = 0
        WHERE json_extract(NEW.data,'$.input') = 'select';

    -- search: populate search_hits, then jump to first hit
    DELETE FROM search_hits
        WHERE json_extract(NEW.data,'$.input') = 'search';
    UPDATE state SET search = COALESCE(json_extract(NEW.data,'$.q'), '')
        WHERE json_extract(NEW.data,'$.input') = 'search';
    -- search mode 0,5,6: processes
    INSERT OR IGNORE INTO search_hits(id)
        SELECT CAST(tgid AS TEXT) FROM processes
        WHERE json_extract(NEW.data,'$.input') = 'search'
          AND (SELECT mode FROM state) IN (0, 5, 6)
          AND json_extract(NEW.data,'$.q') != ''
          AND (CAST(tgid AS TEXT) LIKE '%'||json_extract(NEW.data,'$.q')||'%'
               OR exe LIKE '%'||json_extract(NEW.data,'$.q')||'%'
               OR argv LIKE '%'||json_extract(NEW.data,'$.q')||'%');
    -- search mode 1,3,4: files
    INSERT OR IGNORE INTO search_hits(id)
        SELECT DISTINCT path FROM open_events
        WHERE json_extract(NEW.data,'$.input') = 'search'
          AND (SELECT mode FROM state) IN (1, 3, 4)
          AND json_extract(NEW.data,'$.q') != ''
          AND path LIKE '%'||json_extract(NEW.data,'$.q')||'%';
    -- search mode 2: output
    INSERT OR IGNORE INTO search_hits(id)
        SELECT CAST(e.id AS TEXT) FROM io_events i
        JOIN events e ON e.id = i.eid
        WHERE json_extract(NEW.data,'$.input') = 'search'
          AND (SELECT mode FROM state) = 2
          AND json_extract(NEW.data,'$.q') != ''
          AND i.data LIKE '%'||json_extract(NEW.data,'$.q')||'%';
    -- rebuild file tree after search in file mode (to pick up search styling)
    SELECT build_ftree()
        WHERE json_extract(NEW.data,'$.input') = 'search'
          AND (SELECT mode FROM state) = 1;

    -- evfilt
    UPDATE state SET evfilt = UPPER(COALESCE(json_extract(NEW.data,'$.q'), ''))
        WHERE json_extract(NEW.data,'$.input') = 'evfilt';

    -- print: emit outbox command for C to handle
    INSERT INTO _outbox(cmd, arg)
        SELECT 'print', COALESCE(json_extract(NEW.data,'$.what'), '')
        WHERE json_extract(NEW.data,'$.input') = 'print';

    DELETE FROM inbox WHERE id = NEW.id;
END;

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
