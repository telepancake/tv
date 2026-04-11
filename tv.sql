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

-- ── Trace ingestion trigger ───────────────────────────────────────────
-- Processes inbox rows with kind='trace', inserting into normalized tables.
-- Uses custom SQL functions: canon_path(), resolve_path(), is_sys_path().
CREATE TRIGGER _ingest_trace AFTER INSERT ON inbox WHEN NEW.kind='trace'
BEGIN
    -- Ensure process stub exists (skip own tgid, skip if no event)
    INSERT OR IGNORE INTO processes(tgid,pid,ppid,nspid,nstgid,first_ts,last_ts)
        SELECT json_extract(NEW.data,'$.tgid'),json_extract(NEW.data,'$.pid'),
               json_extract(NEW.data,'$.ppid'),json_extract(NEW.data,'$.nspid'),
               json_extract(NEW.data,'$.nstgid'),json_extract(NEW.data,'$.ts'),
               json_extract(NEW.data,'$.ts')
        WHERE json_extract(NEW.data,'$.event') IS NOT NULL
          AND json_extract(NEW.data,'$.tgid') IS NOT NULL
          AND CAST(json_extract(NEW.data,'$.tgid') AS TEXT)
              != COALESCE((SELECT val FROM _config WHERE key='own_tgid'),'');
    INSERT OR IGNORE INTO expanded(id,ex)
        SELECT CAST(json_extract(NEW.data,'$.tgid') AS TEXT), 1
        WHERE json_extract(NEW.data,'$.event') IS NOT NULL
          AND json_extract(NEW.data,'$.tgid') IS NOT NULL
          AND CAST(json_extract(NEW.data,'$.tgid') AS TEXT)
              != COALESCE((SELECT val FROM _config WHERE key='own_tgid'),'');

    -- CWD
    INSERT OR REPLACE INTO cwd_cache(tgid,cwd)
        SELECT CAST(json_extract(NEW.data,'$.tgid') AS INT),
               json_extract(NEW.data,'$.path')
        WHERE json_extract(NEW.data,'$.event')='CWD';
    UPDATE processes SET cwd=json_extract(NEW.data,'$.path')
        WHERE tgid=CAST(json_extract(NEW.data,'$.tgid') AS INT)
          AND json_extract(NEW.data,'$.event')='CWD';

    -- EXEC
    UPDATE processes SET
        exe=json_extract(NEW.data,'$.exe'),
        argv=CASE WHEN json_type(NEW.data,'$.argv')='array' THEN
            (SELECT GROUP_CONCAT(value,char(10)) FROM json_each(json_extract(NEW.data,'$.argv')))
            ELSE NULL END,
        env=CASE WHEN json_type(NEW.data,'$.env')='object' THEN
            (SELECT GROUP_CONCAT(key||'='||value,char(10)) FROM json_each(json_extract(NEW.data,'$.env')))
            ELSE NULL END,
        auxv=CASE WHEN json_type(NEW.data,'$.auxv')='object' THEN
            (SELECT GROUP_CONCAT(key||'='||value,char(10)) FROM json_each(json_extract(NEW.data,'$.auxv')))
            ELSE NULL END,
        first_ts=MIN(first_ts,json_extract(NEW.data,'$.ts')),
        last_ts=MAX(last_ts,json_extract(NEW.data,'$.ts'))
        WHERE tgid=CAST(json_extract(NEW.data,'$.tgid') AS INT)
          AND json_extract(NEW.data,'$.event')='EXEC';
    INSERT INTO events(tgid,ts,event)
        SELECT json_extract(NEW.data,'$.tgid'),json_extract(NEW.data,'$.ts'),'EXEC'
        WHERE json_extract(NEW.data,'$.event')='EXEC';

    -- OPEN: resolve path, filter system paths for O_RDONLY
    INSERT INTO events(tgid,ts,event)
        SELECT json_extract(NEW.data,'$.tgid'),json_extract(NEW.data,'$.ts'),'OPEN'
        WHERE json_extract(NEW.data,'$.event')='OPEN'
          AND NOT is_sys_path(
              resolve_path(json_extract(NEW.data,'$.path'),
                  (SELECT cwd FROM cwd_cache WHERE tgid=CAST(json_extract(NEW.data,'$.tgid') AS INT))),
              COALESCE(json_extract(NEW.data,'$.flags[0]'),'O_RDONLY'));
    INSERT INTO open_events(eid,path,flags,fd,err)
        SELECT last_insert_rowid(),
            resolve_path(json_extract(NEW.data,'$.path'),
                (SELECT cwd FROM cwd_cache WHERE tgid=CAST(json_extract(NEW.data,'$.tgid') AS INT))),
            CASE WHEN json_type(NEW.data,'$.flags')='array' THEN
                (SELECT GROUP_CONCAT(value,'|') FROM json_each(json_extract(NEW.data,'$.flags')))
                ELSE NULL END,
            json_extract(NEW.data,'$.fd'), json_extract(NEW.data,'$.err')
        WHERE json_extract(NEW.data,'$.event')='OPEN' AND changes()>0;
    UPDATE processes SET
        last_ts=MAX(last_ts,json_extract(NEW.data,'$.ts')),
        first_ts=MIN(first_ts,json_extract(NEW.data,'$.ts'))
        WHERE tgid=CAST(json_extract(NEW.data,'$.tgid') AS INT)
          AND json_extract(NEW.data,'$.event')='OPEN';

    -- EXIT
    INSERT INTO events(tgid,ts,event)
        SELECT json_extract(NEW.data,'$.tgid'),json_extract(NEW.data,'$.ts'),'EXIT'
        WHERE json_extract(NEW.data,'$.event')='EXIT';
    INSERT INTO exit_events(eid,status,code,signal,core_dumped,raw)
        SELECT last_insert_rowid(),json_extract(NEW.data,'$.status'),
               json_extract(NEW.data,'$.code'),json_extract(NEW.data,'$.signal'),
               json_extract(NEW.data,'$.core_dumped'),json_extract(NEW.data,'$.raw')
        WHERE json_extract(NEW.data,'$.event')='EXIT';
    UPDATE processes SET last_ts=MAX(last_ts,json_extract(NEW.data,'$.ts'))
        WHERE tgid=CAST(json_extract(NEW.data,'$.tgid') AS INT)
          AND json_extract(NEW.data,'$.event')='EXIT';

    -- STDOUT / STDERR
    INSERT INTO events(tgid,ts,event)
        SELECT json_extract(NEW.data,'$.tgid'),json_extract(NEW.data,'$.ts'),
               json_extract(NEW.data,'$.event')
        WHERE json_extract(NEW.data,'$.event') IN ('STDOUT','STDERR');
    INSERT INTO io_events(eid,stream,len,data)
        SELECT last_insert_rowid(),json_extract(NEW.data,'$.event'),
               json_extract(NEW.data,'$.len'),json_extract(NEW.data,'$.data')
        WHERE json_extract(NEW.data,'$.event') IN ('STDOUT','STDERR');
    UPDATE processes SET last_ts=MAX(last_ts,json_extract(NEW.data,'$.ts'))
        WHERE tgid=CAST(json_extract(NEW.data,'$.tgid') AS INT)
          AND json_extract(NEW.data,'$.event') IN ('STDOUT','STDERR');

    -- Delete processed row
    DELETE FROM inbox WHERE id=NEW.id;
END;

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
-- Placeholder temp table for mode=1 (file tree), populated by C build_file_tree().
CREATE TEMP TABLE IF NOT EXISTS _ftree(
    rownum INTEGER PRIMARY KEY, id TEXT NOT NULL,
    parent_id TEXT, style TEXT DEFAULT 'normal', text TEXT NOT NULL);

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
