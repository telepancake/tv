#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>
#include "sqlite3.h"

static sqlite3 *db;
static void die(const char *m){fprintf(stderr,"tv: %s\n",m);exit(1);}
static void dbdie(const char *c){fprintf(stderr,"tv: %s: %s\n",c,sqlite3_errmsg(db));exit(1);}
static void xexec(const char *sql){
    char*e;if(sqlite3_exec(db,sql,0,0,&e)!=SQLITE_OK){fprintf(stderr,"sql: %s\n%.300s\n",e,sql);sqlite3_free(e);exit(1);}}
static void xexecf(const char *fmt,...){
    char b[16384];va_list a;va_start(a,fmt);vsnprintf(b,sizeof b,fmt,a);va_end(a);xexec(b);}
static int qint(const char *sql,int def){
    sqlite3_stmt*s;int r=def;if(sqlite3_prepare_v2(db,sql,-1,&s,0)==SQLITE_OK){
        if(sqlite3_step(s)==SQLITE_ROW)r=sqlite3_column_int(s,0);sqlite3_finalize(s);}return r;}
static double qdbl(const char *sql,double def){
    sqlite3_stmt*s;double r=def;if(sqlite3_prepare_v2(db,sql,-1,&s,0)==SQLITE_OK){
        if(sqlite3_step(s)==SQLITE_ROW)r=sqlite3_column_double(s,0);sqlite3_finalize(s);}return r;}

/* ── Globals for streaming ─────────────────────────────────────────── */
static int g_own_tgid = 0;
static int g_trace_fd = -1;
static pid_t g_child_pid = 0;
static char g_rbuf[1<<20];
static int g_rbuf_len = 0;
static int g_headless = 0; /* set when TV_SAVE_PATH is used; skips TUI */

/* ── Part 1: Schema & streaming ingest ────────────────────────────── */

static void db_create(void){xexec(
    "CREATE TABLE processes(tgid INTEGER PRIMARY KEY,pid INT,nspid INT,nstgid INT,"
    " ppid INT,exe TEXT,cwd TEXT,argv TEXT,env TEXT,auxv TEXT,first_ts REAL,last_ts REAL);"
    "CREATE TABLE events(id INTEGER PRIMARY KEY,tgid INT NOT NULL,ts REAL NOT NULL,event TEXT NOT NULL);"
    "CREATE TABLE open_events(eid INTEGER PRIMARY KEY,path TEXT,flags TEXT,fd INT,err INT);"
    "CREATE TABLE io_events(eid INTEGER PRIMARY KEY,stream TEXT NOT NULL,len INT,data TEXT);"
    "CREATE TABLE exit_events(eid INTEGER PRIMARY KEY,status TEXT,code INT,"
    " signal INT,core_dumped INT,raw INT);"
    "CREATE TABLE cwd_cache(tgid INTEGER PRIMARY KEY,cwd TEXT);");}

static void setup_app(void){
    xexec(
        "CREATE INDEX IF NOT EXISTS ix_ev_tg ON events(tgid);"
        "CREATE INDEX IF NOT EXISTS ix_ev_ts ON events(ts);"
        "CREATE INDEX IF NOT EXISTS ix_op_pa ON open_events(path);"
        "CREATE INDEX IF NOT EXISTS ix_ex_co ON exit_events(code);"
        "CREATE INDEX IF NOT EXISTS ix_pr_pp ON processes(ppid);"
        "CREATE TABLE IF NOT EXISTS expanded(id TEXT PRIMARY KEY,ex INT DEFAULT 1);"
        "INSERT OR IGNORE INTO expanded(id,ex) SELECT CAST(tgid AS TEXT),1 FROM processes;"
        "CREATE TABLE IF NOT EXISTS state("
        " cursor INT DEFAULT 0,scroll INT DEFAULT 0,"
        " focus INT DEFAULT 0,dcursor INT DEFAULT 0,dscroll INT DEFAULT 0,"
        " ts_mode INT DEFAULT 0,sort_key INT DEFAULT 0,grouped INT DEFAULT 1,"
        " search TEXT DEFAULT '',evfilt TEXT DEFAULT '',"
        " rows INT DEFAULT 24,cols INT DEFAULT 80,"
        " base_ts REAL DEFAULT 0,has_fts INT DEFAULT 0,mode INT DEFAULT 0,"
        " lp_filter INT DEFAULT 0);"
        "INSERT OR IGNORE INTO state(base_ts) VALUES((SELECT COALESCE(MIN(ts),0) FROM events));"
        "CREATE TABLE IF NOT EXISTS lpane(rownum INTEGER PRIMARY KEY,id TEXT NOT NULL,"
        " parent_id TEXT,style TEXT DEFAULT 'normal',text TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS rpane(rownum INTEGER PRIMARY KEY,style TEXT DEFAULT 'normal',"
        " text TEXT NOT NULL,link_mode INT DEFAULT -1,link_id TEXT DEFAULT '');"
        "CREATE TABLE IF NOT EXISTS search_hits(id TEXT PRIMARY KEY);"
        "CREATE TABLE IF NOT EXISTS cwd_cache(tgid INTEGER PRIMARY KEY,cwd TEXT);");}

static void setup_fts(void){
    char*e=0;if(sqlite3_exec(db,
        "CREATE VIRTUAL TABLE fts USING fts5(id UNINDEXED,source,content,tokenize='unicode61')",0,0,&e)==SQLITE_OK){
        xexec(
            "INSERT INTO fts(id,source,content) SELECT tgid,'argv',argv FROM processes WHERE argv IS NOT NULL;"
            "INSERT INTO fts(id,source,content) SELECT tgid,'env',env FROM processes WHERE env IS NOT NULL;"
            "INSERT INTO fts(id,source,content) SELECT e.tgid,'io',i.data FROM io_events i"
            " JOIN events e ON e.id=i.eid WHERE i.data IS NOT NULL;"
            "INSERT INTO fts(id,source,content) SELECT tgid,'open',GROUP_CONCAT(path,char(10))"
            " FROM(SELECT DISTINCT e.tgid,o.path FROM open_events o JOIN events e ON e.id=o.eid) GROUP BY tgid;"
            "UPDATE state SET has_fts=1;");
    }else sqlite3_free(e);}

/* Process one JSONL line from the trace */
static void process_line(const char *ln){
    if(!ln||ln[0]!='{') return;

    /* Extract event type and tgid */
    char ev[32]=""; int tgid=0;
    {sqlite3_stmt*st;
     sqlite3_prepare_v2(db,
         "SELECT COALESCE(json_extract(?1,'$.event'),''),"
         " COALESCE(CAST(json_extract(?1,'$.tgid')AS INT),0)",
         -1,&st,0);
     sqlite3_bind_text(st,1,ln,-1,SQLITE_TRANSIENT);
     if(sqlite3_step(st)==SQLITE_ROW){
         const char*e=(const char*)sqlite3_column_text(st,0);if(e)snprintf(ev,sizeof ev,"%s",e);
         tgid=sqlite3_column_int(st,1);}
     sqlite3_finalize(st);}
    if(!ev[0]||!tgid||tgid==g_own_tgid) return;

    /* Ensure process stub exists for all event types */
    {sqlite3_stmt*st;
     sqlite3_prepare_v2(db,
         "INSERT OR IGNORE INTO processes(tgid,pid,ppid,nspid,nstgid,first_ts,last_ts)"
         " VALUES(json_extract(?1,'$.tgid'),json_extract(?1,'$.pid'),json_extract(?1,'$.ppid'),"
         "  json_extract(?1,'$.nspid'),json_extract(?1,'$.nstgid'),"
         "  json_extract(?1,'$.ts'),json_extract(?1,'$.ts'))",
         -1,&st,0);
     sqlite3_bind_text(st,1,ln,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);}

    /* Ensure expanded entry */
    {sqlite3_stmt*st;
     sqlite3_prepare_v2(db,
         "INSERT OR IGNORE INTO expanded(id,ex) VALUES(CAST(json_extract(?1,'$.tgid')AS TEXT),1)",
         -1,&st,0);
     sqlite3_bind_text(st,1,ln,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);}

    /* CWD: update cwd_cache and processes.cwd, do NOT insert into events */
    if(strcmp(ev,"CWD")==0){
        {sqlite3_stmt*st;
         sqlite3_prepare_v2(db,
             "INSERT OR REPLACE INTO cwd_cache(tgid,cwd)"
             " VALUES(CAST(json_extract(?1,'$.tgid')AS INT),json_extract(?1,'$.path'))",
             -1,&st,0);
         sqlite3_bind_text(st,1,ln,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);}
        {sqlite3_stmt*st;
         sqlite3_prepare_v2(db,
             "UPDATE processes SET cwd=json_extract(?1,'$.path')"
             " WHERE tgid=CAST(json_extract(?1,'$.tgid')AS INT)",
             -1,&st,0);
         sqlite3_bind_text(st,1,ln,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);}
        return;}

    /* EXEC */
    if(strcmp(ev,"EXEC")==0){
        {sqlite3_stmt*st;
         sqlite3_prepare_v2(db,
             "UPDATE processes SET"
             " exe=json_extract(?1,'$.exe'),"
             " argv=CASE WHEN json_type(?1,'$.argv')='array' THEN"
             "  (SELECT GROUP_CONCAT(value,char(10)) FROM json_each(json_extract(?1,'$.argv')))"
             "  ELSE NULL END,"
             " env=CASE WHEN json_type(?1,'$.env')='object' THEN"
             "  (SELECT GROUP_CONCAT(key||'='||value,char(10)) FROM json_each(json_extract(?1,'$.env')))"
             "  ELSE NULL END,"
             " auxv=CASE WHEN json_type(?1,'$.auxv')='object' THEN"
             "  (SELECT GROUP_CONCAT(key||'='||value,char(10)) FROM json_each(json_extract(?1,'$.auxv')))"
             "  ELSE NULL END,"
             " first_ts=MIN(first_ts,json_extract(?1,'$.ts')),"
             " last_ts=MAX(last_ts,json_extract(?1,'$.ts'))"
             " WHERE tgid=CAST(json_extract(?1,'$.tgid')AS INT)",
             -1,&st,0);
         sqlite3_bind_text(st,1,ln,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);}
        {sqlite3_stmt*st;
         sqlite3_prepare_v2(db,
             "INSERT INTO events(tgid,ts,event)"
             " VALUES(json_extract(?1,'$.tgid'),json_extract(?1,'$.ts'),'EXEC')",
             -1,&st,0);
         sqlite3_bind_text(st,1,ln,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);}
        return;}

    /* OPEN */
    if(strcmp(ev,"OPEN")==0){
        char path[8192]=""; char flag0[32]="O_RDONLY";
        {sqlite3_stmt*st;
         sqlite3_prepare_v2(db,
             "SELECT COALESCE(json_extract(?1,'$.path'),''),"
             " COALESCE(json_extract(?1,'$.flags[0]'),'O_RDONLY')",
             -1,&st,0);
         sqlite3_bind_text(st,1,ln,-1,SQLITE_TRANSIENT);
         if(sqlite3_step(st)==SQLITE_ROW){
             const char*p=(const char*)sqlite3_column_text(st,0);if(p)snprintf(path,sizeof path,"%s",p);
             const char*f=(const char*)sqlite3_column_text(st,1);if(f)snprintf(flag0,sizeof flag0,"%s",f);}
         sqlite3_finalize(st);}

        /* Resolve relative path using cwd_cache.
         * Skip paths that are kernel pseudo-paths (pipe:[N], socket:[N], anon_inode:...)
         * since they are not real filesystem paths and should not have CWD prepended. */
        if(path[0]&&path[0]!='/'&&strncmp(path,"pipe:",5)!=0&&strncmp(path,"socket:",7)!=0&&strncmp(path,"anon_inode:",11)!=0){
            char cwd[4096]="";
            {sqlite3_stmt*st;
             sqlite3_prepare_v2(db,"SELECT COALESCE(cwd,'') FROM cwd_cache WHERE tgid=?",-1,&st,0);
             sqlite3_bind_int(st,1,tgid);
             if(sqlite3_step(st)==SQLITE_ROW){const char*c=(const char*)sqlite3_column_text(st,0);if(c&&c[0])snprintf(cwd,sizeof cwd,"%s",c);}
             sqlite3_finalize(st);}
            if(cwd[0]){char abs[8192];snprintf(abs,sizeof abs,"%s/%s",cwd,path);snprintf(path,8192,"%s",abs);}}

        /* Filter: read-only opens to noisy system paths */
        if(strcmp(flag0,"O_RDONLY")==0&&path[0]=='/'){
            static const char*sys[]={"/usr/","/lib/","/lib64/","/bin/","/sbin/","/opt/","/srv/",NULL};
            for(int i=0;sys[i];i++) if(strncmp(path,sys[i],strlen(sys[i]))==0) return;}

        /* Insert event */
        long long eid;
        {sqlite3_stmt*st;
         sqlite3_prepare_v2(db,
             "INSERT INTO events(tgid,ts,event)"
             " VALUES(json_extract(?1,'$.tgid'),json_extract(?1,'$.ts'),'OPEN')",
             -1,&st,0);
         sqlite3_bind_text(st,1,ln,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);}
        eid=sqlite3_last_insert_rowid(db);

        /* Insert open_event with resolved absolute path */
        {sqlite3_stmt*st;
         sqlite3_prepare_v2(db,
             "INSERT INTO open_events(eid,path,flags,fd,err) VALUES(?1,?2,"
             " CASE WHEN json_type(?3,'$.flags')='array' THEN"
             "  (SELECT GROUP_CONCAT(value,'|') FROM json_each(json_extract(?3,'$.flags')))"
             "  ELSE NULL END,"
             " json_extract(?3,'$.fd'),json_extract(?3,'$.err'))",
             -1,&st,0);
         sqlite3_bind_int64(st,1,eid);
         sqlite3_bind_text(st,2,path,-1,SQLITE_TRANSIENT);
         sqlite3_bind_text(st,3,ln,-1,SQLITE_TRANSIENT);
         sqlite3_step(st);sqlite3_finalize(st);}

        /* Update process timestamps */
        {sqlite3_stmt*st;
         sqlite3_prepare_v2(db,
             "UPDATE processes SET"
             " last_ts=MAX(last_ts,json_extract(?1,'$.ts')),"
             " first_ts=MIN(first_ts,json_extract(?1,'$.ts'))"
             " WHERE tgid=CAST(json_extract(?1,'$.tgid')AS INT)",
             -1,&st,0);
         sqlite3_bind_text(st,1,ln,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);}
        return;}

    /* EXIT */
    if(strcmp(ev,"EXIT")==0){
        long long eid;
        {sqlite3_stmt*st;
         sqlite3_prepare_v2(db,
             "INSERT INTO events(tgid,ts,event)"
             " VALUES(json_extract(?1,'$.tgid'),json_extract(?1,'$.ts'),'EXIT')",
             -1,&st,0);
         sqlite3_bind_text(st,1,ln,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);}
        eid=sqlite3_last_insert_rowid(db);
        {sqlite3_stmt*st;
         sqlite3_prepare_v2(db,
             "INSERT INTO exit_events(eid,status,code,signal,core_dumped,raw)"
             " VALUES(?1,json_extract(?2,'$.status'),json_extract(?2,'$.code'),"
             "  json_extract(?2,'$.signal'),json_extract(?2,'$.core_dumped'),json_extract(?2,'$.raw'))",
             -1,&st,0);
         sqlite3_bind_int64(st,1,eid);sqlite3_bind_text(st,2,ln,-1,SQLITE_TRANSIENT);
         sqlite3_step(st);sqlite3_finalize(st);}
        {sqlite3_stmt*st;
         sqlite3_prepare_v2(db,
             "UPDATE processes SET last_ts=MAX(last_ts,json_extract(?1,'$.ts'))"
             " WHERE tgid=CAST(json_extract(?1,'$.tgid')AS INT)",
             -1,&st,0);
         sqlite3_bind_text(st,1,ln,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);}
        return;}

    /* STDOUT / STDERR */
    if(strcmp(ev,"STDOUT")==0||strcmp(ev,"STDERR")==0){
        long long eid;
        {sqlite3_stmt*st;
         sqlite3_prepare_v2(db,
             "INSERT INTO events(tgid,ts,event)"
             " VALUES(json_extract(?1,'$.tgid'),json_extract(?1,'$.ts'),?2)",
             -1,&st,0);
         sqlite3_bind_text(st,1,ln,-1,SQLITE_TRANSIENT);
         sqlite3_bind_text(st,2,ev,-1,SQLITE_STATIC);
         sqlite3_step(st);sqlite3_finalize(st);}
        eid=sqlite3_last_insert_rowid(db);
        {sqlite3_stmt*st;
         sqlite3_prepare_v2(db,
             "INSERT INTO io_events(eid,stream,len,data)"
             " VALUES(?1,?2,json_extract(?3,'$.len'),json_extract(?3,'$.data'))",
             -1,&st,0);
         sqlite3_bind_int64(st,1,eid);
         sqlite3_bind_text(st,2,ev,-1,SQLITE_STATIC);
         sqlite3_bind_text(st,3,ln,-1,SQLITE_TRANSIENT);
         sqlite3_step(st);sqlite3_finalize(st);}
        {sqlite3_stmt*st;
         sqlite3_prepare_v2(db,
             "UPDATE processes SET last_ts=MAX(last_ts,json_extract(?1,'$.ts'))"
             " WHERE tgid=CAST(json_extract(?1,'$.tgid')AS INT)",
             -1,&st,0);
         sqlite3_bind_text(st,1,ln,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);}
        return;}}

/* ── Part 2: App state & SQL logic ─────────────────────────────────── */

#define BNAME(c) "REPLACE("c",RTRIM("c",REPLACE("c",'/','')),'') "
#define DUR(d) "CASE WHEN "d">=1 THEN printf('%%.2fs',"d") WHEN "d">=.001 THEN printf('%%.1fms',("d")*1e3) WHEN "d">0 THEN printf('%%.0fµs',("d")*1e6) ELSE '' END"

/* ── Filter lpane to matching processes ────────────────────────────── */
static void apply_lp_filter(void){
    int filt=qint("SELECT lp_filter FROM state",0);
    if(!filt) return;

    /* Remember current cursor item so it stays visible */
    char pinned[64]="";
    {sqlite3_stmt*st;
     sqlite3_prepare_v2(db,
         "SELECT COALESCE(id,'') FROM lpane WHERE rownum=(SELECT cursor FROM state)",
         -1,&st,0);
     if(sqlite3_step(st)==SQLITE_ROW){const char*t=(const char*)sqlite3_column_text(st,0);if(t)snprintf(pinned,sizeof pinned,"%s",t);}
     sqlite3_finalize(st);}

    if(filt==1){
        /* Failed: signaled, or non-zero exit with ≥1 write-mode open; plus ancestors */
        sqlite3_stmt*st;
        sqlite3_prepare_v2(db,
            "WITH RECURSIVE"
            " failed(tgid) AS("
            "  SELECT p.tgid FROM processes p"
            "  JOIN events ev ON ev.tgid=p.tgid AND ev.event='EXIT'"
            "  JOIN exit_events x ON x.eid=ev.id"
            "  WHERE x.signal IS NOT NULL"
            "   OR(x.code IS NOT NULL AND x.code!=0"
            "      AND EXISTS(SELECT 1 FROM open_events o JOIN events e ON e.id=o.eid"
            "       WHERE e.tgid=p.tgid"
            "        AND(o.flags LIKE 'O_WRONLY%' OR o.flags LIKE 'O_RDWR%')))"
            " ),"
            " visible(tgid) AS("
            "  SELECT tgid FROM failed"
            "  UNION SELECT p2.ppid FROM processes p2 JOIN visible v ON p2.tgid=v.tgid"
            "   WHERE p2.ppid IS NOT NULL AND p2.ppid IN(SELECT tgid FROM processes)"
            " )"
            " DELETE FROM lpane"
            "  WHERE CAST(id AS INT) NOT IN(SELECT tgid FROM visible) AND id!=?",
            -1,&st,0);
        sqlite3_bind_text(st,1,pinned,-1,SQLITE_TRANSIENT);
        sqlite3_step(st);sqlite3_finalize(st);
    } else if(filt==2){
        /* Running: no EXIT event yet; plus ancestors */
        sqlite3_stmt*st;
        sqlite3_prepare_v2(db,
            "WITH RECURSIVE"
            " running(tgid) AS("
            "  SELECT tgid FROM processes"
            "  WHERE NOT EXISTS("
            "   SELECT 1 FROM events WHERE events.tgid=processes.tgid AND events.event='EXIT')"
            " ),"
            " visible(tgid) AS("
            "  SELECT tgid FROM running"
            "  UNION SELECT p2.ppid FROM processes p2 JOIN visible v ON p2.tgid=v.tgid"
            "   WHERE p2.ppid IS NOT NULL AND p2.ppid IN(SELECT tgid FROM processes)"
            " )"
            " DELETE FROM lpane"
            "  WHERE CAST(id AS INT) NOT IN(SELECT tgid FROM visible) AND id!=?",
            -1,&st,0);
        sqlite3_bind_text(st,1,pinned,-1,SQLITE_TRANSIENT);
        sqlite3_step(st);sqlite3_finalize(st);}

    /* Re-number rows after deletion */
    xexec(
        "CREATE TEMP TABLE _lp AS"
        " SELECT ROW_NUMBER()OVER(ORDER BY rownum)-1 AS rn,id,parent_id,style,text FROM lpane;"
        "DELETE FROM lpane;"
        "INSERT INTO lpane(rownum,id,parent_id,style,text) SELECT*FROM _lp;"
        "DROP TABLE _lp;");

    /* Restore cursor to pinned item if it survived */
    if(pinned[0]){
        sqlite3_stmt*st;
        sqlite3_prepare_v2(db,"SELECT rownum FROM lpane WHERE id=?",-1,&st,0);
        sqlite3_bind_text(st,1,pinned,-1,SQLITE_TRANSIENT);
        if(sqlite3_step(st)==SQLITE_ROW)
            xexecf("UPDATE state SET cursor=%d",sqlite3_column_int(st,0));
        sqlite3_finalize(st);}}

/* ── Rebuild lpane ─────────────────────────────────────────────────── */

static void rebuild_procs(void){
    int gr=qint("SELECT grouped FROM state",1);
    int sk=qint("SELECT sort_key FROM state",0);
    const char*bo,*co,*fo; /* tree-root, tree-child, flat ORDER BY column */
    switch(sk){case 1:bo="p2.first_ts";co="c.first_ts";fo="p.first_ts";break;
               case 2:bo="p2.last_ts";co="c.last_ts";fo="p.last_ts";break;
               default:bo="p2.tgid";co="c.tgid";fo="p.tgid";}
    if(gr){
        xexec("INSERT OR IGNORE INTO expanded(id,ex) SELECT CAST(tgid AS TEXT),1 FROM processes;");
        char sql[8192];snprintf(sql,sizeof sql,
            "INSERT INTO lpane(rownum,id,parent_id,style,text)"
            " SELECT ROW_NUMBER()OVER()-1,CAST(f.tgid AS TEXT),CAST(p.ppid AS TEXT),"
            "  CASE WHEN f.tgid IN(SELECT CAST(id AS INT) FROM search_hits) THEN 'search'"
            "       WHEN x.code IS NOT NULL AND x.code!=0 THEN 'error'"
            "       WHEN x.signal IS NOT NULL THEN 'error' ELSE 'normal' END,"
            "  printf('%%*s%%s[%%d] %%s%%s%%s %%s',f.depth*2,'',"
            "   CASE WHEN NOT EXISTS(SELECT 1 FROM processes WHERE ppid=f.tgid) THEN '  '"
            "        WHEN COALESCE((SELECT ex FROM expanded WHERE id=CAST(f.tgid AS TEXT)),1) THEN '▼ ' ELSE '▶ ' END,"
            "   f.tgid,COALESCE(" BNAME("p.exe") ",'?'),"
            "   CASE WHEN x.code IS NOT NULL AND x.code!=0 THEN ' ✗'"
            "        WHEN x.signal IS NOT NULL THEN printf(' ⚡%%d',x.signal)"
            "        WHEN x.code IS NOT NULL THEN ' ✓' ELSE '' END,"
            "   CASE WHEN(SELECT COUNT(*)FROM processes WHERE ppid=f.tgid)>0"
            "    THEN printf(' (%%d)',(WITH RECURSIVE d(t) AS(SELECT tgid FROM processes WHERE ppid=f.tgid"
            "     UNION ALL SELECT c2.tgid FROM processes c2 JOIN d ON c2.ppid=d.t)SELECT COUNT(*)FROM d))ELSE'' END,"
            "   " DUR("p.last_ts-p.first_ts") ")"
            " FROM(WITH RECURSIVE flat(tgid,depth,sk) AS("
            "  SELECT p2.tgid,0,%s FROM processes p2"
            "   WHERE p2.ppid IS NULL OR p2.ppid NOT IN(SELECT tgid FROM processes)"
            "  UNION ALL SELECT c.tgid,flat.depth+1,%s FROM processes c"
            "   JOIN flat ON c.ppid=flat.tgid"
            "   JOIN expanded ex ON ex.id=CAST(flat.tgid AS TEXT) WHERE ex.ex=1 ORDER BY 3"
            " )SELECT tgid,depth FROM flat)f"
            " JOIN processes p ON p.tgid=f.tgid"
            " LEFT JOIN events ev ON ev.tgid=f.tgid AND ev.event='EXIT'"
            " LEFT JOIN exit_events x ON x.eid=ev.id",bo,co);
        xexec(sql);
    } else {
        xexecf(
            "INSERT INTO lpane(rownum,id,parent_id,style,text)"
            " SELECT ROW_NUMBER()OVER(ORDER BY %s)-1,CAST(p.tgid AS TEXT),CAST(p.ppid AS TEXT),"
            "  CASE WHEN p.tgid IN(SELECT CAST(id AS INT) FROM search_hits) THEN 'search'"
            "       WHEN x.code IS NOT NULL AND x.code!=0 THEN 'error'"
            "       WHEN x.signal IS NOT NULL THEN 'error' ELSE 'normal' END,"
            "  printf('[%%d] %%s%%s %%s',p.tgid,COALESCE(" BNAME("p.exe") ",'?'),"
            "   CASE WHEN x.code IS NOT NULL AND x.code!=0 THEN ' ✗'"
            "        WHEN x.signal IS NOT NULL THEN printf(' ⚡%%d',x.signal)"
            "        WHEN x.code IS NOT NULL THEN ' ✓' ELSE '' END," DUR("p.last_ts-p.first_ts") ")"
            " FROM processes p LEFT JOIN events ev ON ev.tgid=p.tgid AND ev.event='EXIT'"
            " LEFT JOIN exit_events x ON x.eid=ev.id",fo);
    }
}

static void rebuild_files(void){
    int sk=qint("SELECT sort_key FROM state",0);
    const char*ob;switch(sk){case 1:ob="MIN(e.ts)";break;case 2:ob="MAX(e.ts)";break;default:ob="o.path";}
    xexecf(
        "INSERT INTO lpane(rownum,id,parent_id,style,text)"
        " SELECT ROW_NUMBER()OVER(ORDER BY %s)-1,o.path,NULL,"
        "  CASE WHEN o.path IN(SELECT id FROM search_hits) THEN 'search'"
        "       WHEN SUM(CASE WHEN o.err IS NOT NULL THEN 1 ELSE 0 END)>0 THEN 'error'"
        "       ELSE 'normal' END,"
        "  printf('%%s  [%%d opens, %%d procs%%s]',o.path,COUNT(*),COUNT(DISTINCT e.tgid),"
        "   CASE WHEN SUM(o.err IS NOT NULL)>0 THEN printf(', %%d errs',SUM(o.err IS NOT NULL)) ELSE '' END)"
        " FROM open_events o JOIN events e ON e.id=o.eid WHERE o.path IS NOT NULL GROUP BY o.path",ob);
}

static void rebuild_outputs(void){
    int gr=qint("SELECT grouped FROM state",1);
    if(gr){
        xexec("INSERT OR IGNORE INTO expanded(id,ex)"
            " SELECT DISTINCT 'io_'||CAST(e.tgid AS TEXT),1 FROM io_events i JOIN events e ON e.id=i.eid;");
        xexec(
            "INSERT INTO lpane(rownum,id,parent_id,style,text)"
            " SELECT ROW_NUMBER()OVER(ORDER BY sub.g_ts,sub.s_ts)-1,sub.id,sub.par,sub.sty,sub.txt FROM("
            "  SELECT 'io_'||CAST(e.tgid AS TEXT) AS id,NULL AS par,'cyan_bold' AS sty,"
            "   printf('── PID %d %s (%d lines) ──',e.tgid,COALESCE(" BNAME("p.exe") ",'?'),COUNT(*)) AS txt,"
            "   MIN(e.ts) AS g_ts,0.0 AS s_ts"
            "  FROM io_events i JOIN events e ON e.id=i.eid JOIN processes p ON p.tgid=e.tgid GROUP BY e.tgid"
            "  UNION ALL"
            "  SELECT CAST(e.id AS TEXT),'io_'||CAST(e.tgid AS TEXT),"
            "   CASE WHEN i.stream='STDERR' THEN 'error' ELSE 'normal' END,"
            "   printf('  %s %s',i.stream,SUBSTR(REPLACE(COALESCE(i.data,''),char(10),'↵'),1,200)),"
            "   (SELECT MIN(e2.ts) FROM events e2 JOIN io_events i2 ON i2.eid=e2.id WHERE e2.tgid=e.tgid),e.ts"
            "  FROM io_events i JOIN events e ON e.id=i.eid"
            "  WHERE EXISTS(SELECT 1 FROM expanded WHERE id='io_'||CAST(e.tgid AS TEXT) AND ex=1)"
            " )sub;");
    } else {
        xexec(
            "INSERT INTO lpane(rownum,id,parent_id,style,text)"
            " SELECT ROW_NUMBER()OVER(ORDER BY e.ts)-1,CAST(e.id AS TEXT),NULL,"
            "  CASE WHEN i.stream='STDERR' THEN 'error' ELSE 'normal' END,"
            "  printf('[%d] %s %s',e.tgid,i.stream,SUBSTR(REPLACE(COALESCE(i.data,''),char(10),'↵'),1,200))"
            " FROM io_events i JOIN events e ON e.id=i.eid ORDER BY e.ts;");
    }
}

static void rebuild_lpane(void){
    xexec("DELETE FROM lpane;");
    int mode=qint("SELECT mode FROM state",0);
    switch(mode){case 0:rebuild_procs();break;case 1:rebuild_files();break;case 2:rebuild_outputs();break;}
    if(mode==0) apply_lp_filter();
    xexec("UPDATE state SET cursor=MIN(cursor,MAX((SELECT COUNT(*)-1 FROM lpane),0));");
}

/* ── Rebuild rpane ─────────────────────────────────────────────────── */

static void rpane_proc(int tgid){
    int tsm=qint("SELECT ts_mode FROM state",0);double bts=qdbl("SELECT base_ts FROM state",0);
    char ef[64]="";{sqlite3_stmt*s;sqlite3_prepare_v2(db,"SELECT evfilt FROM state",-1,&s,0);
        if(sqlite3_step(s)==SQLITE_ROW){const char*t=(const char*)sqlite3_column_text(s,0);if(t&&t[0])snprintf(ef,sizeof ef,"%s",t);}sqlite3_finalize(s);}

    xexecf("INSERT INTO rpane VALUES(0,'heading','─── Process ───',-1,'')");
    xexecf("INSERT INTO rpane SELECT 1,'cyan',printf('TGID:  %%d',tgid),-1,'' FROM processes WHERE tgid=%d",tgid);
    xexecf("INSERT INTO rpane SELECT 2,'cyan',printf('PPID:  %%d',ppid),0,CAST(ppid AS TEXT) FROM processes WHERE tgid=%d AND ppid IS NOT NULL",tgid);
    xexecf("INSERT INTO rpane SELECT 3,'green',printf('EXE:   %%s',COALESCE(exe,'?')),-1,'' FROM processes WHERE tgid=%d",tgid);
    xexecf("INSERT INTO rpane SELECT 4,'green',printf('CWD:   %%s',COALESCE(cwd,'?')),-1,'' FROM processes WHERE tgid=%d",tgid);
    /* Argv */
    xexecf("WITH RECURSIVE sp(i,rest,line) AS("
        " SELECT 0,"
        "  CASE WHEN INSTR(argv,char(10))>0 THEN SUBSTR(argv,INSTR(argv,char(10))+1) ELSE '' END,"
        "  CASE WHEN INSTR(argv,char(10))>0 THEN SUBSTR(argv,1,INSTR(argv,char(10))-1) ELSE argv END"
        "  FROM processes WHERE tgid=%d AND argv IS NOT NULL"
        " UNION ALL SELECT i+1,"
        "  CASE WHEN INSTR(rest,char(10))>0 THEN SUBSTR(rest,INSTR(rest,char(10))+1) ELSE '' END,"
        "  CASE WHEN INSTR(rest,char(10))>0 THEN SUBSTR(rest,1,INSTR(rest,char(10))-1) ELSE rest END"
        "  FROM sp WHERE LENGTH(rest)>0"
        ")INSERT INTO rpane SELECT 10+i,'normal',printf('  [%%d] %%s',i,line),-1,'' FROM sp",tgid);
    /* Exit */
    xexecf(
        "INSERT INTO rpane SELECT 200,"
        " CASE WHEN x.signal IS NOT NULL THEN 'error' WHEN x.code!=0 THEN 'error' ELSE 'green' END,"
        " CASE WHEN x.signal IS NOT NULL THEN printf('Exit: signal %%d%%s',x.signal,"
        "   CASE WHEN x.core_dumped THEN ' (core)' ELSE '' END)"
        "  ELSE printf('Exit: %%s code=%%d',COALESCE(x.status,'?'),COALESCE(x.code,-1)) END,"
        " -1,'' FROM events ev JOIN exit_events x ON x.eid=ev.id WHERE ev.tgid=%d AND ev.event='EXIT'",tgid);
    xexecf("INSERT INTO rpane SELECT 201,'cyan','Duration: '||" DUR("last_ts-first_ts") ",-1,'' FROM processes WHERE tgid=%d",tgid);
    /* Children */
    xexecf("INSERT INTO rpane VALUES(300,'heading',printf('─── Children (%%d) ───',"
        "(SELECT COUNT(*) FROM processes WHERE ppid=%d)),-1,'')",tgid);
    xexecf("INSERT INTO rpane SELECT 301+rowid,'normal',"
        " printf('  [%%d] %%s',tgid,COALESCE(" BNAME("exe") ",'?')),0,CAST(tgid AS TEXT)"
        " FROM(SELECT tgid,exe,rowid FROM processes WHERE ppid=%d ORDER BY first_ts LIMIT 50)",tgid);
    /* Events */
    char fc[128]="";if(ef[0])snprintf(fc,sizeof fc," AND e.event='%s'",ef);
    xexecf("INSERT INTO rpane VALUES(500,'heading',printf('─── Events (%%d)%%s ───',"
        "(SELECT COUNT(*) FROM events WHERE tgid=%d),"
        "CASE WHEN '%s'!='' THEN printf(' [%%s]','%s') ELSE '' END),-1,'')",tgid,ef,ef);
    xexecf(
        "INSERT INTO rpane SELECT 501+ROW_NUMBER()OVER(ORDER BY e.ts),"
        " CASE WHEN e.event='EXEC' THEN 'cyan_bold'"
        "      WHEN e.event='EXIT' AND(COALESCE(x.code,0)!=0 OR x.signal IS NOT NULL) THEN 'error'"
        "      WHEN e.event='EXIT' THEN 'green'"
        "      WHEN e.event='OPEN' AND o.err IS NOT NULL THEN 'error'"
        "      WHEN e.event='OPEN' THEN 'green'"
        "      WHEN e.event IN('STDERR','STDOUT') THEN 'yellow' ELSE 'normal' END,"
        " printf('%%s %%-6s %%s',"
        "  CASE %d WHEN 0 THEN printf('%%.6f',e.ts)"
        "   WHEN 1 THEN printf('+%%.6f',e.ts-%f)"
        "   ELSE printf('Δ%%.6f',e.ts-COALESCE(LAG(e.ts)OVER(ORDER BY e.ts),e.ts)) END,"
        "  e.event,"
        "  CASE WHEN e.event='OPEN' THEN printf('%%s [%%s]%%s%%s',COALESCE(o.path,'?'),COALESCE(o.flags,'?'),"
        "    CASE WHEN o.fd IS NOT NULL THEN printf(' fd=%%d',o.fd) ELSE '' END,"
        "    CASE WHEN o.err IS NOT NULL THEN printf(' err=%%d',o.err) ELSE '' END)"
        "   WHEN e.event IN('STDERR','STDOUT') THEN SUBSTR(REPLACE(COALESCE(i.data,''),char(10),'↵'),1,200)"
        "   WHEN e.event='EXIT' THEN CASE WHEN x.signal IS NOT NULL THEN printf('signal=%%d',x.signal)"
        "    ELSE printf('%%s code=%%d',COALESCE(x.status,'?'),COALESCE(x.code,-1)) END"
        "   ELSE '' END),"
        " CASE WHEN e.event='OPEN' THEN 1 WHEN e.event IN('STDERR','STDOUT') THEN 2 ELSE -1 END,"
        " CASE WHEN e.event='OPEN' THEN COALESCE(o.path,'') WHEN e.event IN('STDERR','STDOUT') THEN CAST(e.id AS TEXT) ELSE '' END"
        " FROM events e LEFT JOIN open_events o ON o.eid=e.id LEFT JOIN io_events i ON i.eid=e.id"
        " LEFT JOIN exit_events x ON x.eid=e.id WHERE e.tgid=%d%s ORDER BY e.ts LIMIT 5000",
        tsm,bts,tgid,fc);
}

static void rpane_file(const char *path){
    int tsm=qint("SELECT ts_mode FROM state",0);double bts=qdbl("SELECT base_ts FROM state",0);
    xexecf("INSERT INTO rpane VALUES(0,'heading','─── File ───',-1,'')");
    sqlite3_stmt*st;
    sqlite3_prepare_v2(db,"INSERT INTO rpane VALUES(1,'green',printf('Path: %s',?),-1,'')",-1,&st,0);
    sqlite3_bind_text(st,1,path,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);
    sqlite3_prepare_v2(db,
        "INSERT INTO rpane SELECT 2,'cyan',printf('Opens: %d  Errors: %d  Procs: %d',"
        " COUNT(*),SUM(o.err IS NOT NULL),COUNT(DISTINCT e.tgid)),-1,''"
        " FROM open_events o JOIN events e ON e.id=o.eid WHERE o.path=?",-1,&st,0);
    sqlite3_bind_text(st,1,path,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);
    xexecf("INSERT INTO rpane VALUES(10,'heading','─── Accesses ───',-1,'')");
    sqlite3_prepare_v2(db,
        "INSERT INTO rpane SELECT 11+ROW_NUMBER()OVER(ORDER BY e.ts),"
        " CASE WHEN o.err IS NOT NULL THEN 'error' ELSE 'green' END,"
        " printf('%s  PID %d (%s)  [%s]%s%s',"
        "  CASE ?2 WHEN 0 THEN printf('%.6f',e.ts) WHEN 1 THEN printf('+%.6f',e.ts-?3)"
        "   ELSE printf('Δ%.6f',e.ts-COALESCE(LAG(e.ts)OVER(ORDER BY e.ts),e.ts)) END,"
        "  e.tgid,COALESCE(" BNAME("p.exe") ",'?'),COALESCE(o.flags,'?'),"
        "  CASE WHEN o.fd IS NOT NULL THEN printf(' fd=%d',o.fd) ELSE '' END,"
        "  CASE WHEN o.err IS NOT NULL THEN printf(' err=%d',o.err) ELSE '' END),"
        " 0,CAST(e.tgid AS TEXT)"
        " FROM open_events o JOIN events e ON e.id=o.eid JOIN processes p ON p.tgid=e.tgid"
        " WHERE o.path=?1 ORDER BY e.ts LIMIT 5000",-1,&st,0);
    sqlite3_bind_text(st,1,path,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,2,tsm);sqlite3_bind_double(st,3,bts);
    sqlite3_step(st);sqlite3_finalize(st);
}

static void rpane_output(const char *id){
    if(!strncmp(id,"io_",3)){rpane_proc(atoi(id+3));return;}
    int eid=atoi(id);
    xexecf("INSERT INTO rpane VALUES(0,'heading','─── Output ───',-1,'')");
    xexecf("INSERT INTO rpane SELECT 1,'cyan',printf('Stream: %%s  PID: %%d',i.stream,e.tgid),"
        "0,CAST(e.tgid AS TEXT) FROM io_events i JOIN events e ON e.id=i.eid WHERE e.id=%d",eid);
    xexecf("INSERT INTO rpane SELECT 2,'green',printf('Process: %%s',COALESCE(p.exe,'?')),"
        "0,CAST(p.tgid AS TEXT) FROM events e JOIN processes p ON p.tgid=e.tgid WHERE e.id=%d",eid);
    xexecf("INSERT INTO rpane VALUES(5,'heading','─── Content ───',-1,'')");
    xexecf("WITH RECURSIVE sp(i,rest,line) AS("
        " SELECT 0,SUBSTR(data,INSTR(data,char(10))+1),"
        "  CASE WHEN INSTR(data,char(10))>0 THEN SUBSTR(data,1,INSTR(data,char(10))-1) ELSE data END"
        "  FROM io_events WHERE eid=%d"
        " UNION ALL SELECT i+1,"
        "  CASE WHEN INSTR(rest,char(10))>0 THEN SUBSTR(rest,INSTR(rest,char(10))+1) ELSE '' END,"
        "  CASE WHEN INSTR(rest,char(10))>0 THEN SUBSTR(rest,1,INSTR(rest,char(10))-1) ELSE rest END"
        "  FROM sp WHERE LENGTH(rest)>0"
        ")INSERT INTO rpane SELECT 10+i,'normal',line,-1,'' FROM sp",eid);
}

static void rebuild_rpane(void){
    xexec("DELETE FROM rpane;");
    int mode=qint("SELECT mode FROM state",0),cursor=qint("SELECT cursor FROM state",0);
    sqlite3_stmt*st;sqlite3_prepare_v2(db,"SELECT id FROM lpane WHERE rownum=?",-1,&st,0);
    sqlite3_bind_int(st,1,cursor);char id[4096]="";
    if(sqlite3_step(st)==SQLITE_ROW){const char*t=(const char*)sqlite3_column_text(st,0);if(t)snprintf(id,sizeof id,"%s",t);}
    sqlite3_finalize(st);if(!id[0])return;
    switch(mode){case 0:rpane_proc(atoi(id));break;case 1:rpane_file(id);break;case 2:rpane_output(id);break;}
    xexec("CREATE TEMP TABLE _rp AS SELECT ROW_NUMBER()OVER(ORDER BY rownum)-1 AS rn,style,text,link_mode,link_id FROM rpane;"
        "DELETE FROM rpane;INSERT INTO rpane SELECT*FROM _rp;DROP TABLE _rp;");
    /* Highlight search matches in detail pane */
    {char sq[256]="";
     {sqlite3_stmt*st2;sqlite3_prepare_v2(db,"SELECT search FROM state",-1,&st2,0);
      if(sqlite3_step(st2)==SQLITE_ROW){const char*t=(const char*)sqlite3_column_text(st2,0);if(t&&t[0])snprintf(sq,sizeof sq,"%s",t);}
      sqlite3_finalize(st2);}
     if(sq[0]){char lk[260];snprintf(lk,sizeof lk,"%%%s%%",sq);
         sqlite3_stmt*st2;sqlite3_prepare_v2(db,"UPDATE rpane SET style='search' WHERE style='normal' AND text LIKE ?",-1,&st2,0);
         sqlite3_bind_text(st2,1,lk,-1,SQLITE_TRANSIENT);sqlite3_step(st2);sqlite3_finalize(st2);}}}

/* ── Search & navigation ───────────────────────────────────────────── */

static void do_search(const char *q){
    xexec("DELETE FROM search_hits;");if(!q||!q[0])return;
    int mode=qint("SELECT mode FROM state",0);char lk[512];snprintf(lk,sizeof lk,"%%%s%%",q);
    sqlite3_stmt*st;
    if(mode==0){
        if(qint("SELECT has_fts FROM state",0)){char fq[512];snprintf(fq,sizeof fq,"\"%s\"*",q);
            sqlite3_prepare_v2(db,"INSERT OR IGNORE INTO search_hits(id) SELECT DISTINCT CAST(pid AS TEXT) FROM fts WHERE fts MATCH ?",-1,&st,0);
            sqlite3_bind_text(st,1,fq,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);}
        sqlite3_prepare_v2(db,"INSERT OR IGNORE INTO search_hits(id) SELECT CAST(tgid AS TEXT) FROM processes"
            " WHERE CAST(tgid AS TEXT) LIKE ?1 OR exe LIKE ?1 OR argv LIKE ?1",-1,&st,0);
        sqlite3_bind_text(st,1,lk,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);
    } else if(mode==1){
        sqlite3_prepare_v2(db,"INSERT OR IGNORE INTO search_hits(id) SELECT DISTINCT path FROM open_events WHERE path LIKE ?",-1,&st,0);
        sqlite3_bind_text(st,1,lk,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);
    } else {
        sqlite3_prepare_v2(db,"INSERT OR IGNORE INTO search_hits(id) SELECT CAST(e.id AS TEXT) FROM io_events i"
            " JOIN events e ON e.id=i.eid WHERE i.data LIKE ?",-1,&st,0);
        sqlite3_bind_text(st,1,lk,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);
    }
}
static void jump_hit(int dir){
    int c=qint("SELECT cursor FROM state",0);sqlite3_stmt*st;
    const char*sql=dir>0?"SELECT MIN(rownum) FROM lpane WHERE id IN(SELECT id FROM search_hits)AND rownum>?"
                        :"SELECT MAX(rownum) FROM lpane WHERE id IN(SELECT id FROM search_hits)AND rownum<?";
    sqlite3_prepare_v2(db,sql,-1,&st,0);sqlite3_bind_int(st,1,c);int f=-1;
    if(sqlite3_step(st)==SQLITE_ROW&&sqlite3_column_type(st,0)!=SQLITE_NULL)f=sqlite3_column_int(st,0);
    sqlite3_finalize(st);
    if(f<0){sql=dir>0?"SELECT MIN(rownum) FROM lpane WHERE id IN(SELECT id FROM search_hits)"
                      :"SELECT MAX(rownum) FROM lpane WHERE id IN(SELECT id FROM search_hits)";f=qint(sql,-1);}
    if(f>=0){xexecf("UPDATE state SET cursor=%d,dscroll=0,dcursor=0",f);rebuild_rpane();}
}
static void follow_link(void){
    int dc=qint("SELECT dcursor FROM state",0);sqlite3_stmt*st;
    sqlite3_prepare_v2(db,"SELECT link_mode,link_id FROM rpane WHERE rownum=? AND link_mode>=0",-1,&st,0);
    sqlite3_bind_int(st,1,dc);
    if(sqlite3_step(st)==SQLITE_ROW){int tm=sqlite3_column_int(st,0);
        const char*ti=(const char*)sqlite3_column_text(st,1);
        if(ti&&ti[0]){char tid[4096];snprintf(tid,sizeof tid,"%s",ti);sqlite3_finalize(st);
            xexecf("UPDATE state SET mode=%d,cursor=0,scroll=0,dscroll=0,dcursor=0,focus=0",tm);
            if(tm==0){int tg=atoi(tid);xexecf(
                "WITH RECURSIVE a(p) AS(SELECT ppid FROM processes WHERE tgid=%d"
                " UNION ALL SELECT ppid FROM processes JOIN a ON tgid=a.p WHERE ppid IS NOT NULL"
                ")UPDATE expanded SET ex=1 WHERE id IN(SELECT CAST(p AS TEXT) FROM a)",tg);}
            rebuild_lpane();
            sqlite3_prepare_v2(db,"SELECT rownum FROM lpane WHERE id=?",-1,&st,0);
            sqlite3_bind_text(st,1,tid,-1,SQLITE_TRANSIENT);
            if(sqlite3_step(st)==SQLITE_ROW)xexecf("UPDATE state SET cursor=%d",sqlite3_column_int(st,0));
            sqlite3_finalize(st);rebuild_rpane();return;}}
    sqlite3_finalize(st);
}

/* ── Part 3: Terminal ──────────────────────────────────────────────── */
static struct termios orig_tios;static int tty_fd=-1,tty_raw=0;static volatile int g_resized=1;
static char*scr;static int scr_len,scr_cap;
static void sa(const char*s,int n){if(scr_len+n+1>scr_cap){scr_cap=(scr_len+n+1)*2;if(scr_cap<8192)scr_cap=8192;scr=realloc(scr,scr_cap);}memcpy(scr+scr_len,s,n);scr_len+=n;}
static void sp(const char*s){sa(s,strlen(s));}
static void sf(const char*fmt,...){char t[4096];va_list a;va_start(a,fmt);int n=vsnprintf(t,sizeof t,fmt,a);va_end(a);if(n>0)sa(t,n<(int)sizeof t?n:(int)sizeof t-1);}
static void sflush(void){if(scr_len>0&&tty_fd>=0)(void)write(tty_fd,scr,scr_len);scr_len=0;}
static void sputw(const char*s,int w){int p=0;while(*s&&p<w){sa(s,1);if((*s&0xC0)!=0x80)p++;s++;}while(p<w){sp(" ");p++;}}
static void tty_restore(void){if(tty_raw&&tty_fd>=0){tcsetattr(tty_fd,TCSAFLUSH,&orig_tios);(void)write(tty_fd,"\x1b[?25h\x1b[?1049l",14);tty_raw=0;}if(tty_fd>=0){close(tty_fd);tty_fd=-1;}}
static void tty_size(void){struct winsize ws;if(tty_fd>=0&&ioctl(tty_fd,TIOCGWINSZ,&ws)==0&&ws.ws_row>0)xexecf("UPDATE state SET rows=%d,cols=%d",ws.ws_row,ws.ws_col);}
static void tty_init(void){tty_fd=open("/dev/tty",O_RDWR);if(tty_fd<0)die("cannot open /dev/tty");
    tcgetattr(tty_fd,&orig_tios);atexit(tty_restore);struct termios r=orig_tios;
    r.c_iflag&=~(unsigned)(BRKINT|ICRNL|INPCK|ISTRIP|IXON);r.c_oflag&=~(unsigned)(OPOST);r.c_cflag|=CS8;
    r.c_lflag&=~(unsigned)(ECHO|ICANON|IEXTEN|ISIG);r.c_cc[VMIN]=0;r.c_cc[VTIME]=1;
    tcsetattr(tty_fd,TCSAFLUSH,&r);tty_raw=1;(void)write(tty_fd,"\x1b[?1049h\x1b[?25l",14);tty_size();}
static void on_winch(int s){(void)s;g_resized=1;}
enum{K_NONE=-1,K_UP=256,K_DOWN,K_LEFT,K_RIGHT,K_PGUP,K_PGDN,K_HOME,K_END,K_TAB=9,K_ENTER=13,K_ESC=27,K_BS=127};
static int readkey(void){char c;if(read(tty_fd,&c,1)<=0)return K_NONE;
    if(c=='\x1b'){char s[3];if(read(tty_fd,&s[0],1)!=1)return K_ESC;if(read(tty_fd,&s[1],1)!=1)return K_ESC;
        if(s[0]=='['){if(s[1]>='0'&&s[1]<='9'){if(read(tty_fd,&s[2],1)!=1)return K_ESC;
            if(s[2]=='~')switch(s[1]){case'1':case'7':return K_HOME;case'4':case'8':return K_END;case'5':return K_PGUP;case'6':return K_PGDN;}}
            else switch(s[1]){case'A':return K_UP;case'B':return K_DOWN;case'C':return K_RIGHT;case'D':return K_LEFT;case'H':return K_HOME;case'F':return K_END;}}
        else if(s[0]=='O')switch(s[1]){case'H':return K_HOME;case'F':return K_END;}return K_ESC;}
    return(unsigned char)c;}
static int line_edit(const char*prompt,char*buf,int bsz){
    int len=strlen(buf),pos=len,rows=qint("SELECT rows FROM state",24),cols=qint("SELECT cols FROM state",80);
    for(;;){scr_len=0;sf("\x1b[%d;1H\x1b[7m%s%s",rows,prompt,buf);
        for(int i=(int)strlen(prompt)+len;i<cols;i++)sp(" ");
        sf("\x1b[0m\x1b[%d;%dH\x1b[?25h",rows,(int)strlen(prompt)+pos+1);sflush();
        int k=readkey();if(k==K_NONE)continue;if(k==K_ENTER||k=='\n'){sp("\x1b[?25l");sflush();return 1;}
        if(k==K_ESC){sp("\x1b[?25l");sflush();return 0;}
        if((k==K_BS||k==8)&&pos>0){memmove(buf+pos-1,buf+pos,len-pos+1);pos--;len--;}
        else if(k>=32&&k<127&&len<bsz-1){memmove(buf+pos+1,buf+pos,len-pos+1);buf[pos++]=k;len++;}}}
static const char*S(const char*s){if(!s)return"\x1b[0m";
    switch(s[0]){case'c':return s[4]=='_'?"\x1b[36;1m":"\x1b[36m";case'e':return"\x1b[31m";case'g':return"\x1b[32m";
    case'h':return"\x1b[33;1m";case'n':return"\x1b[0m";case's':return"\x1b[1;35m";case'y':return"\x1b[33m";case'd':return"\x1b[2m";}return"\x1b[0m";}

static void render(void){
    int rows=qint("SELECT rows FROM state",24),cols=qint("SELECT cols FROM state",80);
    int uh=rows-1,focus=qint("SELECT focus FROM state",0);
    int tw=cols/2,dw=cols-tw;if(dw<20){tw=cols;dw=0;}
    int cursor=qint("SELECT cursor FROM state",0),sv=qint("SELECT scroll FROM state",0);
    if(cursor<sv)sv=cursor;if(cursor>=sv+uh)sv=cursor-uh+1;if(sv<0)sv=0;
    xexecf("UPDATE state SET scroll=%d",sv);
    scr_len=0;sp("\x1b[H");
    /* Left */
    {sqlite3_stmt*st;sqlite3_prepare_v2(db,"SELECT style,text FROM lpane WHERE rownum>=? AND rownum<? ORDER BY rownum",-1,&st,0);
    sqlite3_bind_int(st,1,sv);sqlite3_bind_int(st,2,sv+uh);int row=0;
    while(sqlite3_step(st)==SQLITE_ROW&&row<uh){int idx=sv+row;sf("\x1b[%d;1H",row+1);
        if(idx==cursor&&!focus)sp("\x1b[1;7m");else if(idx==cursor)sp("\x1b[7m");
        else sp(S((const char*)sqlite3_column_text(st,0)));
        sputw((const char*)sqlite3_column_text(st,1),tw);sp("\x1b[0m");row++;}
    while(row<uh){sf("\x1b[%d;1H\x1b[K",row+1);row++;}sqlite3_finalize(st);}
    /* Right */
    if(dw>0){int dc=qint("SELECT dcursor FROM state",0),ds=qint("SELECT dscroll FROM state",0);
        int nrp=qint("SELECT COUNT(*) FROM rpane",0);
        if(dc<ds)ds=dc;if(dc>=ds+uh-1)ds=dc-uh+2;{int mx=nrp>(uh-1)?nrp-(uh-1):0;if(ds>mx)ds=mx;}if(ds<0)ds=0;
        xexecf("UPDATE state SET dscroll=%d",ds);
        sf("\x1b[1;%dH",tw+1);sp(focus?"\x1b[1;45;37m":"\x1b[7m");
        {char h[256]="";int mode=qint("SELECT mode FROM state",0);
        sqlite3_stmt*st;sqlite3_prepare_v2(db,"SELECT id FROM lpane WHERE rownum=?",-1,&st,0);
        sqlite3_bind_int(st,1,cursor);if(sqlite3_step(st)==SQLITE_ROW){const char*id=(const char*)sqlite3_column_text(st,0);
            if(id){if(mode==0)snprintf(h,sizeof h," PID %s ",id);else snprintf(h,sizeof h," %.60s ",id);}}
        sqlite3_finalize(st);sputw(h,dw);}sp("\x1b[0m");
        sqlite3_stmt*st;sqlite3_prepare_v2(db,"SELECT rownum,style,text,link_mode FROM rpane WHERE rownum>=? AND rownum<? ORDER BY rownum",-1,&st,0);
        sqlite3_bind_int(st,1,ds);sqlite3_bind_int(st,2,ds+uh-1);int row=0;
        while(sqlite3_step(st)==SQLITE_ROW&&row<uh-1){int rn=sqlite3_column_int(st,0);
            sf("\x1b[%d;%dH",row+2,tw+1);int idc=(rn==dc&&focus);
            int hl=(sqlite3_column_type(st,3)!=SQLITE_NULL&&sqlite3_column_int(st,3)>=0);
            if(idc)sp("\x1b[7m");else sp(S((const char*)sqlite3_column_text(st,1)));
            if(idc&&hl)sp("\x1b[4m");sp(" ");sputw((const char*)sqlite3_column_text(st,2),dw-2);sp(" \x1b[0m");row++;}
        while(row<uh-1){sf("\x1b[%d;%dH\x1b[0m\x1b[K",row+2,tw+1);row++;}sqlite3_finalize(st);}
    /* Status */
    {int mode=qint("SELECT mode FROM state",0),nf=qint("SELECT COUNT(*) FROM lpane",0);
    const char*mn[]={"PROCS","FILES","OUTPUT"};const char*tsl[]={"abs","rel","Δ"};
    int tsm=qint("SELECT ts_mode FROM state",0),gr=qint("SELECT grouped FROM state",1);
    int lpf=qint("SELECT lp_filter FROM state",0);
    char s[512];int p=0;p+=snprintf(s+p,sizeof s-p," %s%s | %d/%d",mn[mode],gr?" tree":"",cursor+1,nf);
    p+=snprintf(s+p,sizeof s-p," | TS:%s",tsl[tsm]);
    if(g_trace_fd>=0)p+=snprintf(s+p,sizeof s-p," | LIVE");
    {sqlite3_stmt*st;sqlite3_prepare_v2(db,"SELECT evfilt,search FROM state",-1,&st,0);
     if(sqlite3_step(st)==SQLITE_ROW){const char*ef=(const char*)sqlite3_column_text(st,0);
         const char*sq=(const char*)sqlite3_column_text(st,1);
         if(ef&&ef[0])p+=snprintf(s+p,sizeof s-p," | F:%s",ef);
         if(sq&&sq[0])p+=snprintf(s+p,sizeof s-p," | /%s[%d]",sq,qint("SELECT COUNT(*) FROM search_hits",0));}
     sqlite3_finalize(st);}
    if(lpf==1)p+=snprintf(s+p,sizeof s-p," | V:failed");
    else if(lpf==2)p+=snprintf(s+p,sizeof s-p," | V:running");
    p+=snprintf(s+p,sizeof s-p," | 1:proc 2:file 3:out G:group v:filter W:save ?:help");(void)p;
    sf("\x1b[%d;1H\x1b[7;1m",rows);sputw(s,cols);sp("\x1b[0m");}sflush();}

/* ── Help & SQL ────────────────────────────────────────────────────── */
static const char*HELP[]={"","  Process Trace Viewer","  ════════════════════","",
    "  ↑↓ jk  Navigate    PgUp/PgDn  Page    g  First    Tab  Switch pane",
    "  ← h  Collapse/back    → l  Expand/detail    Enter  Follow link","",
    "  1 Process  2 File  3 Output    G  Toggle tree/flat    s  Sort    t  Timestamps",
    "  /  Search    n/N  Next/prev    f/F  Filter events/clear    e/E  Expand/collapse all",
    "  v  Cycle proc filter (none→failed→running)    V  Clear proc filter",
    "  W  Save DB to file    x  SQL query    q  Quit    ?  Help","","  Press any key.",0};
static void show_help(void){scr_len=0;sp("\x1b[H\x1b[2J");
    for(int i=0;HELP[i];i++)sf("\x1b[%d;1H\x1b[36m%s\x1b[0m",i+1,HELP[i]);sflush();while(readkey()==K_NONE);}
static void run_sql(void){char sql[1024]="";if(!line_edit("SQL> ",sql,sizeof sql)||!sql[0])return;
    scr_len=0;sp("\x1b[H\x1b[2J");sf("\x1b[1;1H\x1b[33;1mSQL: %s\x1b[0m",sql);sqlite3_stmt*st;
    if(sqlite3_prepare_v2(db,sql,-1,&st,0)!=SQLITE_OK){sf("\x1b[3;1H\x1b[31m%s\x1b[0m",sqlite3_errmsg(db));sflush();while(readkey()==K_NONE);return;}
    int nc=sqlite3_column_count(st),row=3,rows=qint("SELECT rows FROM state",24);
    sf("\x1b[%d;1H\x1b[36;1m",row++);for(int c=0;c<nc&&c<10;c++)sf("%-20s",sqlite3_column_name(st,c));
    sp("\x1b[0m");sf("\x1b[%d;1H",row++);for(int c=0;c<nc&&c<10;c++)sp("──────────────────── ");
    int nr=0;while(sqlite3_step(st)==SQLITE_ROW&&row<rows-2){sf("\x1b[%d;1H",row++);
        for(int c=0;c<nc&&c<10;c++){const char*v=(const char*)sqlite3_column_text(st,c);
            char t[21];snprintf(t,sizeof t,"%.20s",v?v:"NULL");sf("%-20s",t);}nr++;}
    sqlite3_finalize(st);sf("\x1b[%d;1H\x1b[2m%d rows.\x1b[0m",row+1,nr);sflush();while(readkey()==K_NONE);}

/* ── Save DB ───────────────────────────────────────────────────────── */
static void save_db(void){
    char fname[256]="trace.db";
    if(!line_edit("Save to: ",fname,sizeof fname)||!fname[0])return;
    sqlite3*dst;
    if(sqlite3_open(fname,&dst)!=SQLITE_OK)return;
    sqlite3_backup*bk=sqlite3_backup_init(dst,"main",db,"main");
    if(bk){sqlite3_backup_step(bk,-1);sqlite3_backup_finish(bk);}
    sqlite3_close(dst);}

/* ── Save DB (headless helper, used by TV_SAVE_PATH) ────────────────── */
static void save_db_to(const char *path){
    sqlite3*dst;
    if(sqlite3_open(path,&dst)!=SQLITE_OK){fprintf(stderr,"tv: cannot open %s for save\n",path);return;}
    sqlite3_backup*bk=sqlite3_backup_init(dst,"main",db,"main");
    if(bk){sqlite3_backup_step(bk,-1);sqlite3_backup_finish(bk);}
    sqlite3_close(dst);}

/* ── Key dispatch ──────────────────────────────────────────────────── */
static void handle_key(int k){
    int focus=qint("SELECT focus FROM state",0),nf=qint("SELECT COUNT(*) FROM lpane",0);
    int nrp=qint("SELECT COUNT(*) FROM rpane",0),rows=qint("SELECT rows FROM state",24),pg=rows-3;
    int mode=qint("SELECT mode FROM state",0);
    switch(k){
    case K_UP:case'k':if(!focus){xexec("UPDATE state SET cursor=MAX(cursor-1,0),dscroll=0,dcursor=0");rebuild_rpane();}
        else xexec("UPDATE state SET dcursor=MAX(dcursor-1,0)");break;
    case K_DOWN:case'j':if(!focus){xexecf("UPDATE state SET cursor=MIN(cursor+1,%d),dscroll=0,dcursor=0",nf-1);rebuild_rpane();}
        else xexecf("UPDATE state SET dcursor=MIN(dcursor+1,%d)",nrp-1);break;
    case K_PGUP:if(!focus){xexecf("UPDATE state SET cursor=MAX(cursor-%d,0),dscroll=0,dcursor=0",pg);rebuild_rpane();}
        else xexecf("UPDATE state SET dcursor=MAX(dcursor-%d,0)",pg);break;
    case K_PGDN:if(!focus){xexecf("UPDATE state SET cursor=MIN(cursor+%d,%d),dscroll=0,dcursor=0",pg,nf-1);rebuild_rpane();}
        else xexecf("UPDATE state SET dcursor=MIN(dcursor+%d,%d)",pg,nrp-1);break;
    case K_HOME:case'g':if(!focus){xexec("UPDATE state SET cursor=0,dscroll=0,dcursor=0");rebuild_rpane();}
        else xexec("UPDATE state SET dcursor=0");break;
    case K_END:if(!focus){xexecf("UPDATE state SET cursor=%d,dscroll=0,dcursor=0",nf>0?nf-1:0);rebuild_rpane();}
        else xexecf("UPDATE state SET dcursor=%d",nrp>0?nrp-1:0);break;
    case'G':xexec("UPDATE state SET grouped=1-grouped,cursor=0,scroll=0,dscroll=0,dcursor=0");rebuild_lpane();rebuild_rpane();break;
    case K_RIGHT:case'l':
        if(focus){follow_link();break;}
        {char id[256]="";sqlite3_stmt*st;sqlite3_prepare_v2(db,"SELECT id FROM lpane WHERE rownum=(SELECT cursor FROM state)",-1,&st,0);
         if(sqlite3_step(st)==SQLITE_ROW){const char*t=(const char*)sqlite3_column_text(st,0);if(t)snprintf(id,sizeof id,"%s",t);}sqlite3_finalize(st);
         /* Try expand (process tree or output groups) */
         if((mode==0||mode==2)&&id[0]){
             int is_ex=qint(sqlite3_mprintf("SELECT COALESCE((SELECT ex FROM expanded WHERE id='%s'),1)",id),1);
             int has_ch=0;
             if(mode==0)has_ch=qint(sqlite3_mprintf("SELECT COUNT(*)>0 FROM processes WHERE ppid=%d",atoi(id)),0);
             else if(!strncmp(id,"io_",3))has_ch=1;
             if(has_ch&&!is_ex){xexecf("UPDATE expanded SET ex=1 WHERE id='%s'",id);rebuild_lpane();rebuild_rpane();break;}}
         xexec("UPDATE state SET focus=1,dcursor=0,dscroll=0");}break;
    case K_ENTER:case'\n':if(focus)follow_link();else xexec("UPDATE state SET focus=1,dcursor=0,dscroll=0");break;
    case K_LEFT:case'h':
        if(focus){xexec("UPDATE state SET focus=0");break;}
        {char id[256]="";sqlite3_stmt*st;sqlite3_prepare_v2(db,"SELECT id FROM lpane WHERE rownum=(SELECT cursor FROM state)",-1,&st,0);
         if(sqlite3_step(st)==SQLITE_ROW){const char*t=(const char*)sqlite3_column_text(st,0);if(t)snprintf(id,sizeof id,"%s",t);}sqlite3_finalize(st);
         if(mode==0&&id[0]){int tgid=atoi(id);
             int has_ch=qint(sqlite3_mprintf("SELECT COUNT(*)>0 FROM processes WHERE ppid=%d",tgid),0);
             int is_ex=qint(sqlite3_mprintf("SELECT COALESCE((SELECT ex FROM expanded WHERE id='%s'),1)",id),1);
             if(has_ch&&is_ex){xexecf("UPDATE expanded SET ex=0 WHERE id='%s'",id);rebuild_lpane();rebuild_rpane();break;}
             int ppid=qint(sqlite3_mprintf("SELECT ppid FROM processes WHERE tgid=%d",tgid),-1);
             if(ppid>=0){int r=qint(sqlite3_mprintf("SELECT rownum FROM lpane WHERE id='%d'",ppid),-1);
                 if(r>=0){xexecf("UPDATE state SET cursor=%d,dscroll=0,dcursor=0",r);rebuild_rpane();}}}
         else if(mode==2&&id[0]){
             if(!strncmp(id,"io_",3)){xexecf("UPDATE expanded SET ex=0 WHERE id='%s'",id);rebuild_lpane();rebuild_rpane();}
             else{sqlite3_stmt*s2;sqlite3_prepare_v2(db,"SELECT parent_id FROM lpane WHERE rownum=(SELECT cursor FROM state)",-1,&s2,0);
                 if(sqlite3_step(s2)==SQLITE_ROW){const char*pi=(const char*)sqlite3_column_text(s2,0);
                     if(pi){int r=qint(sqlite3_mprintf("SELECT rownum FROM lpane WHERE id='%s'",pi),-1);
                         if(r>=0){xexecf("UPDATE state SET cursor=%d,dscroll=0,dcursor=0",r);rebuild_rpane();}}}
                 sqlite3_finalize(s2);}}}break;
    case K_TAB:xexec("UPDATE state SET focus=1-focus,dcursor=0,dscroll=0");break;
    case'e':case'E':if(mode==0){char id[64]="";sqlite3_stmt*st;
        sqlite3_prepare_v2(db,"SELECT id FROM lpane WHERE rownum=(SELECT cursor FROM state)",-1,&st,0);
        if(sqlite3_step(st)==SQLITE_ROW){const char*t=(const char*)sqlite3_column_text(st,0);if(t)snprintf(id,sizeof id,"%s",t);}sqlite3_finalize(st);
        int tg=atoi(id);xexecf("WITH RECURSIVE d(t) AS(SELECT %d UNION ALL SELECT c.tgid FROM processes c JOIN d ON c.ppid=d.t)"
            " UPDATE expanded SET ex=%d WHERE id IN(SELECT CAST(t AS TEXT) FROM d)",tg,k=='e'?1:0);
        rebuild_lpane();rebuild_rpane();}break;
    case'1':xexec("UPDATE state SET mode=0,cursor=0,scroll=0,dscroll=0,dcursor=0,focus=0,sort_key=0");rebuild_lpane();rebuild_rpane();break;
    case'2':xexec("UPDATE state SET mode=1,cursor=0,scroll=0,dscroll=0,dcursor=0,focus=0,sort_key=0");rebuild_lpane();rebuild_rpane();break;
    case'3':xexec("UPDATE state SET mode=2,cursor=0,scroll=0,dscroll=0,dcursor=0,focus=0,sort_key=0");rebuild_lpane();rebuild_rpane();break;
    case's':xexec("UPDATE state SET sort_key=(sort_key+1)%3,cursor=0,scroll=0");rebuild_lpane();rebuild_rpane();break;
    case't':xexec("UPDATE state SET ts_mode=(ts_mode+1)%3");rebuild_rpane();break;
    case'/':{char buf[256]="";if(line_edit("/",buf,sizeof buf)&&buf[0]){
        sqlite3_stmt*st;sqlite3_prepare_v2(db,"UPDATE state SET search=?",-1,&st,0);
        sqlite3_bind_text(st,1,buf,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);
        do_search(buf);rebuild_lpane();jump_hit(1);}}break;
    case'n':jump_hit(1);break;case'N':jump_hit(-1);break;
    case'f':{char buf[32]="";if(line_edit("Filter: ",buf,sizeof buf)&&buf[0]){
        for(char*p=buf;*p;p++)*p=toupper(*p);sqlite3_stmt*st;
        sqlite3_prepare_v2(db,"UPDATE state SET evfilt=?",-1,&st,0);
        sqlite3_bind_text(st,1,buf,-1,SQLITE_TRANSIENT);sqlite3_step(st);sqlite3_finalize(st);
        rebuild_rpane();}}break;
    case'F':xexec("UPDATE state SET evfilt=''");rebuild_rpane();break;
    case'v':xexecf("UPDATE state SET lp_filter=(lp_filter+1)%%3,cursor=0,scroll=0");rebuild_lpane();rebuild_rpane();break;
    case'V':xexec("UPDATE state SET lp_filter=0,cursor=0,scroll=0");rebuild_lpane();rebuild_rpane();break;
    case'W':save_db();break;
    case'x':run_sql();break;case'?':show_help();break;}}

/* ═══════════════════════════════════════════════════════════════════ */
int main(int argc,char**argv){
    int load_mode=0; char load_file[256]=""; char**cmd=NULL;
    for(int i=1;i<argc;i++){
        if(strcmp(argv[i],"--load")==0&&i+1<argc){load_mode=1;snprintf(load_file,sizeof load_file,"%s",argv[++i]);}
        else if(strcmp(argv[i],"--")==0&&i+1<argc){cmd=argv+i+1;break;}}
    if(!load_mode&&!cmd){
        fprintf(stderr,
            "Usage: tv -- <command> [args...]\n"
            "       tv --load <file.db>\n"
            "Env:   TV_TRACE_PATH  override default /proc/proctrace/new path\n"
            "       TV_SAVE_PATH   auto-save DB on trace EOF and exit (for testing)\n");
        return 1;}

    if(sqlite3_open(":memory:",&db)!=SQLITE_OK)die("sqlite3_open");

    if(load_mode){
        /* Restore saved database into memory */
        sqlite3*src;
        if(sqlite3_open(load_file,&src)!=SQLITE_OK)die("cannot open file");
        sqlite3_backup*bk=sqlite3_backup_init(db,"main",src,"main");
        if(!bk)die("backup init failed");
        sqlite3_backup_step(bk,-1);sqlite3_backup_finish(bk);sqlite3_close(src);
        /* Ensure new columns/tables exist for older saves */
        {char*e=0;sqlite3_exec(db,"ALTER TABLE state ADD COLUMN lp_filter INT DEFAULT 0",0,0,&e);if(e)sqlite3_free(e);}
        setup_app(); /* idempotent: IF NOT EXISTS throughout */
        if(!qint("SELECT has_fts FROM state",0)) setup_fts();
    } else {
        /* Live tracing mode */
        db_create();
        setup_app();
        g_own_tgid=(int)getpid();
        /* TV_TRACE_PATH overrides the default kernel proc interface path */
        const char*tpath=getenv("TV_TRACE_PATH");
        if(!tpath)tpath="/proc/proctrace/new";
        g_trace_fd=open(tpath,O_RDONLY);
        if(g_trace_fd<0){fprintf(stderr,"tv: cannot open %s — is the module loaded?\n",tpath);exit(1);}
        g_child_pid=fork();
        if(g_child_pid<0){close(g_trace_fd);die("fork");}
        if(g_child_pid==0){execvp(cmd[0],cmd);perror(cmd[0]);_exit(127);}
        xexec("UPDATE state SET lp_filter=2"); /* show running processes while tracing */
        /* TV_SAVE_PATH: headless mode — skip TUI, auto-save after trace EOF */
        if(getenv("TV_SAVE_PATH"))g_headless=1;
    }

    rebuild_lpane();rebuild_rpane();
    if(!g_headless){
        tty_init();
        struct sigaction sa2={0};sa2.sa_handler=on_winch;sigaction(SIGWINCH,&sa2,0);
    }

    for(;;){
        if(g_resized&&!g_headless){g_resized=0;tty_size();rebuild_lpane();rebuild_rpane();}

        if(g_trace_fd>=0){
            /* Streaming: multiplex tty and trace fd */
            fd_set rfds;FD_ZERO(&rfds);
            if(tty_fd>=0)FD_SET(tty_fd,&rfds);
            FD_SET(g_trace_fd,&rfds);
            int mfd=g_trace_fd;if(tty_fd>mfd)mfd=tty_fd;
            struct timeval to={0,50000}; /* 50 ms */
            int sel=select(mfd+1,&rfds,NULL,NULL,&to);
            if(sel<0&&errno==EINTR){if(!g_headless)render();continue;}

            if(sel>0&&FD_ISSET(g_trace_fd,&rfds)){
                int n=read(g_trace_fd,g_rbuf+g_rbuf_len,
                           (int)(sizeof(g_rbuf)-g_rbuf_len-1));
                if(n<=0){
                    /* EOF: drain partial line, finalise */
                    if(g_rbuf_len>0){
                        g_rbuf[g_rbuf_len]=0;
                        xexec("BEGIN");process_line(g_rbuf);xexec("COMMIT");
                        g_rbuf_len=0;}
                    setup_fts();
                    xexec("UPDATE state SET lp_filter=0");
                    close(g_trace_fd);g_trace_fd=-1;
                    rebuild_lpane();rebuild_rpane();
                    /* TV_SAVE_PATH: auto-save and exit without starting the TUI */
                    if(g_headless){
                        const char*sp=getenv("TV_SAVE_PATH");
                        if(sp&&sp[0])save_db_to(sp);
                        goto done;}
                } else {
                    g_rbuf_len+=n;
                    int did=0;xexec("BEGIN");
                    while(1){
                        char*nl=(char*)memchr(g_rbuf,'\n',g_rbuf_len);if(!nl)break;
                        /* strip CR if present */
                        if(nl>g_rbuf&&*(nl-1)=='\r')*(nl-1)=0;
                        *nl=0;process_line(g_rbuf);did++;
                        int used=(int)(nl-g_rbuf)+1;
                        memmove(g_rbuf,nl+1,g_rbuf_len-used);
                        g_rbuf_len-=used;}
                    /* safety: flush if buffer nearly full */
                    if(g_rbuf_len>=(int)(sizeof(g_rbuf)-1)){
                        g_rbuf[g_rbuf_len]=0;process_line(g_rbuf);did++;g_rbuf_len=0;}
                    xexec("COMMIT");
                    if(did){
                        /* initialise base_ts on first data */
                        xexec("UPDATE state SET base_ts=(SELECT COALESCE(MIN(ts),0) FROM events) WHERE base_ts=0");
                        rebuild_lpane();rebuild_rpane();}}}

            /* Reap child without blocking */
            if(g_child_pid>0){
                int ws;if(waitpid(g_child_pid,&ws,WNOHANG)==g_child_pid)g_child_pid=0;}

            if(!g_headless)render();

            if(sel>0&&tty_fd>=0&&FD_ISSET(tty_fd,&rfds)){
                int k=readkey();
                if(k==K_NONE){}
                else if(k=='q'||k=='Q')break;
                else{handle_key(k);render();}}
        } else {
            /* Non-streaming: classic event loop */
            render();
            int k=readkey();
            if(k==K_NONE)continue;
            if(k=='q'||k=='Q')break;
            handle_key(k);
        }
    }

done:
    if(!g_headless)tty_restore();
    if(g_trace_fd>=0){close(g_trace_fd);g_trace_fd=-1;}
    if(g_child_pid>0){kill(g_child_pid,SIGTERM);waitpid(g_child_pid,NULL,0);}
    sqlite3_close(db);
    return 0;}
