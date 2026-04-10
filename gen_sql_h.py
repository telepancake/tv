#!/usr/bin/env python3
"""Generate tv_sql.h from tv.sql — embeds SQL as C string constants.

Sections in tv.sql are delimited by lines matching  --%% <NAME>
Output variables: tv_sql_schema, tv_sql_setup, tv_sql_fts
"""
import sys

def main():
    src = sys.argv[1] if len(sys.argv) > 1 else 'tv.sql'
    dst = sys.argv[2] if len(sys.argv) > 2 else 'tv_sql.h'

    with open(src) as f:
        content = f.read()

    sections, cur_name, cur_lines = [], 'SCHEMA', []
    for line in content.split('\n'):
        if line.startswith('--%% '):
            sections.append((cur_name, cur_lines))
            cur_name = line[5:].strip()
            cur_lines = []
            continue
        if line.startswith('--') or not line.strip():
            continue
        cur_lines.append(line)
    sections.append((cur_name, cur_lines))

    nm = {'SCHEMA': 'tv_sql_schema', 'SETUP': 'tv_sql_setup', 'FTS': 'tv_sql_fts'}

    with open(dst, 'w') as o:
        o.write('/* Auto-generated from %s -- do not edit */\n\n' % src)
        for name, lines in sections:
            var = nm.get(name, 'tv_sql_' + name.lower())
            o.write('static const char %s[] =\n' % var)
            for l in lines:
                escaped = l.replace('\\', '\\\\').replace('"', '\\"')
                o.write('    "%s\\n"\n' % escaped)
            o.write('    "";\n\n')

if __name__ == '__main__':
    main()
