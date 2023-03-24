#!/usr/bin/env python3
import sqlite3
import sys
import re
import optparse
import os
from pprint import pprint

DIE_reo = re.compile(r'^ ?<\d+><(\d|[a-f])+>: Abbrev Number: \d+.*$')
DIE_tag_reo = re.compile(r'.*<(\d+)><([0-9a-f]+)>: Abbrev Number: \d+ \((\w+)\).*')
ATTR_reo = re.compile(r'^ *<[0-9a-f]+> +(DW_AT_\w+) *: (.*)$')
abstract_reo = re.compile('<0x([0-9a-f]+)>')

call_site_tags = ('DW_TAG_GNU_call_site',
                  'DW_TAG_call_site',
                  'DW_TAG_inlined_subroutine')
origin_tags = ('DW_AT_abstract_origin', 'DW_AT_call_origin')
subprogram_tags = ('DW_TAG_subprogram', 'DW_TAG_inlined_subroutine')

def is_DIE(line):
    if DIE_reo.match(line):
        tag_mo = DIE_tag_reo.match(line)
        if tag_mo:
            return int(tag_mo.group(1)), tag_mo.group(2), tag_mo.group(3)
        return 0, '0', '0'
    return None

def parse_attr(line):
    mo = ATTR_reo.match(line)
    if mo:
        return mo.group(1), mo.group(2)
    pass

def get_name(value):
    return value.split(':')[-1].strip()

def get_abstract_origin(value):
    mo = abstract_reo.match(value)
    if mo:
        return mo.group(1)
    pass

def find_enclosing_caller(stk):
    for i in range(len(stk)-2, -1, -1):
        if stk[i][0] in subprogram_tags:
            return stk[i][1]    # address
    return None

def init_schema(conn):
    conn.execute('create table symbols(id integer primary key asc, name text unique)')
    conn.execute('create table calls(caller integer, callee integer)')
    pass

def insert_symbols(conn, symbols):
    for symbol in symbols:
        try:
            conn.execute('insert into symbols (name) values(?)',
                         (symbol,))
        except sqlite3.IntegrityError:
            #print('symbol %s already exists' % symbol)
            pass
        pass
    pass

def insert_calls(conn, calls):
    for caller, callee in calls:
        conn.execute('insert into calls values(?, ?)',
                     (caller, callee))
        pass
    pass

def get_symbol_id(conn, symbol):
    cur = conn.execute('select id from symbols where name = ?',
                       (symbol,))
    row = cur.fetchone()
    return row[0]

def is_original(subprogram):
    return 'origin' not in subprogram

def persist_subprogram_info(subprograms, filename):
    conn = sqlite3.connect(filename)
    init_schema(conn)

    subprograms = [subprogram for subprogram in subprograms.values()
                   if is_original(subprogram)]

    symbols = [subprogram['name']
               for subprogram in subprograms]
    insert_symbols(conn, symbols)

    conn.commit()

    for subp in subprograms:
        caller = get_symbol_id(conn, subp['name'])
        calls = [(caller, get_symbol_id(conn, callee))
                 for callee in subp['call_names']]
        insert_calls(conn, calls)
        pass

    conn.commit()
    conn.close()
    pass

def parse_DIEs(lines):
    subprograms = {}
    stk = []

    def get_real_addr(addr):
        while addr in subprograms:
            if not is_original(subprograms[addr]):
                addr = subprograms[addr]['origin']
                continue
            break
        return addr

    def get_name_addr(addr):
        while addr in subprograms:
            subp = subprograms[addr]
            if not is_original(subp):
                addr = subp['origin']
                continue
            return subp['name']
        print('no name for addr: %s' % addr)
        raise '<unknown>'

    def tip_tag():
        if len(stk) > 0:
            return stk[-1][0]
        return None

    def tip_addr():
        if len(stk) > 0:
            return stk[-1][1]
        return None

    def original_subprograms():
        return [subp for subp in subprograms.values()
                if is_original(subp)]

    for line in lines:
        dep_addr_die = is_DIE(line)
        if dep_addr_die:
            dep, addr, die = dep_addr_die
            if die == '0':
                stk.pop()
                continue
            stk = stk[:dep]
            stk.append((die, addr))
            if die in subprogram_tags:
                subprograms[addr] = {'name': '<unknown>', 'call': []}
                pass
            pass
        elif tip_tag() == 'DW_TAG_subprogram':
            attr_value = parse_attr(line)
            if attr_value:
                attr, value = attr_value
                if attr == 'DW_AT_name':
                    tag, addr = stk[-1]
                    name = get_name(value)
                    subprograms[addr]['name'] = name
                    #print(' ' * len(stk), attr, get_name(value))
                elif attr == 'DW_AT_abstract_origin':
                    tag, addr = stk[-1]
                    abstract_origin = get_abstract_origin(value)
                    subprograms[addr]['origin'] = abstract_origin
                    pass
                pass
            pass
        elif tip_tag() in call_site_tags:
            attr_value = parse_attr(line)
            if attr_value:
                attr, value = attr_value
                if attr in origin_tags:
                    abstract_origin = get_abstract_origin(value)
                    if abstract_origin:
                        if stk[-1][0] == 'DW_TAG_inlined_subroutine':
                            tag, addr = stk[-1]
                            subprograms[addr]['origin'] = abstract_origin
                            pass
                        enclosing_caller = find_enclosing_caller(stk)
                        if not enclosing_caller:
                            print('no enclosing caller')
                            pprint(stk)
                            raise 'no enclosing caller'
                        subprograms[enclosing_caller]['call'].append(abstract_origin)
                        #print(' ' * (len(stk) + 1), subprograms[addr]['name'], 'call', abstract_origin)
                        pass
                    pass
                pass
            pass
        pass
    pass
    for subp in subprograms.values():
        if not is_original(subp):
            subprograms[get_real_addr(subp['origin'])]['call'] += subp['call']
            pass
        pass
    for subp in original_subprograms():
        subp['call_names'] = [get_name_addr(addr)
                              for addr in set(subp['call'])]
        pass
    return subprograms

def main():
    optparser = optparse.OptionParser()
    optparser.add_option('-o', '--output', dest='output', default='callgraph.sqlite3',
                         help='output file name')
    opts, args = optparser.parse_args()

    filename = args[0]
    output = opts.output

    print('parsing DIEs from %s' % filename)
    lines = open(filename)
    subprograms = parse_DIEs(lines)

    # Check if the file exists. If yes, delete it.
    if os.path.exists(output):
        print('output file %s already exists, delete it' % output)
        os.remove(output)
        pass

    print('persisting to %s...' % output)
    persist_subprogram_info(subprograms, opts.output)
    pass

if __name__ == '__main__':
    main()
    pass
