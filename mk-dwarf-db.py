#!/usr/bin/env python3
import sqlite3
import sys
import re
import optparse
import os
import time
import itertools
import hashlib
from pprint import pprint

DIE_reo = re.compile(r'^ ?<\d+><(\d|[a-f])+>: Abbrev Number: \d+.*$')
DIE_tag_reo = re.compile(r'.*<(\d+)><([0-9a-f]+)>: Abbrev Number: \d+ \((\w+)\).*')
ATTR_reo = re.compile(r'^ *<[0-9a-f]+> +(DW_AT_\w+) *: (.*)$')
abstract_reo = re.compile('<0x([0-9a-f]+)>')
addr_reo = re.compile('<0x([0-9a-f]+)>')

call_site_tags = ('DW_TAG_GNU_call_site',
                  'DW_TAG_call_site',
                  'DW_TAG_inlined_subroutine')
origin_tags = ('DW_AT_abstract_origin', 'DW_AT_call_origin')
subprogram_tags = ('DW_TAG_subprogram', 'DW_TAG_inlined_subroutine')
type_tags = ('DW_TAG_array_type',
             'DW_TAG_base_type',
             'DW_TAG_const_type',
             'DW_TAG_enumeration_type',
             'DW_TAG_pointer_type',
             'DW_TAG_ptr_to_member_type',
             'DW_TAG_reference_type',
             'DW_TAG_restrict_type',
             'DW_TAG_rvalue_reference_type',
             'DW_TAG_structure_type',
             'DW_TAG_class_type',
             'DW_TAG_subroutine_type',
             'DW_TAG_typedef',
             'DW_TAG_union_type',
             'DW_TAG_volatile_type',
             'DW_TAG_unspecified_type')
ptr_tags = ('DW_TAG_pointer_type',
            'DW_TAG_ptr_to_member_type',
            'DW_TAG_reference_type',
            'DW_TAG_rvalue_reference_type')

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

def parse_abstract_origin(value):
    mo = abstract_reo.match(value)
    if mo:
        return mo.group(1)
    pass

def parse_addr_value(value):
    mo = addr_reo.match(value)
    if mo:
        return mo.group(1)
    pass

def find_enclosing_caller(stk):
    for i in range(len(stk)-2, -1, -1):
        if 'call' in stk[i]:
            return stk[i]       # address
    return None

def find_enclosing_type(stk):
    for i in range(len(stk)-2, -1, -1):
        if 'meta_type' in stk[i] and stk[i]['meta_type'] in type_tags:
            return stk[i]
    return None

def init_schema(conn):
    conn.execute('create table symbols(id integer primary key asc, name text unique)')
    conn.execute('create table calls(caller integer, callee integer)')

    conn.execute('create table types(id integer primary key asc, name text, addr text unique, meta_type text, declaration integer)')
    conn.execute('create table members(type_id integer, name text, type integer, offset integer)')
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
    if not row:
        print(symbol)
        pass
    return row[0]

def is_original(subprogram):
    return 'origin' not in subprogram

def get_symbol_name(symbol):
    if 'linkage_name' in symbol:
        return symbol['linkage_name']
    return symbol['name']

def persist_subprogram_info(conn, subprograms):
    subprograms = [subprogram for subprogram in subprograms.values()
                   if is_original(subprogram)]

    symbols = [get_symbol_name(subprogram)
               for subprogram in subprograms]
    insert_symbols(conn, symbols)

    conn.commit()

    for subp in subprograms:
        caller = get_symbol_id(conn, get_symbol_name(subp))
        calls = [(caller, get_symbol_id(conn, callee))
                 for callee in subp['call_names']]
        insert_calls(conn, calls)
        pass

    conn.commit()
    pass

def get_real_type(addr, types):
    if addr.startswith('placeholder:'):
        return types[types[addr]['real_type']]
    return types[addr]

def persist_types_info(conn, types):
    for addr, type_info in types.items():
        if type_info['meta_type'] == 'placeholder':
            continue
        name = get_symbol_name(type_info)
        meta_type = type_info['meta_type']
        declaration = 1 if 'declaration' in type_info else 0
        conn.execute('insert into types(name, addr, meta_type, declaration) values(?, ?, ?, ?)',
                     (name, addr, meta_type, declaration))
        cur = conn.execute('select id from types where addr = ?',
                           (addr,))
        row = cur.fetchone()
        type_id = row[0]
        type_info['id'] = type_id
        pass

    for type_info in types.values():
        if type_info['meta_type'] == 'placeholder':
            continue
        type_id = type_info['id']
        if 'members' in type_info:
            for member in type_info['members']:
                conn.execute('insert into members values(?, ?, ?, ?)',
                             (type_id, get_symbol_name(member),
                              get_real_type(member['type'], types)['id'],
                              member['location'] or 0))
                pass
            pass
        elif 'type' in type_info:
            if type_info['type'] not in types:
                print('unknown type %s' % type_info['type'])
                print(type_info)
                pass
            type_type = get_real_type(type_info['type'], types)
            if 'id' not in type_type:
                print(type_info['type'], types[type_info['type']], type_type)
                pass
            conn.execute('insert into members values(?, ?, ?, ?)',
                         (type_id, '',
                          type_type['id'],
                          0))
            pass
        elif 'params' in type_info:
            for i, param in enumerate(type_info['params']):
                conn.execute('insert into members values(?, ?, ?, ?)',
                             (type_id, str(i),
                              get_real_type(param, types)['id'],
                              0))
                pass
            pass
        pass
    conn.commit()
    pass

def persist_info(subprograms, types, filename):
    conn = sqlite3.connect(filename)

    init_schema(conn)
    persist_subprogram_info(conn, subprograms)
    persist_types_info(conn, types)

    conn.close()
    pass

def parse_DIEs(lines):
    subprograms = {}
    subprograms_lst = []
    types = {'void': {'name': 'void',
                      'meta_type': 'DW_TAG_base_type',
                      'addr': 'void'}}
    types_lst = []
    stk = []
    meta_flyweight = {}
    name_flyweight = {}

    def fly_name(name):
        h = hash(name) & 0xff
        bucket = name_flyweight.setdefault(h, {})
        return bucket.setdefault(name, name)

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
            return get_symbol_name(subp)
        print('no name for addr: %s' % addr)
        raise '<unknown>'

    def tip_tag():
        if len(stk) > 0 and 'meta_type' in stk[-1]:
            return stk[-1]['meta_type']
        return None

    for line in lines:
        dep_addr_die = is_DIE(line)
        if dep_addr_die:
            dep, addr, die = dep_addr_die
            if die == '0':
                stk.pop()
                continue
            stk = stk[:dep]
            if die in subprogram_tags:
                subp = {'name': '<unknown>',
                        'call': [],
                        'addr': addr,
                        'meta_type': meta_flyweight.setdefault(die, die)}
                subprograms_lst.append(subp)
                stk.append(subp)
            elif die in type_tags:
                _type = {'name': '<unknown>',
                         'meta_type': meta_flyweight.setdefault(die, die),
                         'addr': addr}
                if die in ('DW_TAG_structure_type', 'DW_TAG_union_type', 'DW_TAG_class_type'):
                    _type['members'] = []
                elif die in ('DW_TAG_pointer_type', 'DW_TAG_const_type',
                             'DW_TAG_reference_type', 'DW_TAG_rvalue_reference_type',
                             'DW_TAG_volatile_type', 'DW_TAG_restrict_type',
                             'DW_TAG_ptr_to_member_type'):
                    _type['type'] = 'void'
                elif die == 'DW_TAG_enumeration_type':
                    _type['values'] = []
                    _type['type'] = 'void'
                elif die == 'DW_TAG_subroutine_type':
                    _type['params'] = []
                    pass
                types_lst.append(_type)
                stk.append(_type)
                pass
            elif die == 'DW_TAG_member':
                member_def = {'name': '<unknown>',
                              'meta_type': meta_flyweight.setdefault(die, die),
                              'type': None,
                              'location': None}
                stk.append(member_def)
                enclosing_type = find_enclosing_type(stk)
                enclosing_type['members'].append(member_def)
                pass
            elif die == 'DW_TAG_enumerator':
                value_def = {'name': '<unknown>',
                             'meta_type': meta_flyweight.setdefault(die, die),
                             'value': None}
                stk.append(value_def)
                enclosing_type = find_enclosing_type(stk)
                enclosing_type['values'].append(value_def)
            else:
                stk.append({'meta_type': meta_flyweight.setdefault(die, die)})
                pass
            pass
        elif tip_tag() == 'DW_TAG_subprogram':
            attr_value = parse_attr(line)
            if not attr_value:
                continue
            attr, value = attr_value
            if attr == 'DW_AT_name':
                subp = stk[-1]
                name = fly_name(get_name(value))
                subp['name'] = name
                #print(' ' * len(stk), attr, get_name(value))
            elif attr == 'DW_AT_linkage_name':
                subp = stk[-1]
                name = fly_name(get_name(value))
                subp['linkage_name'] = name
            elif attr == 'DW_AT_abstract_origin':
                subp = stk[-1]
                abstract_origin = parse_abstract_origin(value)
                subp['origin'] = abstract_origin
            elif attr == 'DW_AT_specification':
                subp = stk[-1]
                specification = parse_abstract_origin(value)
                subp['specification'] = specification
                pass
            pass
        elif tip_tag() in call_site_tags:
            attr_value = parse_attr(line)
            if attr_value:
                attr, value = attr_value
                if attr in origin_tags:
                    abstract_origin = parse_abstract_origin(value)
                    if abstract_origin:
                        enclosing_caller = find_enclosing_caller(stk)
                        if tip_tag() == 'DW_TAG_inlined_subroutine':
                            subp = stk[-1]
                            subp['origin'] = abstract_origin
                            pass
                        if not enclosing_caller:
                            print('no enclosing caller')
                            pprint(stk)
                            raise 'no enclosing caller'
                        if abstract_origin not in enclosing_caller['call']:
                            enclosing_caller['call'].append(abstract_origin)
                            pass
                        pass
                    pass
                pass
            pass
        elif tip_tag() in type_tags:
            attr_value = parse_attr(line)
            if not attr_value:
                continue
            attr, value = attr_value
            _type = stk[-1]
            if attr == 'DW_AT_name':
                name = fly_name(get_name(value))
                _type['name'] = name
            elif attr == 'DW_AT_linkage__name':
                name = fly_name(get_name(value))
                _type['linkage_name'] = name
            elif attr == 'DW_AT_type':
                _type['type'] = parse_addr_value(value)
            elif attr == 'DW_AT_declaration':
                _type['declaration'] = True
                pass
            pass
        elif tip_tag() == 'DW_TAG_member':
            attr_value = parse_attr(line)
            if not attr_value:
                continue
            attr, value = attr_value
            member = find_enclosing_type(stk)['members'][-1]
            if attr == 'DW_AT_name':
                name = fly_name(get_name(value))
                member['name'] = name
            elif attr == 'DW_AT_linkage_name':
                name = fly_name(get_name(value))
                member['linkage_name'] = name
            elif attr == 'DW_AT_type':
                member['type'] = parse_addr_value(value)
            elif attr == 'DW_AT_data_member_location':
                member['location'] = value
            elif attr == 'DW_AT_external':
                member['external'] = True
                pass
            pass
        elif tip_tag() == 'DW_TAG_enumerator':
            attr_value = parse_attr(line)
            if not attr_value:
                continue
            attr, value = attr_value
            if attr == 'DW_AT_name':
                name = fly_name(get_name(value))
                find_enclosing_type(stk)['values'][-1]['name'] = name
            elif attr == 'DW_AT_linkage_name':
                name = fly_name(get_name(value))
                find_enclosing_type(stk)['values'][-1]['linkage_name'] = name
            elif attr == 'DW_AT_const_value':
                if value.strip().startswith('0x'):
                    value = int(value, 16)
                else:
                    value = int(value)
                    pass
                find_enclosing_type(stk)['values'][-1]['value'] = value
                pass
            pass
        elif tip_tag() == 'DW_TAG_formal_parameter':
            if 'meta_type' not in stk[-2] or stk[-2]['meta_type'] != 'DW_TAG_subroutine_type':
                continue
            attr_value = parse_attr(line)
            if not attr_value:
                continue
            attr, value = attr_value
            if attr == 'DW_AT_type':
                type_addr = parse_addr_value(value)
                find_enclosing_type(stk)['params'].append(type_addr)
                pass
            pass
        pass

    subprograms.update((subp['addr'], subp) for subp in subprograms_lst)
    types.update((_type['addr'], _type) for _type in types_lst)

    for subp in subprograms.values():
        if not is_original(subp):
            origin = subprograms[get_real_addr(subp['origin'])]
            for call in subp['call']:
                if call in origin['call']:
                    continue
                origin['call'].append(call)
                pass
            pass
        else:
            if subp['name'] == '<unknown>':
                subp['name'] += subp['addr']
                pass
            pass
        pass
    for subp in subprograms_lst:
        if (not is_original(subp)) and \
           subp['meta_type'] == 'DW_TAG_inlined_subroutine':
            del subprograms[subp['addr']]
            pass
        pass
    return subprograms, types

def make_signature(_type, types):
    if _type['meta_type'] == 'placeholder':
        return get_symbol_name(_type)
    if _type['meta_type'] == 'DW_TAG_base_type':
        return get_symbol_name(_type)
    if _type['meta_type'] == 'DW_TAG_unspecified_type':
        return get_symbol_name(_type)
    if _type['meta_type'] in ptr_tags:
        if types[_type['type']]['meta_type'] == 'placeholder':
            return '<pointer>:' + get_symbol_name(types[_type['type']])
        return '<pointer>:' + _type['type']
    sig = _type['meta_type'] + ' ' + get_symbol_name(_type)
    if 'type' in _type:
        sig += ' ' + _type['type']
    if 'members' in _type:
        sig += ' {'
        sig += ','.join([get_symbol_name(member) + ':' + member['type']
                         for member in _type['members']])
        sig += '}'
    if 'values' in _type:
        sig += ' {'
        sig += ','.join([get_symbol_name(value) + ':' + str(value['value'])
                         for value in _type['values']])
        sig += '}'
    if 'params' in _type:
        sig += '('
        sig += ','.join(_type['params'])
        sig += ')'
        pass
    return sig

def make_sig_recur(_type, types, lvl=0):
    if lvl == 100:
        raise 'too deep'
    if _type['meta_type'] == 'placeholder':
        return get_symbol_name(_type)
    if _type['meta_type'] == 'DW_TAG_base_type':
        return get_symbol_name(_type)
    if _type['meta_type'] == 'DW_TAG_unspecified_type':
        return get_symbol_name(_type)
    sig = _type['meta_type'] + ' ' + get_symbol_name(_type)
    if 'type' in _type:
        sig += ' ' + make_sig_recur(types[_type['type']], types, lvl+1)
    if 'members' in _type:
        sig += ' {'
        sig += ','.join([get_symbol_name(member) + ':' +
                         make_sig_recur(types[member['type']], types, lvl+1)
                         for member in _type['members']])
        sig += '}'
    if 'values' in _type:
        sig += ' {'
        sig += ','.join([get_symbol_name(value) + ':' + str(value['value'])
                         for value in _type['values']])
        sig += '}'
    if 'params' in _type:
        sig += '('
        sig += ','.join([make_sig_recur(types[param], types, lvl+1)
                         for param in _type['params']])
        sig += ')'
        pass

    if lvl == 0:
        sig = hashlib.sha256(sig.encode('utf-8')).hexdigest()
        pass
    return sig

# Break the circular reference
# DW_TAG_pointer_type -> DW_TAG_structure_type -> DW_TAG_pointer_type
#
# We will follow pointer types until we reach a type that is not a pointer
# type or a type visited before. If we reach a type that is visited before,
# we will break the circular reference by replacing a pointer type pointing
# to a placeholder of the real type. The placeholder is a type with no
# members.
#
# Steps:
# 1. Create a list of tasks of types to be processed. Each task is a tuple
#    of a type and a list of visited types.
# 2. Repeat until all tasks are done:
#    2.1. Pop a task from the list.
#    2.2. If the type is marked as visited and with the same start addr,
#         skip it.
#    2.3. Mark the type as visited.
#    2.4. If the type is in the list of visited types,
#         replace a pointer type with a placeholder type to break
#         the circular reference.
#    2.5. Repeat for each member of the type.
#         2.5.1. Creat a task to process the member type. Add the current
#                type to the list of visited types of the new task.
# 3. Stop.
def break_circular_reference(subprograms, types, context):
    placeholder_names = set()
    context['placeholder_names'] = placeholder_names
    if len(types) == 0:
        return
    tpiter = iter(list(types.keys()))
    # 1. Create a list of tasks of types to be processed. Each task is a tuple
    #    of a type and a list of visited types.
    start_addr = next(tpiter)
    tasks = [(types[start_addr], [], set(), start_addr)]
    # 2. Repeat until all tasks are done:
    pop_cnt = 0
    while tasks:
        # 2.1. Pop a task from the list.
        _type, visited, visited_set, start_addr = tasks.pop()
        if not tasks:
            try:
                next_start_addr = next(tpiter)
                tasks.append((types[next_start_addr], [], set(), next_start_addr))
            except StopIteration:
                pass
            else:
                pop_cnt += 1
                if pop_cnt % 10000:
                    print('.', end='', flush=True)
                    pass
                pass
            pass
        # 2.2. If the type is marked as visited and with same start
        #      addr, skip it.
        if 'visited' in _type and _type['visited'] != start_addr:
            continue
        # 2.3. Mark the type as visited.
        _type['visited'] = start_addr
        # 2.4. If the type is in the list of visited types,
        #      replace a pointer type with a placeholder type to break
        #      the circular reference.
        if _type['addr'] in visited_set:
            path_lst = []
            while isinstance(visited[0], list):
                path_lst.append(visited[1:])
                visited = visited[0]
                pass
            path_lst.append(visited)
            path_lst.reverse()
            visited = list(itertools.chain(*path_lst))
            circular_path = visited[visited.index(_type['addr']):]
            break_circular_path(circular_path, types, placeholder_names)
            continue
        visited_set.add(_type['addr'])
        visited.append(_type['addr'])
        if len(visited) >= 1024:
            visisted = [visited]
            pass
        # 2.5. Repeat for each member of the type.
        if 'members' in _type:
            for member in _type['members']:
                # 2.5.1. Creat a task to process the member type. Add the
                #        current type to the list of visited types of the
                #        new task.
                if not member['type']:
                    print(_type)
                    pass
                if _type['meta_type'] != 'DW_TAG_union_type' and member['location'] is None:
                    continue
                tasks.append((types[member['type']], visited.copy(), visited_set.copy(), start_addr))
                pass
            pass
        if 'type' in _type:
            tasks.append((types[_type['type']], visited.copy(), visited_set.copy(), start_addr))
            pass
        if 'params' in _type:
            for param in _type['params']:
                tasks.append((types[param], visited.copy(), visited_set.copy(), start_addr))
                pass
            pass
        pass
    # 3. Stop.
    create_placeholders(types, placeholder_names)
    pass

# Break the circular reference described by the given path.
#
# The path is a list of addresses of types. The first type in the path
# is a pointer type pointing to the second type in the path. The second
# type in the path is a pointer type pointing to the third type in the
# path. And so on. The last type in the path is a pointer type pointing
# to the first type in the path.
#
# We choose the pointer type pointing to a type with a name that is
# first in the dictionary order. The pointed type will be replaced by
# a placeholder type.
#
# Steps:
# 1. Create a list of pointer types pointing to a type having a name.
# 2. Sort the list by the name of the pointed type.
# 3. Replace the pointed type of the first pointer type in the list
#    with a placeholder type.
# 4. Stop.
def break_circular_path(circular_path, types, placeholder_names):
    if try_existing_placeholders(circular_path, types, placeholder_names):
        return
    # 1. Create a list of pointer types pointing to a type having a name.
    ptrs = []
    for addr in circular_path:
        _type = types[addr]
        if _type['meta_type'] in ptr_tags and \
           'name' in types[_type['type']] and \
           get_symbol_name(types[_type['type']]) != '<unknown>':
            if types[_type['type']]['meta_type'] == 'placeholder':
                return
            ptrs.append(_type)
            pass
        pass
    if not ptrs:
        print('No pointer type found in the circular path')
        print([types[addr] for addr in circular_path])
        #return
        pass
    # 2. Sort the list by the name of the pointed type.
    ptrs.sort(key=lambda ptr: get_symbol_name(types[ptr['type']]))
    # 3. Replace the pointed type of the first pointer type in the list
    #    with a placeholder type.
    ptr = ptrs[0]
    placeholder_names.add(get_symbol_name(types[ptr['type']]))
    ptr['type'] = create_placeholder(ptr['type'], types)
    # 4. Stop.
    pass

# Try to use existing placeholders to break the circular reference.
#
# If a pointer type pointing to a type having a name that is the name
# of another type, and a placeholder has been created for that type,
# we will create a placeholder for the pointed type and replace the
# pointed type with the placeholder.
def try_existing_placeholders(circular_path, types, placeholder_names):
    for addr in circular_path:
        _type = types[addr]
        if _type['meta_type'] not in ptr_tags:
            continue
        pointed_type = types[_type['type']]
        if 'name' in pointed_type and \
            get_symbol_name(pointed_type) in placeholder_names:
            _type['type'] = create_placeholder(_type['type'], types)
            return True
        pass
    return False

# Create a placholders for each pointer type pointing to a
# non-placholder type but with a name in the set of placholder names.
def create_placeholders(types, placeholder_names):
    for _type in list(types.values()):
        if _type['meta_type'] not in ptr_tags:
            continue
        pointed_type = types[_type['type']]
        if 'name' in pointed_type and \
            get_symbol_name(pointed_type) in placeholder_names:
            _type['type'] = create_placeholder(_type['type'], types)
            pass
        pass
    pass

def create_placeholder(addr, types):
    real_type = types[addr]
    assert 'name' in real_type
    placeholder_addr = 'placeholder:' + addr
    if placeholder_addr in types:
        return placeholder_addr
    placeholder = {
        'meta_type': 'placeholder',
        'name': '<placeholder>:' + get_symbol_name(real_type),
        'addr': placeholder_addr,
        'real_type': addr,
    }
    types[placeholder_addr] = placeholder
    return placeholder_addr

# Give a name to unnamed transit types.
#
# Transit types are DW_TAG_const_type, DW_TAG_volatile_type,
# and DW_TAG_restrict_type.
#
# Steps:
# 1. Repeat until all types are processed:
#    1.1. Initialize the new name as an empty string.
#    1.2. Repeatly follow the 'type' field until a type with a name is
#         found or a non-transit type is found.
#         1.2.1. If a type with a name is found, skip it.
#         1.2.1. Append the 'meta_type' to the new name.
#    1.3. If the name of the latest type is empty, skip the type.
#    1.4. Append the name of the type found in the 1.2 step to the new name.
#    1.5. Set the 'name' field of the processing type to the new name.
# 2. Stop.
def init_transit_type_names(subprograms, types, context):
    # 1. Repeat until all types are processed:
    for _type in types.values():
        if _type['meta_type'] not in ('DW_TAG_const_type',
                                      'DW_TAG_volatile_type',
                                      'DW_TAG_restrict_type'):
            continue
        processing = _type
        # 1.1. Initialize the new name as an empty string.
        new_name = ''
        # 1.2. Repeatly follow the 'type' field until a type with a name is
        #      found or a non-transit type is found.
        while _type['meta_type'] in ('DW_TAG_const_type',
                                     'DW_TAG_volatile_type',
                                     'DW_TAG_restrict_type'):
            # 1.2.1. If a type with a name is found, skip it.
            if 'name' in _type and get_symbol_name(_type) != '<unknown>':
                break
            # 1.2.1. Append the 'meta_type' to the new name.
            new_name = new_name + ' ' + _type['meta_type']
            # 1.2.2. Follow the 'type' field.
            _type = types[_type['type']]
            pass
        # 1.3. If the name of the latest type is empty, skip the type.
        if not get_symbol_name(_type) or get_symbol_name(_type) == '<unknown>':
            continue
        # 1.4. Append the name of the type found in the 1.2 step to the new name.
        new_name = new_name + ' ' + get_symbol_name(_type)
        # 1.5. Set the 'name' field of the processing type to the new name.
        processing['name'] = new_name.strip()
        pass
    # 2. Stop.
    pass

# Dump the tree rooted at the given type.
def dump_tree(_type, types, indent=0):
    print(' ' * indent + get_symbol_name(_type) + '@' + _type['addr'] + ' ' + _type['meta_type'] + '\tsig: ' + make_signature(_type, types))
    if 'members' in _type:
        for member in _type['members']:
            dump_tree(types[member['type']], types, indent + 2)
            pass
        pass
    elif 'type' in _type:
        dump_tree(types[_type['type']], types, indent + 2)
        pass
    elif 'params' in _type:
        for param in _type['params']:
            dump_tree(types[param], types, indent + 2)
            pass
        pass
    pass

def merge_types(subprograms, types, context):
    choosed_types = context.setdefault('choosed_types', {})

    for _type in types.values():
        if _type['meta_type'] in ('DW_TAG_base_type', 'DW_TAG_unspecified_type'):
            if get_symbol_name(_type) in choosed_types:
                _type['replaced_by'] = choosed_types[get_symbol_name(_type)]['addr']
            else:
                choosed_types[get_symbol_name(_type)] = _type
                _type['choosed'] = True
                pass
            pass
        elif _type['meta_type'] == 'placeholder':
            _type['choosed'] = True
            pass
        pass
    replacing_cnt = 1
    choosing_cnt = 1
    rounds = 0
    while (replacing_cnt + choosing_cnt) > 0:
        replacing_cnt = 0
        choosing_cnt = 0
        for _type in types.values():
            if 'replaced_by' in _type:
                continue
            if 'choosed' in _type and 'merge_set' not in _type:
                continue

            choosed_cnt = 0
            should_choosed = 0
            if 'type' in _type:
                backing = types[_type['type']]
                if 'replaced_by' in backing:
                    _type['type'] = backing['replaced_by']
                    replacing_cnt += 1
                    pass
                backing = types[_type['type']]
                if 'choosed' in backing:
                    choosed_cnt += 1
                    pass
                should_choosed += 1
                pass
            if 'members' in _type:
                members = _type['members']
                for i in range(len(members)):
                    member = members[i]
                    member_backing = types[member['type']]
                    if 'replaced_by' in member_backing:
                        member['type'] = member_backing['replaced_by']
                        replacing_cnt += 1
                        pass
                    member_backing = types[member['type']]
                    if 'choosed' in member_backing:
                        choosed_cnt += 1
                        pass
                    pass
                should_choosed += len(members)
                pass
            if 'params' in _type:
                params = _type['params']
                for i in range(len(params)):
                    param = params[i]
                    param_backing = types[param]
                    if 'replaced_by' in param_backing:
                        params[i] = param_backing['replaced_by']
                        replacing_cnt += 1
                        pass
                    param_backing = types[param]
                    if 'choosed' in param_backing:
                        choosed_cnt += 1
                        pass
                    pass
                should_choosed += len(params)
                pass

            if choosed_cnt == should_choosed and 'choosed' not in _type:
                sig = make_signature(_type, types)
                if sig in choosed_types:
                    _type['replaced_by'] = choosed_types[sig]['addr']
                    replacing_cnt += 1
                else:
                    choosed_types[sig] = _type
                    _type['choosed'] = True
                    choosing_cnt += 1
                    pass
                pass
            pass
        rounds += 1
        #print('   - rounds', rounds, 'replacing_cnt', replacing_cnt, 'choosing_cnt', choosing_cnt)
        pass
    pass

def dump_types(subprograms, types, context):
    dump_cnt = 0
    for _type in types.values():
        if get_symbol_name(_type) == 'fib_rule' and 'choosed' in _type:
            #dump_tree(_type, types)
            dump_cnt += 1
            if dump_cnt >= 2:
                break
            pass
        pass
    pass

def handle_placeholder_replacement(subprograms, types, context):
    # Handle replaced real types of placeholders.
    for _type in types.values():
        if _type['meta_type'] != 'placeholder':
            continue
        real_type = types[_type['real_type']]
        if 'replaced_by' in real_type:
            _type['real_type'] = real_type['replaced_by']
            pass
        pass
    pass

def remove_replaced_types(subprograms, types, context):
    # Remove replaced types and placeholders
    non_choosed = 0
    for addr in list(types.keys()):
        if 'replaced_by' in types[addr]:
            if 'choosed' in types[addr]:
                print('replaced choosed type', types[addr])
                pass
            del types[addr]
            pass
        elif 'choosed' not in types[addr]:
            if non_choosed < 3:
                print('non choosed types:')
                print(types[addr])
                pass
            non_choosed += 1
            pass
        pass
    print(' non_choosed', non_choosed, end='')
    pass

def init_merge_set_of_types_with_placeholders(subprograms, types, context):
    placeholder_names = context['placeholder_names']
    merge_sets = dict([(name, set()) for name in placeholder_names])
    # For each type with a name in placeholder_names.
    for _type in types.values():
        if 'name' not in _type:
            continue
        name = get_symbol_name(_type)
        if name not in placeholder_names:
            continue
        # Add the type to the merge set of the name.
        merge_sets[name].add(_type['addr'])
        _type['merge_set'] = merge_sets[name]
        pass

    context['merge_sets'] = merge_sets.values()
    print(': merge_sets', len(merge_sets), end='')
    pass

# Divide a marge set to subsets of same signature.
def divide_merge_set_sig(merge_set, types):
    sigs = dict()
    for addr in merge_set:
        _type = types[addr]
        sig = make_sig_recur(_type, types)
        if sig not in sigs:
            sigs[sig] = set()
            pass
        sigs[sig].add(addr)
        _type['merge_set'] = sigs[sig]
        pass
    return sigs.values()

# Divide each merge set to subsets of same signature.
def divide_merge_sets_sig(subprograms, types, context):
    merge_sets = context['merge_sets']
    new_merge_sets = []
    for merge_set in merge_sets:
        sigs = divide_merge_set_sig(merge_set, types)
        new_merge_sets.extend(sigs)
        pass
    context['merge_sets'] = new_merge_sets
    print(': merge_sets', len(new_merge_sets), end='')
    pass

# Divide a merge set to sbusets of the same dependent merge sets.
#
# A dependent placeholder of a type is a placeholder that is used by
# the type.  A type can has more than one dependent placeholders.  A
# dependent type is a type that represeted by a dependent placeholder.
# A dependent merge set is a merge set that can contains a dependent
# type.  The dependent merge set of a dependent type is the
# 'merge_set' attribute of the dependent type.
#
# This function return a list of subsets.
def divide_merge_set_dep(merge_set, types):
    deps = dict()
    for addr in merge_set:
        _type = types[addr]
        dep_sets = find_dependent_merge_sets(_type, types)
        dep = tuple((id(dep_set) for dep_set in dep_sets))
        if dep not in deps:
            deps[dep] = set()
            pass
        deps[dep].add(addr)
        _type['merge_set'] = deps[dep]
        pass
    return deps.values()

# Find the dependent merge sets of a type.
#
# We need to follow the 'type', 'members', and 'params' attributes
# until we find a placeholder.  The merge set of the type represented
# by the placeholder is the dependent merge set.
#
# Steps:
# 1. Set a list of tasks containing only the given type and an empty
#    list of dependent sets.
# 2. While the list is not empty:
#    2.1. Pop a task from the list.
#    2.2. If the task is a placeholder, add the merge set of the
#         placeholder to the list of dependent sets.
#    2.3. If the task is not a placeholder, add the tasks of the
#         attributes of the task to the list.
#         2.3.1. Add the task of the 'type' attribute if it exists.
#         2.3.2. Add the tasks of the 'members' attribute if it
#                exists.
#         2.3.3. Add the tasks of the 'params' attribute if it
#                exists.
# 3. Return a list of dependent sets.
def find_dependent_merge_sets(_type, types):
    # 1. Set a list of tasks containing only the given type and an empty
    #    list of dependent sets.
    tasks = [_type]
    dep_sets = []
    # 2. While the list is not empty:
    while tasks:
        # 2.1. Pop a task from the list.
        task = tasks.pop()
        # 2.2. If the task is a placeholder, add the merge set of the
        #      placeholder to the list of dependent sets.
        if task['meta_type'] == 'placeholder':
            dep_sets.append(types[task['real_type']]['merge_set'])
            continue
        # 2.3. If the task is not a placeholder, add the tasks of the
        #      attributes of the task to the list.
        #      2.3.1. Add the task of the 'type' attribute if it exists.
        if 'type' in task:
            tasks.append(types[task['type']])
            pass
        #      2.3.2. Add the tasks of the 'members' attribute if it
        #             exists.
        if 'members' in task:
            for member in task['members']:
                tasks.append(types[member['type']])
                pass
            pass
        #      2.3.3. Add the tasks of the 'params' attribute if it
        #             exists.
        if 'params' in task:
            for param in task['params']:
                tasks.append(types[param])
                pass
            pass
        pass
    # 3. Return a list of dependent sets.
    return dep_sets

# Divide merge sets to subsets of the same dependent merge sets.
#
# Repeat this process until the number of merge sets doesn't change
# anymore.
def divide_merge_sets_dep(subprograms, types, context):
    merge_sets = context['merge_sets']
    while True:
        print('.', end='', flush=True)
        new_merge_sets = []
        for merge_set in merge_sets:
            subsets = divide_merge_set_dep(merge_set, types)
            new_merge_sets.extend(subsets)
            pass
        if len(new_merge_sets) == len(merge_sets):
            break
        merge_sets = new_merge_sets
        pass
    context['merge_sets'] = new_merge_sets
    print(': merge_sets', len(new_merge_sets), end='')
    pass

# Do replacements for merge sets.
def replace_merge_sets(subprograms, types, context):
    merge_sets = context['merge_sets']
    for merge_set in merge_sets:
        if len(merge_set) == 1:
            continue
        replace_merge_set(merge_set, types)
        pass
    pass

# Do replacements for a merge set.
def replace_merge_set(merge_set, types):
    # Find the representative type.
    rep_type = types[list(merge_set).pop()]
    rep_type['choose'] = True
    # Replace all types in the merge set with the representative type.
    for addr in merge_set:
        if addr == rep_type['addr']:
            continue
        _type = types[addr]
        _type['replace_by'] = rep_type['addr']
        pass
    pass

def remove_external_members(subprograms, types, context):
    for _type in types.values():
        if 'members' not in _type:
            continue
        for i in range(len(_type['members']) - 1, -1, -1):
            if 'external' in _type['members'][i]:
                del _type['members'][i]
                pass
            pass
        pass
    pass

def borrow_name_from_specification(subprograms, types, context):
    for subp in subprograms.values():
        if 'specification' not in subp:
            continue
        spec = subprograms[subp['specification']]
        if get_symbol_name(subp).startswith('<unknown>'):
            subp['name'] = get_symbol_name(spec)
            pass
        pass
    pass

def redirect_calls_to_origin(subprograms, types, context):
    for caller in subprograms.values():
        if 'call' not in caller:
            continue
        for i, callee in enumerate(caller['call']):
            while 'origin' in subprograms[callee]:
                callee = subprograms[callee]['origin']
                caller['call'][i] = callee
                pass
            pass
        pass
    pass

def set_call_names(subprograms, types, context):
    for subp in subprograms.values():
        if 'call' not in subp:
            continue
        if not is_original(subp):
            continue
        subp['call_names'] = [get_symbol_name(subprograms[callee])
                              for callee in set(subp['call'])]
        pass
    pass

type_process_phases = [
    redirect_calls_to_origin,
    borrow_name_from_specification,
    set_call_names,
    remove_external_members,
    init_transit_type_names,
    break_circular_reference,
    init_merge_set_of_types_with_placeholders,
    divide_merge_sets_sig,
    divide_merge_sets_dep,
    replace_merge_sets,
    merge_types,
    dump_types,
    handle_placeholder_replacement,
    remove_replaced_types,
]

def main():
    optparser = optparse.OptionParser()
    optparser.add_option('-o', '--output', dest='output', default='callgraph.sqlite3',
                         help='output file name')
    opts, args = optparser.parse_args()

    filename = args[0]
    output = opts.output

    print('parsing DIEs from %s' % filename, end='', flush=True)
    lines = open(filename)
    start_time = time.time()
    subprograms, types = parse_DIEs(lines)
    print(' - done in %.2f seconds' % (time.time() - start_time))

    # Check if the file exists. If yes, delete it.
    if os.path.exists(output):
        print('output file %s already exists, delete it' % output)
        os.remove(output)
        pass

    context = {}
    print('processing subprograms (%d) and types (%d types)' % (len(subprograms), len(types)))
    for phase in type_process_phases:
        print(' - processing phase', phase.__name__, end='', flush=True)
        start_time = time.time()
        phase(subprograms, types, context)
        print(': done in %.2f seconds' % (time.time() - start_time))
        pass
    print(' - processing phase done (%d subprograms and %d types)' % (len(subprograms), len(types)))

    print('persisting to %s...' % output)
    persist_info(subprograms, types, output)
    pass

if __name__ == '__main__':
    start_time = time.time()
    main()
    print('Total time: %.2f seconds' % (time.time() - start_time))
    pass
