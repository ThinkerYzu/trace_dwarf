#!/usr/bin/env python3
import sqlite3
import sys
import re
import optparse
import os
import time
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
        if stk[i][0] in subprogram_tags:
            return stk[i][1]    # address
    return None

def find_enclosing_type(stk):
    for i in range(len(stk)-2, -1, -1):
        if stk[i][0] in type_tags:
            return stk[i][1]
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
    types = {'void': {'name': 'void',
                      'meta_type': 'DW_TAG_base_type',
                      'addr': 'void'}}
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
            elif die in type_tags:
                types[addr] = {'name': '<unknown>',
                               'meta_type': meta_flyweight.setdefault(die, die),
                               'addr': addr}
                if die in ('DW_TAG_structure_type', 'DW_TAG_union_type', 'DW_TAG_class_type'):
                    types[addr]['members'] = []
                elif die in ('DW_TAG_pointer_type', 'DW_TAG_const_type',
                             'DW_TAG_volatile_type', 'DW_TAG_restrict_type',
                             'DW_TAG_ptr_to_member_type'):
                    types[addr]['type'] = 'void'
                elif die == 'DW_TAG_enumeration_type':
                    types[addr]['values'] = []
                    types[addr]['type'] = 'void'
                elif die == 'DW_TAG_subroutine_type':
                    types[addr]['params'] = []
                    pass
                pass
            elif die == 'DW_TAG_member':
                enclosing_type = find_enclosing_type(stk)
                member_def = {'name': '<unknown>',
                              'type': None,
                              'location': None}
                types[enclosing_type]['members'].append(member_def)
                pass
            elif die == 'DW_TAG_enumerator':
                enclosing_type = find_enclosing_type(stk)
                value_def = {'name': '<unknown>',
                            'value': None}
                types[enclosing_type]['values'].append(value_def)
                pass
            pass
        elif tip_tag() == 'DW_TAG_subprogram':
            attr_value = parse_attr(line)
            if not attr_value:
                continue
            attr, value = attr_value
            if attr == 'DW_AT_name':
                tag, addr = stk[-1]
                name = fly_name(get_name(value))
                subprograms[addr]['name'] = name
                #print(' ' * len(stk), attr, get_name(value))
            elif attr == 'DW_AT_linkage_name':
                tag, addr = stk[-1]
                name = fly_name(get_name(value))
                subprograms[addr]['linkage_name'] = name
            elif attr == 'DW_AT_abstract_origin':
                tag, addr = stk[-1]
                abstract_origin = parse_abstract_origin(value)
                subprograms[addr]['origin'] = abstract_origin
                pass
            pass
        elif tip_tag() in call_site_tags:
            attr_value = parse_attr(line)
            if attr_value:
                attr, value = attr_value
                if attr in origin_tags:
                    abstract_origin = parse_abstract_origin(value)
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
        elif tip_tag() in type_tags:
            attr_value = parse_attr(line)
            if not attr_value:
                continue
            attr, value = attr_value
            tag, addr = stk[-1]
            _type = types[addr]
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
            tag, addr = stk[-1]
            member = types[find_enclosing_type(stk)]['members'][-1]
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
                pass
            pass
        elif tip_tag() == 'DW_TAG_enumerator':
            attr_value = parse_attr(line)
            if not attr_value:
                continue
            attr, value = attr_value
            tag, addr = stk[-1]
            if attr == 'DW_AT_name':
                name = fly_name(get_name(value))
                types[find_enclosing_type(stk)]['values'][-1]['name'] = name
            elif attr == 'DW_AT_linkage_name':
                name = fly_name(get_name(value))
                types[find_enclosing_type(stk)]['values'][-1]['linkage_name'] = name
            elif attr == 'DW_AT_const_value':
                if value.strip().startswith('0x'):
                    value = int(value, 16)
                else:
                    value = int(value)
                    pass
                types[find_enclosing_type(stk)]['values'][-1]['value'] = value
                pass
            pass
        elif tip_tag() == 'DW_TAG_formal_parameter':
            if stk[-2][0] != 'DW_TAG_subroutine_type':
                continue
            attr_value = parse_attr(line)
            if not attr_value:
                continue
            attr, value = attr_value
            tag, addr = stk[-1]
            if attr == 'DW_AT_type':
                type_addr = parse_addr_value(value)
                types[find_enclosing_type(stk)]['params'].append(type_addr)
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
    return subprograms, types

def make_signature(_type, types):
    if _type['meta_type'] == 'placeholder':
        return get_symbol_name(_type)
    if _type['meta_type'] == 'DW_TAG_base_type':
        return get_symbol_name(_type)
    if _type['meta_type'] == 'DW_TAG_unspecified_type':
        return get_symbol_name(_type)
    if _type['meta_type'] in ('DW_TAG_pointer_type', 'DW_TAG_ptr_to_member_type'):
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

def make_sig_recur(_type, types):
    if _type['meta_type'] == 'placeholder':
        return get_symbol_name(_type)
    if _type['meta_type'] == 'DW_TAG_base_type':
        return get_symbol_name(_type)
    if _type['meta_type'] == 'DW_TAG_unspecified_type':
        return get_symbol_name(_type)
    sig = _type['meta_type'] + ' ' + get_symbol_name(_type)
    if 'type' in _type:
        sig += ' ' + make_sig_recur(types[_type['type']], types)
    if 'members' in _type:
        sig += ' {'
        sig += ','.join([get_symbol_name(member) + ':' +
                         make_sig_recur(types[member['type']], types)
                         for member in _type['members']])
        sig += '}'
    if 'values' in _type:
        sig += ' {'
        sig += ','.join([get_symbol_name(value) + ':' + str(value['value'])
                         for value in _type['values']])
        sig += '}'
    if 'params' in _type:
        sig += '('
        sig += ','.join([make_sig_recur(types[param], types)
                         for param in _type['params']])
        sig += ')'
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
#    2.2. If the type is marked as visited and empty visited list, skip it.
#    2.3. Mark the type as visited.
#    2.4. If the type is a pointer type, follow the pointer type.
#         2.4.1. If the following type is in the list of visited types,
#                replace the pointer type with a placeholder type to break
#                the circular reference.
#    2.5. Repeat for each member of the type.
#         2.5.1. Creat a task to process the member type. Add the current
#                type to the list of visited types of the new task.
# 3. Stop.
def break_circular_reference(types, context):
    placeholder_names = set()
    context['placeholder_names'] = placeholder_names
    if len(types) == 0:
        return
    tpiter = iter(types)
    # 1. Create a list of tasks of types to be processed. Each task is a tuple
    #    of a type and a list of visited types.
    tasks = [(types[next(tpiter)], [])]
    # 2. Repeat until all tasks are done:
    while tasks:
        # 2.1. Pop a task from the list.
        _type, visited = tasks.pop()
        if not tasks:
            try:
                tasks.append((types[next(tpiter)], []))
            except StopIteration:
                pass
            pass
        # 2.2. If the type is marked as visited and empty visited
        #      list, skip it.
        if len(visited) == 0 and 'visited' in _type:
            continue
        # 2.3. Mark the type as visited.
        _type['visited'] = True
        # 2.4. If the type is a pointer type, follow the pointer type.
        if _type['meta_type'] in ('DW_TAG_pointer_type', 'DW_TAG_ptr_to_member_type'):
            # 2.4.1. If the following type is in the list of visited types,
            #        replace the pointer type with a placeholder type to break
            #        the circular reference.
            following_type = types[_type['type']]
            if _type['type'] in visited:
                circular_path = visited[visited.index(_type['type']):] + [_type['addr']]
                break_circular_path(circular_path, types, placeholder_names)
                continue
            pass
        # 2.5. Repeat for each member of the type.
        if 'members' in _type:
            for member in _type['members']:
                # 2.5.1. Creat a task to process the member type. Add the
                #        current type to the list of visited types of the
                #        new task.
                tasks.append((types[member['type']], visited + [_type['addr']]))
                pass
            pass
        if 'type' in _type:
            tasks.append((types[_type['type']], visited + [_type['addr']]))
            pass
        if 'params' in _type:
            for param in _type['params']:
                tasks.append((types[param], visited + [_type['addr']]))
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
        if _type['meta_type'] in ('DW_TAG_pointer_type', 'DW_TAG_ptr_to_member_type') and \
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
        if _type['meta_type'] not in ('DW_TAG_pointer_type', 'DW_TAG_ptr_to_member_type'):
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
        if _type['meta_type'] not in ('DW_TAG_pointer_type', 'DW_TAG_ptr_to_member_type'):
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
def init_transit_type_names(types, context):
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

def merge_types(types, context):
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

def dump_types(types, context):
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

def handle_placeholder_replacement(types, context):
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

def remove_replaced_types(types, context):
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

def init_merge_set_of_types_with_placeholders(types, context):
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
def divide_merge_sets_sig(types, context):
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
def divide_merge_sets_dep(types, context):
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
def replace_merge_sets(types, context):
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

type_process_phases = [
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
    print('processing types (%d types)' % len(types))
    for phase in type_process_phases:
        print(' - processing phase', phase.__name__, end='', flush=True)
        start_time = time.time()
        phase(types, context)
        print(': done in %.2f seconds' % (time.time() - start_time))
        pass
    print(' - processing phase done (%d types)' % len(types))

    print('persisting to %s...' % output)
    persist_info(subprograms, types, output)
    pass

if __name__ == '__main__':
    start_time = time.time()
    main()
    print('Total time: %.2f seconds' % (time.time() - start_time))
    pass
