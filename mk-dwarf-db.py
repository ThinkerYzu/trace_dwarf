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
from dataclasses import dataclass, field
from typing import List

DIE_reo = re.compile(r'^ ?<\d+><(\d|[a-f])+>: Abbrev Number: \d+.*$')
DIE_tag_reo = re.compile(r'.*<(\d+)><([0-9a-f]+)>: Abbrev Number: \d+ \((\w+)\).*')
ATTR_reo = re.compile(r'^ *<[0-9a-f]+> +(DW_AT_\w+) *: (.*)$')
abstract_reo = re.compile('<0x([0-9a-f]+)>')
addr_reo = re.compile('<0x([0-9a-f]+)>')

origin_attrs = ('DW_AT_abstract_origin', 'DW_AT_call_origin')

MT_other = -1
MT_array = 1
MT_base = 2
MT_const = 3
MT_enumeration = 4
MT_pointer = 5
MT_ptr_to_member = 6
MT_reference = 7
MT_restrict = 8
MT_rvalue_reference = 9
MT_structure = 10
MT_class = 11
MT_subroutine = 12
MT_typedef = 13
MT_union = 14
MT_volatile = 15
MT_unspecified = 16
MT_subprogram = 17
MT_inlined_subroutine = 18
MT_GNU_call_site = 19
MT_call_site = 20
MT_placeholder = 21
MT_member = 22
MT_enumerator = 23
MT_formal_parameter = 24

MT_table = {
    'DW_TAG_array_type': MT_array,
    'DW_TAG_base_type': MT_base,
    'DW_TAG_const_type': MT_const,
    'DW_TAG_enumeration_type': MT_enumeration,
    'DW_TAG_pointer_type': MT_pointer,
    'DW_TAG_ptr_to_member_type': MT_ptr_to_member,
    'DW_TAG_reference_type': MT_reference,
    'DW_TAG_restrict_type': MT_restrict,
    'DW_TAG_rvalue_reference_type': MT_rvalue_reference,
    'DW_TAG_structure_type': MT_structure,
    'DW_TAG_class_type': MT_class,
    'DW_TAG_subroutine_type': MT_subroutine,
    'DW_TAG_typedef': MT_typedef,
    'DW_TAG_union_type': MT_union,
    'DW_TAG_volatile_type': MT_volatile,
    'DW_TAG_unspecified_type': MT_unspecified,
    'DW_TAG_subprogram': MT_subprogram,
    'DW_TAG_inlined_subroutine': MT_inlined_subroutine,
    'DW_TAG_GNU_call_site': MT_GNU_call_site,
    'DW_TAG_call_site': MT_call_site,
    'DW_TAG_placeholder': MT_placeholder,
    'DW_TAG_member': MT_member,
    'DW_TAG_enumerator': MT_enumerator,
    'DW_TAG_formal_parameter': MT_formal_parameter,
}

MT_table_rev = {v: k for k, v in MT_table.items()}

type_tags = (MT_array,
             MT_base,
             MT_const,
             MT_enumeration,
             MT_pointer,
             MT_ptr_to_member,
             MT_reference,
             MT_restrict,
             MT_rvalue_reference,
             MT_structure,
             MT_class,
             MT_subroutine,
             MT_typedef,
             MT_union,
             MT_volatile,
             MT_unspecified)

call_site_tags = (MT_GNU_call_site, MT_call_site, MT_inlined_subroutine)
subprogram_tags = (MT_subprogram, MT_inlined_subroutine)
ptr_tags = (MT_pointer, MT_ptr_to_member, MT_reference, MT_rvalue_reference)

@dataclass(slots=True)
class MemberInfo:
    name: str = '<unknown>'
    linkage_name: str = ''
    type: int = -1
    offset: int = -1
    external: bool = False
    pass

@dataclass(slots=True)
class ValueInfo:
    name: str = '<unknown>'
    linkage_name: str = ''
    value: int = 0
    pass

@dataclass(slots=True)
class TypeInfo:
    addr: int
    meta_type: int
    id: int = -1
    name: str = '<unknown>'
    linkage_name: str = ''
    declaration: bool = False
    members: List[MemberInfo] = field(default_factory=list)
    values: List[ValueInfo] = field(default_factory=list)
    params: List[int] = field(default_factory=list)
    type: int = -1
    real_type: int = -1
    replaced_by: int = -1
    visited: int = -1
    choosed: bool = False
    pass

@dataclass(slots=True)
class SubpInfo:
    addr: int
    meta_type: int
    id: int = -1
    origin: int = -1
    specification: int = -1
    name: str = '<unknown>'
    linkage_name: str = ''
    calls: List[int] = field(default_factory=list)
    call_names: List[str] = field(default_factory=list)
    pass

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
        if isinstance(stk[i], SubpInfo):
            return stk[i]
    return None

def find_enclosing_type(stk):
    for i in range(len(stk)-2, -1, -1):
        if isinstance(stk[i], TypeInfo) and stk[i].meta_type in type_tags:
            return stk[i]
    return None

def init_schema(conn):
    conn.execute('create table symbols(id integer primary key asc, name text unique)')
    conn.execute('create table calls(caller integer, callee integer)')

    conn.execute('create table types(id integer primary key asc, name text, addr integer unique, meta_type text, declaration integer)')
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
    return subprogram.origin < 0

def get_symbol_name(symbol):
    if symbol.linkage_name:
        return symbol.linkage_name
    return symbol.name

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
                 for callee in subp.call_names]
        insert_calls(conn, calls)
        pass

    conn.commit()
    pass

def get_real_type(addr, types):
    if types[addr].meta_type == MT_placeholder:
        return types[types[addr].real_type]
    return types[addr]

def persist_types_info(conn, types):
    for addr, type_info in types.items():
        if type_info.meta_type == MT_placeholder:
            continue
        name = get_symbol_name(type_info)
        meta_type = MT_table_rev[type_info.meta_type]
        declaration = 1 if type_info.declaration else 0
        conn.execute('insert into types(name, addr, meta_type, declaration) values(?, ?, ?, ?)',
                     (name, addr, meta_type, declaration))
        cur = conn.execute('select id from types where addr = ?',
                           (addr,))
        row = cur.fetchone()
        type_id = row[0]
        type_info.id = type_id
        pass

    for type_info in types.values():
        if type_info.meta_type == MT_placeholder:
            continue
        type_id = type_info.id
        if type_info.members:
            for member in type_info.members:
                conn.execute('insert into members values(?, ?, ?, ?)',
                             (type_id, get_symbol_name(member),
                              get_real_type(member.type, types).id,
                              member.offset or 0))
                pass
            pass
        if type_info.type >= 0:
            if type_info.type not in types:
                print('unknown type %s' % type_info.type)
                print(type_info)
                pass
            type_type = get_real_type(type_info.type, types)
            if type_type.id < 0:
                print(type_info.type, types[type_info.type], type_type)
                pass
            conn.execute('insert into members values(?, ?, ?, ?)',
                         (type_id, '',
                          type_type.id,
                          0))
            pass
        if type_info.params:
            for i, param in enumerate(type_info.params):
                conn.execute('insert into members values(?, ?, ?, ?)',
                             (type_id, str(i),
                              get_real_type(param, types).id,
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
    void = TypeInfo(0, MT_base)
    void.name = 'void'
    types = {0: void}
    types_lst = []
    stk = []
    name_flyweight = {}

    def fly_name(name):
        h = hash(name) & 0xff
        bucket = name_flyweight.setdefault(h, {})
        return bucket.setdefault(name, name)

    def get_real_addr(addr):
        while addr in subprograms:
            if not is_original(subprograms[addr]):
                addr = subprograms[addr].origin
                continue
            break
        return addr

    def get_name_addr(addr):
        while addr in subprograms:
            subp = subprograms[addr]
            if not is_original(subp):
                addr = subp.origin
                continue
            return get_symbol_name(subp)
        print('no name for addr: %x' % addr)
        raise '<unknown>'

    def tip_tag():
        if len(stk) == 0:
            return None
        if isinstance(stk[-1], (TypeInfo, SubpInfo)):
            return stk[-1].meta_type
        if isinstance(stk[-1], MemberInfo):
            return MT_member
        if isinstance(stk[-1], ValueInfo):
            return MT_enumerator
        return stk[-1]['meta_type']

    for line in lines:
        dep_addr_die = is_DIE(line)
        if dep_addr_die:
            dep, addr, die_str = dep_addr_die
            if die_str == '0':
                stk.pop()
                continue
            addr = int(addr, 16)
            if die_str in MT_table:
                die = MT_table[die_str]
            else:
                die = MT_other
            stk = stk[:dep]
            if die in subprogram_tags:
                subp = SubpInfo(addr, die)
                subprograms_lst.append(subp)
                stk.append(subp)
            elif die in type_tags:
                _type = TypeInfo(addr, die)
                if die in (MT_pointer, MT_const, MT_reference,
                           MT_rvalue_reference, MT_volatile,
                           MT_restrict, MT_ptr_to_member):
                    _type.type = void.addr
                elif die == MT_enumeration:
                    _type.type = void.addr
                    pass
                types_lst.append(_type)
                stk.append(_type)
                pass
            elif die == MT_member:
                member_def = MemberInfo()
                stk.append(member_def)
                enclosing_type = find_enclosing_type(stk)
                enclosing_type.members.append(member_def)
                pass
            elif die == MT_enumerator:
                value_def = ValueInfo()
                stk.append(value_def)
                enclosing_type = find_enclosing_type(stk)
                enclosing_type.values.append(value_def)
            else:
                stk.append({'meta_type': die})
                pass
            pass
        elif tip_tag() == MT_subprogram:
            attr_value = parse_attr(line)
            if not attr_value:
                continue
            attr, value = attr_value
            if attr == 'DW_AT_name':
                subp = stk[-1]
                name = fly_name(get_name(value))
                subp.name = name
                #print(' ' * len(stk), attr, get_name(value))
            elif attr == 'DW_AT_linkage_name':
                subp = stk[-1]
                name = fly_name(get_name(value))
                subp.linkage_name = name
            elif attr == 'DW_AT_abstract_origin':
                subp = stk[-1]
                abstract_origin = parse_abstract_origin(value)
                subp.origin = int(abstract_origin, 16)
            elif attr == 'DW_AT_specification':
                subp = stk[-1]
                specification = parse_abstract_origin(value)
                subp.specification = int(specification, 16)
                pass
            pass
        elif tip_tag() in call_site_tags:
            attr_value = parse_attr(line)
            if attr_value:
                attr, value = attr_value
                if attr in origin_attrs:
                    abstract_origin = parse_abstract_origin(value)
                    if abstract_origin:
                        enclosing_caller = find_enclosing_caller(stk)
                        if tip_tag() == MT_inlined_subroutine:
                            subp = stk[-1]
                            subp.origin = int(abstract_origin, 16)
                            pass
                        if not enclosing_caller:
                            print('no enclosing caller')
                            pprint(stk)
                            raise 'no enclosing caller'
                        abstract_origin = int(abstract_origin, 16)
                        if abstract_origin not in enclosing_caller.calls:
                            enclosing_caller.calls.append(abstract_origin)
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
                _type.name = name
            elif attr == 'DW_AT_linkage__name':
                name = fly_name(get_name(value))
                _type.linkage_name = name
            elif attr == 'DW_AT_type':
                _type.type = int(parse_addr_value(value), 16)
            elif attr == 'DW_AT_declaration':
                _type.declaration = True
                pass
            pass
        elif tip_tag() == MT_member:
            attr_value = parse_attr(line)
            if not attr_value:
                continue
            attr, value = attr_value
            member = find_enclosing_type(stk).members[-1]
            if attr == 'DW_AT_name':
                name = fly_name(get_name(value))
                member.name = name
            elif attr == 'DW_AT_linkage_name':
                name = fly_name(get_name(value))
                member.linkage_name = name
            elif attr == 'DW_AT_type':
                member.type = int(parse_addr_value(value), 16)
            elif attr == 'DW_AT_data_member_location':
                member.offset = int(value, 16)
            elif attr == 'DW_AT_external':
                member.external = True
                pass
            pass
        elif tip_tag() == 'DW_TAG_enumerator':
            attr_value = parse_attr(line)
            if not attr_value:
                continue
            attr, value = attr_value
            if attr == 'DW_AT_name':
                name = fly_name(get_name(value))
                find_enclosing_type(stk).values[-1].name = name
            elif attr == 'DW_AT_linkage_name':
                name = fly_name(get_name(value))
                find_enclosing_type(stk).values[-1].linkage_name = name
            elif attr == 'DW_AT_const_value':
                if value.strip().startswith('0x'):
                    value = int(value, 16)
                else:
                    value = int(value)
                    pass
                find_enclosing_type(stk).values[-1].value = value
                pass
            pass
        elif tip_tag() == 'DW_TAG_formal_parameter':
            if not isinstance(stk[-2], TypeInfo) or stk[-2].meta_type != MT_subroutine_type:
                continue
            attr_value = parse_attr(line)
            if not attr_value:
                continue
            attr, value = attr_value
            if attr == 'DW_AT_type':
                type_addr = int(parse_addr_value(value), 16)
                find_enclosing_type(stk).params.append(type_addr)
                pass
            pass
        pass

    subprograms.update((subp.addr, subp) for subp in subprograms_lst)
    types.update((_type.addr, _type) for _type in types_lst)

    for subp in subprograms.values():
        if not is_original(subp):
            origin = subprograms[get_real_addr(subp.origin)]
            for call in subp.calls:
                if call in origin.calls:
                    continue
                origin.calls.append(call)
                pass
            pass
        else:
            if subp.name == '<unknown>':
                subp.name += hex(subp.addr)[2:]
                pass
            pass
        pass
    for subp in subprograms_lst:
        if (not is_original(subp)) and \
           subp.meta_type == MT_inlined_subroutine:
            del subprograms[subp.addr]
            pass
        pass
    return subprograms, types

def make_signature(_type, types):
    if _type.meta_type == MT_placeholder:
        return get_symbol_name(_type)
    if _type.meta_type == MT_base:
        return get_symbol_name(_type)
    if _type.meta_type == MT_unspecified:
        return get_symbol_name(_type)
    if _type.meta_type in ptr_tags:
        if types[_type.type].meta_type == MT_placeholder:
            return '<pointer>:' + get_symbol_name(types[_type.type])
        return '<pointer>:' + hex(_type.type)
    sig = MT_table_rev[_type.meta_type] + ' ' + get_symbol_name(_type)
    if _type.type >= 0:
        sig += ' ' + hex(_type.type)
    if _type.members:
        sig += ' {'
        sig += ','.join([get_symbol_name(member) + ':' + hex(member.type)
                         for member in _type.members])
        sig += '}'
    if _type.values:
        sig += ' {'
        sig += ','.join([get_symbol_name(value) + ':' + str(value.value)
                         for value in _type.values])
        sig += '}'
    if _type.params:
        sig += '('
        sig += ','.join([hex(p) for p in _type.params])
        sig += ')'
        pass
    return sig

def make_sig_recur(_type, types, lvl=0):
    if lvl == 100:
        raise 'too deep'
    if _type.meta_type == MT_placeholder:
        return get_symbol_name(_type)
    if _type.meta_type == MT_base:
        return get_symbol_name(_type)
    if _type.meta_type == MT_unspecified:
        return get_symbol_name(_type)
    if _type.declaration:
        sig = MT_table_rev[_type.meta_type] + '+' + get_symbol_name(_type)
    else:
        sig = MT_table_rev[_type.meta_type] + ' ' + get_symbol_name(_type)
        pass
    if _type.type >= 0:
        sig += ' ' + make_sig_recur(types[_type.type], types, lvl+1)
    if _type.members:
        sig += ' {'
        sig += ','.join([get_symbol_name(member) + ':' +
                         make_sig_recur(types[member.type], types, lvl+1)
                         for member in _type.members])
        sig += '}'
    if _type.values:
        sig += ' {'
        sig += ','.join([get_symbol_name(value) + ':' + str(value.value)
                         for value in _type.values])
        sig += '}'
    if _type.params:
        sig += '('
        sig += ','.join([make_sig_recur(types[param], types, lvl+1)
                         for param in _type.params])
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
                if pop_cnt % 10000 == 0:
                    print('.', end='', flush=True)
                    pass
                pass
            pass
        # 2.2. If the type is marked as visited and with same start
        #      addr, skip it.
        if _type.visited >= 0 and _type.visited != start_addr:
            continue
        # 2.3. Mark the type as visited.
        _type.visited = start_addr
        # 2.4. If the type is in the list of visited types,
        #      replace a pointer type with a placeholder type to break
        #      the circular reference.
        if _type.addr in visited_set:
            path_lst = []
            while isinstance(visited[0], list):
                path_lst.append(visited[1:])
                visited = visited[0]
                pass
            path_lst.append(visited)
            path_lst.reverse()
            visited = list(itertools.chain(*path_lst))
            circular_path = visited[visited.index(_type.addr):]
            break_circular_path(circular_path, types, placeholder_names)
            continue
        visited_set.add(_type.addr)
        visited.append(_type.addr)
        if len(visited) >= 1024:
            visisted = [visited]
            pass
        # 2.5. Repeat for each member of the type.
        if _type.members:
            for member in _type.members:
                # 2.5.1. Creat a task to process the member type. Add the
                #        current type to the list of visited types of the
                #        new task.
                if member.type < 0:
                    print(_type)
                    pass
                if _type.meta_type != MT_union and member.offset < 0:
                    continue
                tasks.append((types[member.type], visited.copy(), visited_set.copy(), start_addr))
                pass
            pass
        if _type.type >= 0:
            tasks.append((types[_type.type], visited.copy(), visited_set.copy(), start_addr))
            pass
        if _type.params:
            for param in _type.params:
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
        if _type.meta_type in ptr_tags and \
           get_symbol_name(types[_type.type]) != '<unknown>':
            if types[_type.type].meta_type == MT_placeholder:
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
    ptrs.sort(key=lambda ptr: get_symbol_name(types[ptr.type]))
    # 3. Replace the pointed type of the first pointer type in the list
    #    with a placeholder type.
    ptr = ptrs[0]
    placeholder_names.add(get_symbol_name(types[ptr.type]))
    ptr.type = create_placeholder(ptr.type, types)
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
        if _type.meta_type not in ptr_tags:
            continue
        pointed_type = types[_type.type]
        if get_symbol_name(pointed_type) in placeholder_names:
            _type.type = create_placeholder(_type.type, types)
            return True
        pass
    return False

# Create a placholders for each pointer type pointing to a
# non-placholder type but with a name in the set of placholder names.
def create_placeholders(types, placeholder_names):
    for _type in list(types.values()):
        if _type.meta_type not in ptr_tags:
            continue
        pointed_type = types[_type.type]
        if get_symbol_name(pointed_type) in placeholder_names:
            _type.type = create_placeholder(_type.type, types)
            pass
        pass
    pass

PLACEHOLDER_FLAG = 0x80000000

def create_placeholder(addr, types):
    real_type = types[addr]
    placeholder_addr = addr | PLACEHOLDER_FLAG
    if placeholder_addr in types:
        return placeholder_addr
    placeholder = TypeInfo(placeholder_addr, MT_placeholder)
    placeholder.name = '<placeholder>:' + get_symbol_name(real_type)
    placeholder.real_type = addr
    types[placeholder_addr] = placeholder
    return placeholder_addr

transit_tags = (MT_const, MT_volatile, MT_restrict)

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
        if _type.meta_type not in transit_tags:
            continue
        processing = _type
        # 1.1. Initialize the new name as an empty string.
        new_name = ''
        # 1.2. Repeatly follow the 'type' field until a type with a name is
        #      found or a non-transit type is found.
        while _type.meta_type in transit_tags:
            # 1.2.1. If a type with a name is found, skip it.
            if get_symbol_name(_type) != '<unknown>':
                break
            # 1.2.1. Append the 'meta_type' to the new name.
            new_name = new_name + ' ' + MT_table_rev[_type.meta_type]
            # 1.2.2. Follow the 'type' field.
            _type = types[_type.type]
            pass
        # 1.3. If the name of the latest type is empty, skip the type.
        if not get_symbol_name(_type) or get_symbol_name(_type) == '<unknown>':
            continue
        # 1.4. Append the name of the type found in the 1.2 step to the new name.
        new_name = new_name + ' ' + get_symbol_name(_type)
        # 1.5. Set the 'name' field of the processing type to the new name.
        processing.name = new_name.strip()
        pass
    # 2. Stop.
    pass

# Dump the tree rooted at the given type.
def dump_tree(_type, types, indent=0):
    print(' ' * indent + get_symbol_name(_type) + '@' + _type.addr + ' ' + _type.meta_type + '\tsig: ' + make_signature(_type, types))
    for member in _type.members:
        dump_tree(types[member.type], types, indent + 2)
        pass
    if _type.type >= 0:
        dump_tree(types[_type.type], types, indent + 2)
        pass
    for param in _type.params:
        dump_tree(types[param], types, indent + 2)
        pass
    pass

def merge_types(subprograms, types, context):
    choosed_types = context.setdefault('choosed_types', {})
    type_merge_sets = context.setdefault('type_merge_sets', {})

    for _type in types.values():
        if _type.meta_type in (MT_base, MT_unspecified):
            if get_symbol_name(_type) in choosed_types:
                _type.replaced_by = choosed_types[get_symbol_name(_type)].addr
            else:
                choosed_types[get_symbol_name(_type)] = _type
                _type.choosed = True
                pass
            pass
        elif _type.meta_type == MT_placeholder:
            _type.choosed = True
            pass
        pass
    replacing_cnt = 1
    choosing_cnt = 1
    rounds = 0
    while (replacing_cnt + choosing_cnt) > 0:
        replacing_cnt = 0
        choosing_cnt = 0
        for _type in types.values():
            if _type.replaced_by >= 0:
                continue
            if _type.choosed and _type.addr not in type_merge_sets:
                continue

            choosed_cnt = 0
            should_choosed = 0
            if _type.type >= 0:
                backing = types[_type.type]
                if backing.replaced_by >= 0:
                    _type.type = backing.replaced_by
                    replacing_cnt += 1
                    pass
                backing = types[_type.type]
                if backing.choosed:
                    choosed_cnt += 1
                    pass
                should_choosed += 1
                pass
            if _type.members:
                members = _type.members
                for i in range(len(members)):
                    member = members[i]
                    member_backing = types[member.type]
                    if member_backing.replaced_by >= 0:
                        member.type = member_backing.replaced_by
                        replacing_cnt += 1
                        pass
                    member_backing = types[member.type]
                    if member_backing.choosed:
                        choosed_cnt += 1
                        pass
                    pass
                should_choosed += len(members)
                pass
            if _type.params:
                params = _type.params
                for i in range(len(params)):
                    param = params[i]
                    param_backing = types[param]
                    if param_backing.replaced_by >= 0:
                        params[i] = param_backing.replaced_by
                        replacing_cnt += 1
                        pass
                    param_backing = types[param]
                    if param_backing.choosed:
                        choosed_cnt += 1
                        pass
                    pass
                should_choosed += len(params)
                pass

            if choosed_cnt == should_choosed and not _type.choosed:
                sig = make_signature(_type, types)
                if sig in choosed_types:
                    _type.replaced_by = choosed_types[sig].addr
                    replacing_cnt += 1
                else:
                    choosed_types[sig] = _type
                    _type.choosed = True
                    choosing_cnt += 1
                    pass
                pass
            pass
        rounds += 1
        #print('   - rounds', rounds, 'replacing_cnt', replacing_cnt, 'choosing_cnt', choosing_cnt)
        pass
    pass

def dump_types(subprograms, types, context):
    # For debugging
    pass

def handle_placeholder_replacement(subprograms, types, context):
    # Handle replaced real types of placeholders.
    for _type in types.values():
        if _type.meta_type != MT_placeholder:
            continue
        real_type = types[_type.real_type]
        if real_type.replaced_by >= 0:
            _type.real_type = real_type.replaced_by
            pass
        pass
    pass

def remove_replaced_types(subprograms, types, context):
    # Remove replaced types and placeholders
    non_choosed = 0
    for addr in list(types.keys()):
        if types[addr].replaced_by >= 0:
            if types[addr].choosed:
                print('replaced choosed type', types[addr])
                pass
            del types[addr]
            pass
        elif not types[addr].choosed:
            if non_choosed < 3:
                print('non choosed types:')
                print(types[addr])
                print('... and more')
                pass
            non_choosed += 1
            pass
        pass
    print(' non_choosed', non_choosed, end='')
    pass

def init_merge_set_of_types_with_placeholders(subprograms, types, context):
    placeholder_names = context['placeholder_names']
    merge_sets = dict([(name, set()) for name in placeholder_names])
    type_merge_sets = dict()
    # For each type with a name in placeholder_names.
    for _type in types.values():
        name = get_symbol_name(_type)
        if name not in placeholder_names:
            continue
        # Add the type to the merge set of the name.
        merge_sets[name].add(_type.addr)
        type_merge_sets[_type.addr] = merge_sets[name]
        pass

    context['merge_sets'] = merge_sets.values()
    print(': merge_sets', len(merge_sets), end='')
    context['type_merge_sets'] = type_merge_sets
    pass

# Divide a marge set to subsets of same signature.
def divide_merge_set_sig(merge_set, type_merge_sets, types):
    sigs = dict()
    for addr in merge_set:
        _type = types[addr]
        sig = make_sig_recur(_type, types)
        if sig not in sigs:
            sigs[sig] = set()
            pass
        sigs[sig].add(addr)
        type_merge_sets[_type.addr] = sigs[sig]
        pass
    return sigs.values()

# Divide each merge set to subsets of same signature.
def divide_merge_sets_sig(subprograms, types, context):
    merge_sets = context['merge_sets']
    type_merge_sets = context['type_merge_sets']
    new_merge_sets = []
    for merge_set in merge_sets:
        sigs = divide_merge_set_sig(merge_set, type_merge_sets, types)
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
def divide_merge_set_dep(merge_set, type_merge_sets, types):
    deps = dict()
    for addr in merge_set:
        _type = types[addr]
        dep_sets = find_dependent_merge_sets(_type, type_merge_sets, types)
        dep = tuple((id(dep_set) for dep_set in dep_sets))
        if dep not in deps:
            deps[dep] = set()
            pass
        deps[dep].add(addr)
        type_merge_sets[_type.addr] = deps[dep]
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
def find_dependent_merge_sets(_type, type_merge_sets, types):
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
        if task.meta_type == MT_placeholder:
            dep_sets.append(type_merge_sets[types[task.real_type].addr])
            continue
        # 2.3. If the task is not a placeholder, add the tasks of the
        #      attributes of the task to the list.
        #      2.3.1. Add the task of the 'type' attribute if it exists.
        if task.type >= 0:
            tasks.append(types[task.type])
            pass
        #      2.3.2. Add the tasks of the 'members' attribute if it
        #             exists.
        if task.members:
            for member in task.members:
                tasks.append(types[member.type])
                pass
            pass
        #      2.3.3. Add the tasks of the 'params' attribute if it
        #             exists.
        if task.params:
            for param in task.params:
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
    type_merge_sets = context['type_merge_sets']
    while True:
        print('.', end='', flush=True)
        new_merge_sets = []
        for merge_set in merge_sets:
            subsets = divide_merge_set_dep(merge_set, type_merge_sets, types)
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
    rep_type.choosed = True
    # Replace all types in the merge set with the representative type.
    for addr in merge_set:
        if addr == rep_type.addr:
            continue
        _type = types[addr]
        _type.replaced_by = rep_type.addr
        pass
    pass

def remove_external_members(subprograms, types, context):
    for _type in types.values():
        if not _type.members:
            continue
        for i in range(len(_type.members) - 1, -1, -1):
            if _type.members[i].external:
                del _type.members[i]
                pass
            pass
        pass
    pass

def borrow_name_from_specification(subprograms, types, context):
    for subp in subprograms.values():
        if subp.specification < 0:
            continue
        spec = subprograms[subp.specification]
        if get_symbol_name(subp).startswith('<unknown>'):
            subp.name = get_symbol_name(spec)
            pass
        pass
    pass

def redirect_calls_to_origin(subprograms, types, context):
    for caller in subprograms.values():
        if not caller.calls:
            continue
        for i, callee in enumerate(caller.calls):
            while subprograms[callee].origin >= 0:
                callee = subprograms[callee].origin
                caller.calls[i] = callee
                pass
            pass
        pass
    pass

def set_call_names(subprograms, types, context):
    for subp in subprograms.values():
        if not subp.calls:
            continue
        if not is_original(subp):
            continue
        subp.call_names = [get_symbol_name(subprograms[callee])
                           for callee in set(subp.calls)]
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
