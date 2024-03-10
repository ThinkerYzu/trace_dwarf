#!/usr/bin/env python3
import sqlite3
import sys
import optparse
import os
import time
import itertools
import hashlib
from pprint import pprint
from dataclasses import dataclass, field
from typing import List
from elftools.elf.elffile import ELFFile

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
MT_namespace = 25

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
    'DW_TAG_namespace': MT_namespace,
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
class TypeCommonParam:
    '''Common parameters for all types

    These parameters can be paramters of a function, values of an
    enum, and members of a struct.

    '''
    meta_type: int
    name: str = '<unknown>'
    linkage_name: str = ''
    value: int = -1
    offset: int = -1
    external: bool = False
    pass

@dataclass(slots=True)
class TypeInfo:
    '''Type information'''
    addr: int
    meta_type: int
    id: int = -1
    name: str = '<unknown>'
    linkage_name: str = ''
    declaration: bool = False
    members: bool = False
    values: bool = False
    params: bool = False
    comm_params: List[TypeCommonParam] = field(default_factory=list)
    type: int = -1
    real_type: int = -1
    replaced_by: int = -1
    visited: int = -1
    chosen: bool = False
    to_loop_head: bool = False
    sig: str = ''
    def choose_params(self, members=False, values=False, params=False):
        if int(members) + int(values) + int(params) != 1:
            raise ValueError('Only one of members, values, params can be True')
        if (self.members, self.values, self.params) != (members, values, params) and \
           (self.members, self.values, self.params) != (False, False, False):
            raise ValueError('Params already chosen')
        self.members = members
        self.values = values
        self.params = params
        pass
    pass

@dataclass(slots=True)
class SubpInfo:
    '''Information of a subprogram'''
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

@dataclass(slots=True)
class NSInfo:
    '''Information of a namespace'''
    addr: int
    meta_type: int
    name: str = '<unknown>'
    pass

def find_enclosing_subprog(stk):
    '''Fint the subprogram that enclose the current context'''
    for i in range(len(stk) - 1, -1, -1):
        if isinstance(stk[i], SubpInfo):
            return stk[i]
    return None

def find_enclosing_type(stk):
    '''Fint the type that enclose the current context'''
    for i in range(len(stk) - 1, -1, -1):
        if isinstance(stk[i], TypeInfo) and stk[i].meta_type in type_tags:
            return stk[i]
    return None

class CFDB:
    def __init__(self, conn):
        self.conn = conn
        pass

    def init_schema(self):
        self.conn.execute('create table symbols(id integer primary key asc, name text unique)')
        self.conn.execute('create table calls(caller integer, callee integer)')

        self.conn.execute('create table types(id integer primary key asc, name text, addr integer unique, meta_type text, declaration integer)')
        self.conn.execute('create table members(type_id integer, name text, type integer, offset integer)')
        pass

    def insert_symbols(self, symbols):
        conn = self.conn
        for symbol in symbols:
            try:
                conn.execute('insert into symbols (name) values(?)',
                             (symbol,))
            except sqlite3.IntegrityError:
                #print('symbol %s already exists' % symbol)
                pass
            pass
        pass

    def insert_calls(self, calls):
        conn = self.conn
        for caller, callee in calls:
            conn.execute('insert into calls values(?, ?)',
                         (caller, callee))
            pass
        pass

    def get_symbol_id(self, symbol):
        conn = self.conn
        cur = conn.execute('select id from symbols where name = ?',
                           (symbol,))
        row = cur.fetchone()
        if not row:
            print(symbol)
            pass
        return row[0]

    def persist_subprogram_info(self, subprograms):
        subprograms = [subprogram for subprogram in subprograms.values()
                       if is_original(subprogram)]

        symbols = [get_symbol_name(subprogram)
               for subprogram in subprograms]
        self.insert_symbols(symbols)

        self.commit()

        for subp in subprograms:
            caller = self.get_symbol_id(get_symbol_name(subp))
            calls = [(caller, self.get_symbol_id(callee))
                     for callee in subp.call_names]
            self.insert_calls(calls)
            pass

        self.commit()
        pass

    def persist_types_info(self, types):
        conn = self.conn
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
                for member in type_info.comm_params:
                    conn.execute('insert into members values(?, ?, ?, ?)',
                                 (type_id, get_symbol_name(member),
                                  get_real_type(member.value, types).id,
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
                for i, param in enumerate(type_info.comm_params):
                    conn.execute('insert into members values(?, ?, ?, ?)',
                                 (type_id, str(i),
                                  get_real_type(param.value, types).id,
                                  0))
                    pass
                pass
            pass
        self.commit()
        pass

    def commit(self):
        self.conn.commit()
        pass

    def close(self):
        self.conn.close()
        pass
    pass

def is_original(subprogram):
    return subprogram.origin < 0

def get_symbol_name(symbol):
    if symbol.linkage_name:
        return symbol.linkage_name
    return symbol.name

def get_real_type(addr, types):
    if types[addr].meta_type == MT_placeholder:
        return types[types[addr].real_type]
    return types[addr]

def persist_info(subprograms, types, filename):
    conn = sqlite3.connect(filename)
    db = CFDB(conn)

    db.init_schema()
    db.persist_subprogram_info(subprograms)
    db.persist_types_info(types)

    db.close()
    pass

def prepend_namespace(name, stk):
    for i in range(len(stk) - 1, -1, -1):
        if isinstance(stk[i], TypeInfo) and \
           stk[i].meta_type in (MT_structure, MT_class):
            name = stk[i].name + '::' + name
            break
        if isinstance(stk[i], NSInfo) and \
           stk[i].meta_type == MT_namespace:
            name = stk[i].name + '::' + name
            break
        pass
    return name

name_flyweight = {}
def fly_name(name):
    h = hash(name) & 0xff
    bucket = name_flyweight.setdefault(h, {})
    return bucket.setdefault(name, name)

def parse_die_subprogram(die, subprograms_lst, stk):
    subp = SubpInfo(die.offset, die)

    for attr in die.attributes:
        _attr = die.attributes[attr]
        if attr == 'DW_AT_name':
            name = _attr.value.decode('utf-8')
            subp.name = fly_name(prepend_namespace(name, stk))
        elif attr == 'DW_AT_linkage_name':
            subp.linkage_name = fly_name(_attr.value.decode('utf-8'))
        elif attr == 'DW_AT_abstract_origin':
            subp.origin = _attr.value + die.cu.cu_offset
        elif attr == 'DW_AT_specification':
            subp.specification = _attr.value + die.cu.cu_offset
            pass
        elif attr in origin_attrs:
            origin = _attr.value + die.cu.cu_offset
            subp.origin = origin
            # Need to handle the case that is inside antoher inlined
            enclosing_caller = find_enclosing_subprog(stk)
            if origin not in enclosing_caller.calls:
                enclosing_caller.calls.append(origin)
                pass
            pass
        pass

    subprograms_lst.append(subp)
    if die.has_children:
        stk.append(subp)
        pass
    pass

def parse_die_type(die, types_lst, stk):
    die_tag = MT_table[die.tag]
    _type = TypeInfo(die.offset, die_tag)
    if die_tag in (MT_pointer, MT_const, MT_reference,
                   MT_rvalue_reference, MT_volatile,
                   MT_restrict, MT_ptr_to_member):
        _type.type = 0 # void.addr
    elif die_tag == MT_enumeration:
        _type.type = 0 # void.addr
        pass

    for attr in die.attributes:
        _attr = die.attributes[attr]
        if attr == 'DW_AT_name':
            _type.name = fly_name(prepend_namespace(_attr.value.decode('utf-8'), stk))
        elif attr == 'DW_AT_linkage__name':
            _type.linkage_name = fly_name(_attr.value.decode('utf-8'))
        elif attr == 'DW_AT_type':
            _type.type = _attr.value + die.cu.cu_offset
        elif attr == 'DW_AT_declaration':
            _type.declaration = True
            pass
        pass

    types_lst.append(_type)
    if die.has_children:
        stk.append(_type)
        pass
    pass

def parse_die_member(die, stk):
    member_def = TypeCommonParam(MT_member)
    enclosing_type = find_enclosing_type(stk)
    enclosing_type.choose_params(members=True)
    enclosing_type.comm_params.append(member_def)

    for attr in die.attributes:
        _attr = die.attributes[attr]
        if attr == 'DW_AT_name':
            member_def.name = fly_name(_attr.value.decode('utf-8'))
        elif attr == 'DW_AT_linkage_name':
            member_def.link_age = fly_name(_attr.value.decode('utf-8'))
        elif attr == 'DW_AT_type':
            member_def.value = _attr.value + die.cu.cu_offset
        elif attr == 'DW_AT_data_member_location':
            member_def.offset = _attr.value
        elif attr == 'DW_AT_external':
            member_def.external = True
            pass
        pass

    if die.has_children:
        stk.append(member_def)
        pass
    pass

def parse_die_enumerator(die, stk):
    value_def = TypeCommonParam(MT_enumerator)
    enclosing_type = find_enclosing_type(stk)
    enclosing_type.choose_params(values=True)
    enclosing_type.comm_params.append(value_def)

    for attr in die.attributes:
        _attr = die.attributes[attr]
        if attr == 'DW_AT_name':
            value_def.name = fly_name(_attr.value.decode('utf-8'))
        elif attr == 'DW_AT_linkage_name':
            value_def.linkage_name = fly_name(_attr.value.decode('utf-8'))
        elif attr == 'DW_AT_const_value':
            value_def.value = _attr.value
            pass
        pass

    if die.has_children:
        stk.append(value_def)
        pass
    pass

def parse_die_namespace(die, stk):
    namespace_def = NSInfo(addr, die)

    for attr in die.attributes:
        _attr = die.attributes[attr]
        if attr == 'DW_AT_name':
            namespace_def.name = fly_name(_attr.value.decode('utf-8'))
            pass
        pass

    if die.has_children:
        stk.append(namespace_def)
        pass
    pass

flyweight_tinfo = {}
def flyweight_type(meta_type):
    if meta_type in flyweight_tinfo:
        return flyweight_tinfo[meta_type]
    flyweight_tinfo[meta_type] = {'meta_type': meta_type}
    return flyweight_tinfo[meta_type]

def parse_die_call_site(die, stk):
    enclosing_caller = find_enclosing_subprog(stk)
    for attr in die.attributes:
        _attr = die.attributes[attr]
        if attr in origin_attrs:
            origin = _attr.value + die.cu.cu_offset
            enclosing_caller = find_enclosing_subprog(stk)
            if origin not in enclosing_caller.calls:
                enclosing_caller.calls.append(origin)
                pass
            pass
        pass

    if die.has_children:
        stk.append(flyweight_type(MT_table[die.tag]))
        pass
    pass

def parse_die_formal_parameter(die, stk):
    if not isinstance(stk[-1], TypeInfo) or stk[-1].meta_type != MT_subroutine:
        return

    for attr in die.attributes:
        _attr = die.attributes[attr]
        p = TypeCommonParam(MT_formal_parameter)
        p.value = _attr.value + die.cu.cu_offset
        enclosing = stk[-1]
        enclosing.choose_params(params=True)
        p.name = str(len(enclosing.comm_params))
        enclosing.comm_params.append(p)
        pass

    if die.has_children:
        stk.append(flyweight_type(MT_formal_parameter))
        pass
    pass

def parse_CU(cu, subprograms_lst, types_lst):
    stk = []

    for die in cu.iter_DIEs():
        if not die.tag:
            stk.pop()
            continue
        if die.tag in MT_table:
            die_tag = MT_table[die.tag]
        else:
            die_tag = MT_other
            pass
        if die_tag in subprogram_tags:
            parse_die_subprogram(die, subprograms_lst, stk)
        elif die_tag in type_tags:
            parse_die_type(die, types_lst, stk)
        elif die_tag == MT_member:
            parse_die_member(die, stk)
        elif die_tag == MT_enumerator:
            parse_die_enumerator(die, stk)
        elif die_tag == MT_namespace:
            parse_die_namespace(die, stk)
        elif die_tag in call_site_tags:
            parse_die_call_site(die, stk)
        elif die_tag == MT_formal_parameter:
            parse_die_formal_parameter(die, stk)
        elif die.has_children:
            stk.append(flyweight_type(die_tag))
            pass
        pass

    assert not stk
    pass

def parse_DIEs(fo):
    from collections import deque
    subprograms = {}
    subprograms_lst = deque()
    void = TypeInfo(0, MT_base)
    void.name = 'void'
    types = {0: void}
    types_lst = deque()

    elffile = ELFFile(fo)
    if not elffile.has_dwarf_info():
        print('no dwarf info')
        return
    dwarfinfo = elffile.get_dwarf_info()
    if dwarfinfo.skip_cache:
        dwarfinfo.skip_cache()
        pass
    for cu in dwarfinfo.iter_CUs():
        parse_CU(cu, subprograms_lst, types_lst)
        pass

    subprograms.fromkeys([subprog.addr for subprog in subprograms_lst])
    subprograms.update((subprog.addr, subprog) for subprog in subprograms_lst)
    types.fromkeys([t.addr for t in types_lst])
    types.update((type.addr, type) for type in types_lst)

    def get_real_addr(addr):
        while addr in subprograms:
            if not is_original(subprograms[addr]):
                addr = subprograms[addr].origin
                continue
            break
        return addr

    for subp in subprograms_lst:
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
        sig += ','.join([get_symbol_name(member) + ':' + hex(member.value)
                         for member in _type.comm_params])
        sig += '}'
    if _type.values:
        sig += ' {'
        sig += ','.join([get_symbol_name(value) + ':' + str(value.value)
                         for value in _type.comm_params])
        sig += '}'
    if _type.params:
        sig += '('
        sig += ','.join([hex(p.value) for p in _type.comm_params])
        sig += ')'
        pass
    return sig

def make_sig_recur_(_type, types, lvl=0):
    if _type.sig:
        return _type.sig

    if lvl == 200:
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
        sig += ' ' + make_sig_recur_(types[_type.type], types, lvl+1)
    if _type.members:
        sig += ' {'
        sig += ','.join([get_symbol_name(member) + ':' +
                         make_sig_recur_(types[member.value], types, lvl+1)
                         for member in _type.comm_params])
        sig += '}'
    if _type.values:
        sig += ' {'
        sig += ','.join([get_symbol_name(value) + ':' + str(value.value)
                         for value in _type.comm_params])
        sig += '}'
    if _type.params:
        sig += '('
        sig += ','.join([make_sig_recur_(types[param.value], types, lvl+1)
                         for param in _type.comm_params])
        sig += ')'
        pass

    sig = hashlib.sha256(sig.encode('utf-8')).hexdigest()
    _type.sig = sig

    return sig

def make_sig_recur(_type, types):
    sig = make_sig_recur_(_type, types)
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
#    2.3. If the type has been visited from the current start addr,
#         replace a pointer type with a placeholder type to break
#         the circular reference.
#    2.4. Mark the type as visited.
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
    tasks = []
    # 2. Repeat until all tasks are done:
    pop_cnt = 0
    while True:
        if not tasks:
            try:
                next_start_addr = next(tpiter)
                tasks.append((types[next_start_addr], [], next_start_addr))
            except StopIteration:
                break
            else:
                pop_cnt += 1
                if pop_cnt % 10000 == 0:
                    print('.', end='', flush=True)
                    pass
                pass
            pass
        # 2.1. Pop a task from the list.
        _type, visited, start_addr = tasks.pop()
        # 2.2. If the type is marked as visited and with same start
        #      addr, skip it.
        if _type.visited >= 0 and _type.visited != start_addr:
            continue
        # 2.3. If the type has been visited from the current start addr,
        #      replace a pointer type with a placeholder type to break
        #      the circular reference.
        if _type.visited == start_addr:
            path_lst = []
            while isinstance(visited[0], list):
                path_lst.append(visited[1:])
                visited = visited[0]
                pass
            path_lst.append(visited)
            path_lst.reverse()
            visited = list(itertools.chain(*path_lst))
            try:
                circular_path = visited[visited.index(_type.addr):]
            except ValueError:
                if not _type.to_loop_head:
                    continue
                pass
            else:
                break_circular_path(circular_path, types, placeholder_names)
                continue
            pass
        # 2.4. Mark the type as visited.
        _type.visited = start_addr

        visited.append(_type.addr)
        if len(visited) >= 1024:
            visited = [visited]
            pass
        # 2.5. Repeat for each member of the type.
        if _type.members:
            for member in _type.comm_params:
                # 2.5.1. Creat a task to process the member type. Add the
                #        current type to the list of visited types of the
                #        new task.
                if member.value < 0:
                    print(_type)
                    pass
                tasks.append((types[member.value], visited.copy(), start_addr))
                pass
            pass
        if _type.type >= 0:
            tasks.append((types[_type.type], visited.copy(), start_addr))
            pass
        if _type.params:
            for param in _type.comm_params:
                tasks.append((types[param.value], visited.copy(), start_addr))
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
# 2. Replace the pointed type of the last pointer type in the list
#    with a placeholder type.  It make sure we break as many furture
#    loops as possible.
# 3. Mark all types following the last pointer type in the list as
#    to_loop_head.
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
            ptrs.append(_type)
            pass
        pass
    if not ptrs:
        print('No pointer type found in the circular path')
        print([types[addr] for addr in circular_path])
        pass
    # 2. Replace the pointed type of the last pointer type in the list
    #    with a placeholder type.  It make sure we break as many
    #    furture loops as possible.
    ptr = ptrs[-1]
    placeholder_names.add(get_symbol_name(types[ptr.type]))
    ptr.type = create_placeholder(ptr.type, types)
    # 3. Mark all types following the last pointer type in the list as
    #    to_loop_head.
    for addr in circular_path[circular_path.index(ptr.addr) + 1:]:
        types[addr].to_loop_head = True
        pass
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
            if pointed_type.meta_type != MT_placeholder:
                _type.type = create_placeholder(_type.type, types)
                pass
            for addr in circular_path[circular_path.index(_type.addr) + 1:]:
                types[addr].to_loop_head = True
                pass
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
        if pointed_type.meta_type != MT_placeholder and \
           get_symbol_name(pointed_type) in placeholder_names:
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

def check_circular(subprograms, types, context):
    for _type in types.values():
        _type.visited = -1
        pass
    tasks = []
    typeiter = iter(types.values())
    while True:
        if not tasks:
            try:
                tasks.append((next(typeiter), []))
            except StopIteration:
                break
            pass
        _type, visited = tasks.pop()
        if _type.visited >= 0:
            if _type.addr in visited:
                raise Exception(f'circular type {get_symbol_name(_type)}')
            continue
        _type.visited = 1
        visited.append(_type.addr)

        # 2.5. Repeat for each member of the type.
        if _type.members:
            for member in _type.comm_params:
                # 2.5.1. Creat a task to process the member type. Add the
                #        current type to the list of visited types of the
                #        new task.
                if member.value < 0:
                    print(_type)
                    pass
                tasks.append((types[member.value], visited.copy()))
                pass
            pass
        if _type.type >= 0:
            tasks.append((types[_type.type], visited.copy()))
            pass
        if _type.params:
            for param in _type.comm_params:
                tasks.append((types[param.value], visited.copy()))
                pass
            pass
        pass
    pass

transit_tags = (MT_const, MT_volatile, MT_restrict)
transit_sym_str = {MT_const: 'const',
                   MT_volatile: 'volatile',
                   MT_restrict: 'restrict'}

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
            new_name = new_name + ' ' + transit_sym_str[_type.meta_type]
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
        processing.linkage_name = processing.name
        pass
    # 2. Stop.
    pass

# Dump the tree rooted at the given type.
def dump_tree(_type, types, indent=0):
    print(' ' * indent + get_symbol_name(_type) + '@' + _type.addr + ' ' + _type.meta_type + '\tsig: ' + make_signature(_type, types))
    if _type.members:
        for member in _type.comm_params:
            dump_tree(types[member.value], types, indent + 2)
            pass
        pass
    if _type.type >= 0:
        dump_tree(types[_type.type], types, indent + 2)
        pass
    if _type.params:
        for param in _type.comm_params:
            dump_tree(types[param.value], types, indent + 2)
            pass
        pass
    pass

def merge_types(subprograms, types, context):
    chosen_types = {}
    type_merge_sets = context.setdefault('type_merge_sets', {})

    for _type in types.values():
        if _type.chosen or _type.replaced_by >= 0:
            continue
        if _type.meta_type in (MT_base, MT_unspecified):
            name = get_symbol_name(_type)
            if name in chosen_types:
                _type.replaced_by = chosen_types[name].addr
            else:
                chosen_types[name] = _type
                _type.chosen = True
                pass
            pass
        elif _type.meta_type == MT_placeholder:
            _type.chosen = True
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
            # If the type is already chosen, skip it.  But if the type
            # is in type_merge_sets, we don't skip it because we can
            # not register it in chosen_types at the beginning of this
            # function.  It is because the signature of the type is
            # still changing.  Its dependencies may be replaced.
            if _type.chosen and _type.addr not in type_merge_sets:
                continue

            chosen_cnt = 0
            should_chosen = 0
            if _type.type >= 0:
                backing = types[_type.type]
                if backing.replaced_by >= 0:
                    _type.type = backing.replaced_by
                    replacing_cnt += 1
                    pass
                backing = types[_type.type]
                if backing.chosen:
                    chosen_cnt += 1
                    pass
                should_chosen += 1
                pass
            if _type.members:
                members = _type.comm_params
                for i in range(len(members)):
                    member = members[i]
                    member_backing = types[member.value]
                    if member_backing.replaced_by >= 0:
                        member.value = member_backing.replaced_by
                        replacing_cnt += 1
                        pass
                    member_backing = types[member.value]
                    if member_backing.chosen:
                        chosen_cnt += 1
                        pass
                    pass
                should_chosen += len(members)
                pass
            if _type.params:
                params = _type.comm_params
                for i in range(len(params)):
                    param = params[i].value
                    param_backing = types[param]
                    if param_backing.replaced_by >= 0:
                        params[i].value = param_backing.replaced_by
                        replacing_cnt += 1
                        pass
                    param_backing = types[param]
                    if param_backing.chosen:
                        chosen_cnt += 1
                        pass
                    pass
                should_chosen += len(params)
                pass

            if chosen_cnt == should_chosen and not _type.chosen:
                sig = make_signature(_type, types)
                if sig in chosen_types:
                    _type.replaced_by = chosen_types[sig].addr
                    replacing_cnt += 1
                else:
                    chosen_types[sig] = _type
                    _type.chosen = True
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
            assert types[_type.real_type].chosen
            pass
        pass
    pass

def remove_replaced_types(subprograms, types, context):
    # Remove replaced types and placeholders
    non_chosen = 0
    for addr in list(types.keys()):
        if types[addr].replaced_by >= 0:
            if types[addr].chosen:
                print('replaced chosen type', types[addr])
                pass
            del types[addr]
            pass
        elif not types[addr].chosen:
            if non_chosen == 0:
                print('non chosen types:')
                pass
            if non_chosen < 3:
                print(types[addr])
                pass
            if non_chosen == 3:
                print('... and more')
            non_chosen += 1
            pass
        pass
    print(' non_chosen', non_chosen, end='')
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
        type_merge_sets[_type.addr] = id(merge_sets[name])
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
        type_merge_sets[_type.addr] = id(sigs[sig])
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
        dep = hash(tuple(dep_sets))
        if dep not in deps:
            deps[dep] = set()
            pass
        deps[dep].add(addr)
        pass
    if len(deps) > 1:
        cnt = 0
        for dep, addrs in deps.items():
            for addr in addrs:
                _type = types[addr]
                if get_symbol_name(_type) == 'pnp_driver':
                    cnt += 1
                    break
                pass
            pass
        if cnt >= 2:
            print('deps', deps, cnt)
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
            if task.real_type not in types:
                print('placeholder real_type doesnot exist')
                pass
            elif task.real_type not in type_merge_sets:
                print('placeholder real_type doesnot have merge_set')
                pass
            dep_sets.append(type_merge_sets[task.real_type])
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
            for member in task.comm_params:
                tasks.append(types[member.value])
                pass
            pass
        #      2.3.3. Add the tasks of the 'params' attribute if it
        #             exists.
        if task.params:
            for param in task.comm_params:
                tasks.append(types[param.value])
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
        # update type_merge_sets
        for merge_set in merge_sets:
            for addr in merge_set:
                type_merge_sets[addr] = id(merge_set)
                pass
            pass
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
    rep_type.chosen = True
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
        for i in range(len(_type.comm_params) - 1, -1, -1):
            if _type.comm_params[i].external:
                del _type.comm_params[i]
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
                pass
            caller.calls[i] = callee
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

# Replace references to declarations with definitions.
#
# For every reference pointing to a declaration type, find a
# definition and point to it instead.
#
# A reference is a member, parameter, or type of a type.  A definition
# of a declaration is a type that is not a declaration and have the
# same meta type and name.
def replace_declaration_refs(subprograms, types, context):
    # Collect definition types to create a map from meta type and name
    # pairs to types.
    def_types = {}
    is_declaration = lambda _type: _type.declaration
    for _type in types.values():
        if is_declaration(_type):
            continue
        key = (_type.meta_type, get_symbol_name(_type))
        if key not in def_types:
            # We only need one definition type for each meta type and
            # name pair.
            def_types[key] = _type
            pass
        pass
    # Replace references to declarations with definitions.
    #
    # The visited references should be labeled with a non-negative
    # visited value.  The visited value is used to remove unused
    # declaration types later.
    for _type in types.values():
        if is_declaration(_type):
            continue
        replace_declaration_refs_type(_type, def_types, types)
        pass

    # Remove unused declaration types which is not pointed to by any
    # definition type from 'types'.  The visited value is used to
    # determine if a declaration type is pointed to by a definition
    # type. If the visited value is non-negative, the declaration type
    # is not pointed to by any definition type.
    for _type in list(types.values()):
        if not is_declaration(_type):
            continue
        if _type.visited >= 0:
            del types[_type.addr]
            pass
        pass
    pass

def replace_declaration_refs_type(_type, def_types, types):
    # Replace the type of the type if it is a declaration.
    if _type.type >= 0:
        _type.type = replace_declaration_ref(_type.type, def_types, types)
        pass
    # Replace the members of the type.
    if _type.members:
        for member in _type.comm_params:
            member.value = replace_declaration_ref(member.value, def_types, types)
            pass
        pass
    # Replace the parameters of the type.
    if _type.params:
        for param in _type.comm_params:
            param.value = replace_declaration_ref(param.value, def_types, types)
            pass
        pass
    pass

def replace_declaration_ref(addr, def_types, types):
    _type = types[addr]
    if not _type.declaration:
        return addr
    key = (_type.meta_type, get_symbol_name(_type))
    if key not in def_types:
        return addr
    # Since the declaration type has a definition found, we can remove
    # it from 'types' later by setting the visited value to a
    # non-negative value.
    _type.visited = 1
    return def_types[key].addr

type_process_phases = [
    redirect_calls_to_origin,
    borrow_name_from_specification,
    set_call_names,

    replace_declaration_refs,
    remove_external_members,
    init_transit_type_names,
    break_circular_reference,
    check_circular,
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
    fo = open(filename, 'rb')
    start_time = time.time()
    subprograms, types = parse_DIEs(fo)
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
    tm_delta = time.time() - start_time
    print('Total time: %.2f seconds (%.2f minutes)' % (tm_delta, tm_delta / 60))
    pass
