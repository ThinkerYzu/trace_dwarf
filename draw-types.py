#!/usr/bin/env python3
#
# Draw a diagram of given types and their dependencies.
#
# Use a database generated by mk-dwarf-db.py as the source of types.
#
# Usage: draw-types.py [-t <type>] [-n <max-levels>]
#                      [-x <exclude-type>] [-X <strict-exclude-type>]
#                      [-o <output-file>]
#                      [-i]
#                      <database>
#
# Schema of the DB
#   create table symbols(id integer primary key asc, name text unique)
#   create table calls(caller integer, callee integer)
#   create table types(id integer primary key asc, name text, \
#                      addr text unique, meta_type text, declaration integer)
#   create table members(type_id integer, name text, \
#                        type integer, offset integer)
import sys
import sqlite3
import argparse

# Return a list of type IDs of a given type name
def get_type_ids(db, name):
    cur = db.cursor()
    cur.execute('select id from types where name = ?', (name,))
    return [row[0] for row in cur]

# Return a list of members of a given type ID.
def get_members(db, type_id):
    cur = db.cursor()
    cur.execute('select * from members where type_id = ?', (type_id,))
    return cur

# Return the type of a given ID.
def get_type(db, type_id):
    cur = db.cursor()
    cur.execute('select * from types where id = ?', (type_id,))
    return cur.fetchone()

# Return a list of type IDs depending on a given type ID.
def get_dependant_ids(db, type_id):
    cur = db.cursor()
    cur.execute('select type_id from members where type = ?', (type_id,))
    return [row[0] for row in cur]

class Member:
    def __init__(self, name, type_id, offset):
        self.name = name
        self.type_id = type_id
        self.offset = offset
        pass
    pass

class Type:
    def __init__(self, db, id):
        self.db = db
        self.id = id
        self.load()
        pass

    def load(self):
        db = self.db
        id = self.id

        row = get_type(db, id)
        self.id = row[0]
        self.name = row[1]
        self.addr = row[2]
        self.meta_type = row[3]
        self.declaration = row[4]
        self.members = []

        cur = get_members(db, id)
        for row in cur:
            member = Member(row[1], row[2], row[3])
            self.members.append(member)
            pass
        cur.close()
        pass

    def get_full_name_slow(self):
        meta_tag = ''
        suffix_tag = ''
        if self.meta_type == 'DW_TAG_structure_type':
            meta_tag = 'struct'
        elif self.meta_type == 'DW_TAG_union_type':
            meta_tag = 'union'
        elif self.meta_type == 'DW_TAG_class_type':
            meta_tag = 'class'
        elif self.meta_type == 'DW_TAG_enumeration_type':
            meta_tag = 'enum'
        elif self.meta_type == 'DW_TAG_typedef':
            meta_tag = 'typedef'
        elif self.meta_type == 'DW_TAG_base_type':
            meta_tag = ''
        elif self.meta_type == 'DW_TAG_pointer_type':
            meta_tag = 'ptr'
        elif self.meta_type == 'DW_TAG_constant_type':
            meta_tag = 'const'
        elif self.meta_type == 'DW_TAG_volatile_type':
            meta_tag = 'volatile'
        elif self.meta_type == 'DW_TAG_array_type':
            suffix_tag = '[]'
        elif self.meta_type == 'DW_TAG_subroutine_type':
            suffix_tag = '()'
        else:
            meta_tag = self.meta_type
            pass
        full_name = ''
        if self.declaration:
            full_name += '+'
            pass
        if meta_tag:
            full_name += meta_tag + ' '
            pass
        if self.name and self.name == '<unknown>':
            self.name = '?'
            pass
        full_name += self.name
        if suffix_tag:
            full_name += suffix_tag
            pass
        return full_name

    def get_full_name(self):
        if hasattr(self, 'full_name'):
            return self.full_name
        full_name = self.get_full_name_slow()
        self.full_name = full_name
        return full_name
    pass

transit_types = [
    'DW_TAG_typedef',
    'DW_TAG_constant_type',
    'DW_TAG_volatile_type',
    'DW_TAG_pointer_type',
    'DW_TAG_array_type',
    ]

def draw_types(db, type_ids, max_levels,
               exclude_types, strict_exclude_types,
               show_id=False):
    tasks = [(Type(db, type_id), to_descendant, 0)
             for type_id, to_descendant in type_ids]
    visited = set()
    has_labels = set()
    while tasks:
        _type, to_descendant, lvl = tasks.pop(0)
        if _type.id in visited:
            continue
        visited.add(_type.id)
        if _type.id not in has_labels:
            if show_id:
                print('"%s" [label="%s@%s"];' % (_type.id, _type.get_full_name(), _type.id))
            else:
                print('  "%s" [label="%s"];' % (_type.id, _type.get_full_name()))
                pass
            has_labels.add(_type.id)
            pass
        if _type.name in exclude_types or ('@' + str(_type.id)) in exclude_types:
            continue
        if lvl > max_levels and max_levels > 0:
            continue
        for member in _type.members:
            member_type = Type(db, member.type_id)
            if (member_type.name in strict_exclude_types) or (('@' + str(member_type.id)) in strict_exclude_types):
                continue
            if _type.meta_type not in transit_types:
                if member_type.meta_type == 'DW_TAG_base_type':
                    continue
                pass
            if member_type.id not in has_labels:
                if show_id:
                    print('"%s" [label="%s@%s"];' % (member_type.id, member_type.get_full_name(), member_type.id))
                else:
                    print('  "%s" [label="%s"];' % (member_type.id, member_type.get_full_name()))
                    pass
                has_labels.add(member_type.id)
                pass
            if _type.meta_type in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
                edge = (_type.id, member_type.id, member.name)
                do_label = True
            else:
                edge = (_type.id, member_type.id)
                do_label = False
                pass
            if edge not in visited:
                if do_label:
                    print('  "%s" -> "%s" [label="%s"];' % (_type.id, member_type.id, member.name))
                else:
                    print('  "%s" -> "%s";' % (_type.id, member_type.id))
                    pass
                visited.add(edge)
                if to_descendant:
                    tasks.append((member_type, to_descendant, lvl + 1))
                    pass
                pass
            pass
        if not to_descendant:
            for dependant_id in get_dependant_ids(db, _type.id):
                tasks.append((Type(db, dependant_id), to_descendant, lvl + 1))
                pass
            pass
        pass
    pass

def main():
    parser = argparse.ArgumentParser(description='Draw a diagram of given types and their dependencies.')
    parser.add_argument('db', help='database file')
    parser.add_argument('-t', '--type', help='type name or id to start with', action='append')
    parser.add_argument('-n', '--max-levels', type=int, help='maximum number of levels to draw')
    parser.add_argument('-x', '--exclude-type', action='append', help='type name or id to exclude')
    parser.add_argument('-X', '--strict-exclude-type', action='append', help='type name or id to exclude (not show at all)')
    parser.add_argument('-i', '--show-id', action='store_true', help='show address of types')
    parser.add_argument('-o', '--output-file', help='output file')
    args = parser.parse_args()

    if args.output_file:
        sys.stdout = open(args.output_file, 'w')

    print('digraph G {')
    print('  graph [rankdir=LR];')
    print('  node [shape=record];')

    db = sqlite3.connect(args.db)
    db.row_factory = sqlite3.Row

    # Get the type IDs of the given type names
    type_ids = []
    for type_name in args.type:
        if type_name[0] == '+':
            to_descendant = True
        elif type_name[0] == '~':
            to_descendant = False
        else:
            raise 'Type name must start with + or ~'
            pass
        if type_name[1:].startswith('@'):
            type_id = int(type_name[2:])
            type_ids.append((type_id, to_descendant))
        else:
            type_ids += [(type_id, to_descendant)
                         for type_id in get_type_ids(db, type_name[1:])]
            pass
        pass
    draw_types(db, type_ids, args.max_levels or 5,
               set(args.exclude_type or []),
               set(args.strict_exclude_type or []),
               show_id=args.show_id)

    print('}')
    pass

if __name__ == '__main__':
    main()
    pass
