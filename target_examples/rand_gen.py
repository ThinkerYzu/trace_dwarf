import random, sys

# Generate a diagram of random types in the given size.
#
# Each type has a unique name and a list of members.
# These members are point to other types, or to themselves.
#
# This function will reteurn a list of types, each type is a pair of a
# name and a list of members.
#
# @param size The number of types to generate.
# @param fanout The number of members each type can have at most. (at least 1)
def generate_type_diagram(size, fanout):
    if size == 0 or fanout == 0:
        return []

    types = [[] for i in range(size)]
    for i in range(size):
        selected_fanout = random.randint(1, fanout)
        for j in range(selected_fanout):
            selected_type = random.choice(types)
            types[i].append(random.randint(0, size - 1))
            pass
        pass

    lost_types = find_lost_types_internal(types)
    while lost_types:
        connected_types = list(set(range(size)) - set(lost_types))
        src = random.choice(connected_types)
        dst = random.choice(lost_types)
        types[src].append(dst)
        lost_types = find_lost_types_internal(types)
        pass

    ret_types = []
    for i in range(size):
        fields = []
        for j in types[i]:
            fields.append('type_' + str(j))
            pass
        ret_types.append(('type_' + str(i), fields))
        pass

    return ret_types

# Find all types that are not reachable from the first type.
def find_lost_types_internal(types):
    reachable = [False for i in range(len(types))]
    reachable[0] = True
    stack = [0]
    while stack:
        current = stack.pop()
        for i in types[current]:
            if not reachable[i]:
                reachable[i] = True
                stack.append(i)
                pass
            pass
        pass

    return [i for i in range(len(reachable)) if not reachable[i]]

# Work just like find_lost_types_internal, but with the types returned
# by generate_type_diagram.
#
# Return a list of indexes of types that are not reachable from the
# given type.
def find_lost_types(types, start_index=0):
    reachable = [False for i in range(len(types))]
    reachable[start_index] = True
    type2index = {t[0]: i for i, t in enumerate(types)}
    stack = [start_index]
    while stack:
        current = stack.pop()
        for field in types[current][1]:
            if field not in type2index:
                continue
            i = type2index[field]
            if not reachable[i]:
                reachable[i] = True
                stack.append(i)
                pass
            pass
        pass

    return [i for i in range(len(reachable)) if not reachable[i]]

def build_subtree(types, num_subtree, drop_min=1, drop_max=1):
    assert drop_min <= drop_max
    start_indexes = []
    while len(start_indexes) != num_subtree:
        start_indexes = [random.randint(0, len(types) - 1)
                         for i in range(num_subtree)]
        start_indexes = list(set(start_indexes))
        pass
    subtrees = []
    for start_index in start_indexes:
        lost_types = find_lost_types(types, start_index)
        subtree = [types[i]
                   for i in range(len(types))
                   if i not in (lost_types + [start_index])]
        random.shuffle(subtree)
        subtree = [types[start_index]] + subtree
        if drop_min >= len(subtree):
            return

        drop_count = random.randint(drop_min, min(drop_max, len(subtree) - 1))
        subtree = subtree[:-drop_count]
        st_lost_types = find_lost_types(subtree, 0)
        subtree = [subtree[i] for i in range(len(subtree))
                   if i not in st_lost_types]
        subtrees.append(subtree)
        pass

    t_names = set()
    for subtree in subtrees:
        for t in subtree:
            t_names.add(t[0])
            pass
        pass
    if len(t_names) != len(types):
        return

    return subtrees

def print_c_type(type, out):
    print('struct ' + type[0] + ' {', file=out)
    for i, field in enumerate(type[1]):
        print('    struct ' + field + ' *f' + str(i) + '_' + type[0] + '__' + field + ';', file=out)
        pass
    print('};', file=out)
    pass


def print_c_types(types, out=sys.stdout):
    t_names = set([t[0] for t in types])
    for type in types:
        for field in type[1]:
            t_names.add(field)
            pass
    for t_name in t_names:
        print('struct ' + t_name + ';', file=out)
        pass
    print('', file=out)
    for type in types:
        print_c_type(type, out)
        print('', file=out)
        pass
    print('', file=out)
    for type in types:
        print('static void use_{}_(struct {} *a)'.format(type[0], type[0]), file=out)
        print('{}', file=out)
        pass
    print('', file=out)
    print('void use_{}(void *a)'.format(types[0][0]), file=out)
    print('{', file=out)
    for type in types:
        print('    use_{}_(a);'.format(type[0]), file=out)
        pass
    print('}', file=out)
    pass

def print_c_types_main(subtrees, out=sys.stdout):
    print('#include <stdio.h>', file=out)
    print('', file=out)
    for subtree in subtrees:
        print('void use_{}(void *a);'.format(subtree[0][0]), file=out)
        pass
    print('', file=out)
    print('int main()', file=out)
    print('{', file=out)
    for subtree in subtrees:
        print('    use_{}(NULL);'.format(subtree[0][0]), file=out)
        pass
    print('    return 0;', file=out)
    print('}', file=out)

def print_dot(types, out=sys.stdout):
    print('digraph G {', file=out)
    for type in types:
        for field in type[1]:
            print('    ' + type[0] + ' -> ' + field + ';', file=out)
            pass
        pass
    print('}', file=out)
    pass

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Generate a diagram of random types.')
    parser.add_argument('--size', type=int, default=5, help='The number of types to generate.')
    parser.add_argument('--fanout', type=int, default=3, help='The number of members each type can have at most.')
    parser.add_argument('--c', action='store_true', help='Print the types in C syntax.')
    parser.add_argument('--output', type=str, help='The file to output the types.')
    parser.add_argument('--subtrees', type=int, default=1, help='The number of subtrees to generate.')
    parser.add_argument('--drop-min', type=int, default=1, help='The minimum number of types to drop from each subtree.')
    parser.add_argument('--drop-max', type=int, default=1, help='The maximum number of types to drop from each subtree.')
    args = parser.parse_args()

    types = generate_type_diagram(args.size, args.fanout)
    if args.c:
        output_func = print_c_types
        output_main = print_c_types_main
        output_suffix = '.c'
    else:
        output_func = print_dot
        output_main = None
        output_suffix = '.dot'
        pass
    if args.subtrees > 1:
        subtrees = build_subtree(types, 3, 1, 2)
        while not subtrees:
            subtrees = build_subtree(types, 3, 1, 2)
            pass
        for i, subtree in enumerate(subtrees):
            if args.output:
                out = open(args.output + '-' + str(i) + output_suffix, 'w')
            else:
                out = sys.stdout
                pass
            output_func(subtree, out)
            pass
        if output_main:
            out = open(args.output + output_suffix, 'w')
            output_main(subtrees, out)
            pass
        pass
    else:
        output_func(types)
        if output_main:
            output_main([types])
            pass
        pass
    pass

if __name__ == '__main__':
    main()
    pass
