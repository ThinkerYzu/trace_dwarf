TraceDwarf is a collection of tools designed to assist developers in
tracing function call flows and relationships of data types using
DWARF in binary files.

## Build a Database from DWARF
The first step is to create a database from DWARF in binary files. The
tool being used to build the database is mk-dwarf-db.py.

The lines that follow create a database for the Linux kernel.

    mk-dwarf-db.py vmlinux

It creates a database named callgraph.sqlite3. You can now use this
database to create call flow diagrams. Make sure to compile your files
with DWARF information.

## Generate Callflow Diagram
The draw-callflow.py script generates dot files that describe the call
flow of specified function names. You can provide multiple function
names to discover all the functions that call them or the functions
called by them. The script will trace calls up to a specified depth.

For example,

     draw-callflow.py -o ip6_route_input.dot \
         -n 10 \
         -f ~fib6_table_lookup \
         -f +fib6_table_lookup \
         -x NF_HOOK \
         -x ip6_route_add \
         -x find_match \
         -x kfree \
         -x spin_lock_bh \
         -x spin_unlock_bh \
         callgraph.sqlite3

This example will generate a dot file that describes the call flows of
fib6_table_lookup. '~fib6_table_lookup' instructs the tool to trace
callers, while '+fib6_table_lookup' instructs the tool to trace
callees.

Some functions are not essential, so we may consider ignoring
them. With '-x', we do not follow the calls that cross NF_HOOK,
ip6_route_add... and spin_unlock_bh.

The command below will create a PNG file from the DOT file.

    dot -Tpng ip6_route_input.dot > ip6_route_input.png

## Generate Type Diagram
draw-types.py generates dot files to describe the structure of types
related to the given type names.

For example,

    draw-types.py -o net.dot \
        -n 5 \
        -t +net \
        -x netns_ct \
        -x netns_ipv6 \
        -x netns_mib \
        -x fqdir \
        -x module \
        -x proc_ns_operations \
        -x user_namespace \
        -x netns_sctp \
        -x netns_xfrm \
        -x netns_ipv4 \
        -x dst_ops \
        callgraph.sqlite3

This example will generate a dot file to describe how the `struct net`
utilizes other types. This tool will recursively find types until no
more types are found or until reaching a maximum number of levels,
which in this case is 5. Some types are too complicated and do not
provide much meaning, so we filter them out; such as `netns_ct`,
`netns_ipv6`, and `dst_ops`.

The following command will create a PNG file from the dot file.

    dot -Tpng net.dot > net.png

## Highlights
You can highlight functions or types by using '-L <symbol>' option.
A highlighted function or type will be in red.

## Prerequisites

 - python
 - sqlite3
 - pyelftools
 - dot (graphviz)

## TODOs
Improve the performance of mk-dwarf-db.py.
