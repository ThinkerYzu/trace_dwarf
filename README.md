TraceDwarf is a set of tools to help people to trace function call flows
with DWARF in the binary files.

## Build a Database from DWARF
You need to dump DWARF info into a text file and parse the file with
mk-dwarf-db.py.

The following lines build a database for the Linux kernel.

    objdump --dwarf=info vmlinux > dwarf.data
    mk-dwarf-db.py dwarf.data

It generates a database called callgraph.sqlite3.  Now, you can use
this database to create call flow diagrams.  For sure, you should
compile your files with DWARF information.

## Generate Callflow Diagram
draw-callflow.py generates dot files to describe the call flow of
given function names.  You can give more than one function name to
find all its callers or the callees called by it.  It will follow
calls to a given level.

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

This example will generate a dot file to describe call flows of
fib6_table_lookup.  '~fib6_table_lookup' asks the tool to trace callers
while '+fib6_table_lookup' asks this tool to trace callees.

Some functions are not critical and annoying, so we may want to
ignore them.  With '-x', we follow calls crossing NF_HOOK,
ip6_route_add ... and spin_unlock_bh.

The following command will generate a PNG file from the dot file.

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

This example will generate a dot file to describe how `struct net`
uses other types.  This tool will find types recursively until no more
types are found or reach a max number of levels.  Here, it is 5.  Some
types are too complicated and don't mean much.  We filter it out;
likes netns_ct, netns_ipv6, ... and dst_ops.

The following command will create a PNG file from the dot file.

    dot -Tpng net.dot > net.png

## Prerequisites

 - python
 - sqlite3
 - objdump (binutils)
 - dot (graphviz)

## TODOs
Adding information of types to a database is a good idea.  With that,
people can trace the relationships of a set of types.  Function
signatures and types of variables are also useful.  With these
information, user can select a set of functions according type
constrains.  For example, find out all functions using a specific
type.


## Warning

This tools parses the output of objdump.  The format may change.  And,
DWARF is too flexible so that TAG and ATTRIBUTES may changes from one
platform to another.  It may also vary with different versions of
toolchains.

