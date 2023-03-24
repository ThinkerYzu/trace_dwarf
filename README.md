TraceDwarf a set of tools to help people to trace function call flows
with DWARF in the binary files.

## Build a Database from DWARF
You need to dump DWARF info to a text file, and parse the file with
mk-dwarf-db.py.

The following lines build a database for Linux kernel.

    objdump --dwarf=info vmlinux > dwarf.data
    mk-dwarf-db.py dwarf.data

It generates a database called callgraph.sqlite3.  Now, you can use
this database to generate callflow graphs.  For sure, you should
compile your files with DWARF information.

## Generate Callflow Graphs
draw-callflow.py generate dot file to describe the callflow of given
function names. You can give more than one function names to find all
its callers or the callees called by it. It will follow calls to a
given level.

For example,

     draw-callflow.py -o ip6_route_input.dot \
         -n 10 \
         -f -fib6_table_lookup \
         -f +fib6_table_lookup \
         -x NF_HOOK \
         -x ip6_route_add \
         -x find_match \
         -x kfree \
         -x spin_lock_bh \
         -x spin_unlock_bh \
         callgraph.sqlite3

This example will generate a dot file to describe callflows of
fib6_table_lookup. '-fib6_table_lookup' asks the tool to trace callers
while '+fib6_table_lookup' asks the tool to trace callees.

Some functions are not critical and anony so that we may want to
ignore them. With '-x' we do follow calls crossing NF_HOOK,
ip6_route_add, ... and spin_unlock_bh.

The following command will generate a PNG file from the dot file.

    dot -Tpng ip6_route_input.dot > ip6_route_input.png

## Prerequisites

 - python
 - sqlite3
 - objdump (binutils)
 - dot (graphviz)

## TODOs
Adding information of types to database is a good idea.  With that,
people can trace the relationships of a set of types.  Function
signatures and types of variables are also useful. With these
information, user can select a set of functions according type
constrains. For example, find out all functions using a specific type.


## Warning

This tools parses the output of objdump. The format may change.  And,
DWARF is too flexible so that TAG and ATTRIBUTES may changes from one
platform to another.  It may also vary with different versions of
toolchains.

