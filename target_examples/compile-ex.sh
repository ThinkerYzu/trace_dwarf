gcc -o test -gdwarf test*.c
objdump --dwarf=info test > dwarf.data
mk-dwarf-db.py dwarf.data
sqlite3 callgraph.sqlite3 "select count(*) from types where meta_type = 'DW_TAG_structure_type'"

