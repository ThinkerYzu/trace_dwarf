gcc -o test -gdwarf -O test*.c
../../scripts/mk-dwarf-db.py test
sqlite3 callgraph.sqlite3 "select count(*) from types where meta_type = 'DW_TAG_structure_type'"
sqlite3 callgraph.sqlite3 "select count(*) from calls;"

