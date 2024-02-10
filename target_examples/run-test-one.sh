rm test*
rm callgraph.sqlite3
python3 rand_gen.py --c --size 8 --subtrees 3 --drop-max 3 --output test
./compile-ex.sh
