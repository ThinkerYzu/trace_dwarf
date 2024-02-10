#!/usr/bin/bash

# This script is used to create a type diagram of given types in a
# given database generated from a binary.
#
# It use draw-types.py to generate the diagram.
# Usage: ./mkcf.sh <diagram_name> -t <sym1> -t <sym2> ...
#
DIAGGRAM_NAME=$1
shift
if [ -z "$LEVELS" ]; then
    LEVELS=5
fi
if [ -z "$DB" ]; then
    DB=callgraph.sqlite3
fi

draw-types.py -o ${DIAGGRAM_NAME}.dot -n $LEVELS $@ \
                 $(cat types-common) $DB || exit 1
dot -Tpng ${DIAGGRAM_NAME}.dot -o ${DIAGGRAM_NAME}.png
