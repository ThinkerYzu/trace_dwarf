#!/usr/bin/env python3
#
# Draw call flow graph from a database generated by mk-dwarf-db.py.
#
# Usage: draw-callflow.py [-f <+caller|~callee>] [-n <levels>]
#                         [-t <source>:<target>]
#                         [-x <exclude-symbol>]
#                         [-r <removed-symbol>]
#                         [-L <symbol>]
#                         [-o <output-file>] <database>
#
# Options:
#   -f <+caller|-callee>  Follow caller to functions called by the caller, or
#                         follow callee to functions calling the callee.
#   -n <levels>           Number of levels to follow.
#   -t <source>:<target>  Follow the call path from the source to the target.
#   -x <exclude-symbol>   Exclude the specified symbol. Stop following the
#                         symbol.
#   -r <exclude-symbol>   Remove the specified symbol. Stop following the
#                         symbol and remove the edges to the symbol.
#   -L <symbol>           Highlight the specified symbol.
#   -o <output-file>      Output file name. If not specified, output to stdout.
#
# You can specify multiple -f options to follow multiple call paths.
#
# Example:
#   draw-callflow.py -f +caller -f ~callee -n 2 -o callflow.dot my-database
#
# This will draw a call flow graph with two levels of callers and two levels of
# callees.
#
import sys
import optparse
import sqlite3

#
# Database schema:
#
#    CREATE TABLE symbols (
#        id integer primary key asc,
#        name text unique
#    );
#
#    CREATE TABLE calls (
#        caller integer,
#        callee integer
#    );
#

class CallflowNode:
    def __init__(self, id, name, tree):
        self.id = id
        self.name = name
        self.tree = tree
        self.children = []
        self.extra_label = []
        pass

    def add_non_existing_child(self, child):
        if child in self.children:
            return False
        self.children.append(child)
        return True

    def is_in_set(self, set):
        return self.name in set or '@' + str(self.id) in set

    def mark_as_highlight(self):
        if not hasattr(self, 'highlight'):
            self.extra_label.append('color=red')
            self.highlight = True
            pass
        pass
    pass

class CallflowTree:
    def __init__(self, id, name, to_callee):
        self.root = CallflowNode(id, name, self)
        self.symbols = {name: self.root}
        self.to_callee = to_callee
        pass

    def draw(self, out, hist):
        if self.to_callee:
            self.draw_to_callee(out, hist)
        else:
            self.draw_to_caller(out, hist)
            pass
        pass

    def draw_to_callee(self, out, hist):
        tasks = [self.root]
        has_label = set()
        visited = set()
        while tasks:
            node = tasks.pop()
            if node in visited:
                continue
            visited.add(node)
            if node.name not in has_label and node.extra_label:
                out.write('"%s" [%s];\n' % (node.name, ','.join(node.extra_label)))
                has_label.add(node.name)
                pass
            for child in node.children:
                if (node.name, child.name) in hist:
                    continue
                hist.add((node.name, child.name))
                if child.name not in has_label and child.extra_label:
                    out.write('"%s" [%s];\n' % (child.name, ','.join(child.extra_label)))
                    has_label.add(child.name)
                    pass
                if hasattr(node, 'highlight') and hasattr(child, 'highlight'):
                    out.write('"%s" -> "%s" [color=red,weight=2];\n' % (node.name, child.name))
                else:
                    out.write('"%s" -> "%s";\n' % (node.name, child.name))
                    pass
                tasks.append(child)
                pass
            pass
        pass

    def draw_to_caller(self, out, hist):
        tasks = [self.root]
        has_label = set()
        visited = set()
        while tasks:
            node = tasks.pop()
            if node in visited:
                continue
            visited.add(node)
            if node.name not in has_label and node.extra_label:
                out.write('"%s" [%s];\n' % (node.name, ','.join(node.extra_label)))
                has_label.add(node.name)
                pass
            for child in node.children:
                if child.name not in has_label and child.extra_label:
                    out.write('"%s" [%s];\n' % (child.name, ','.join(child.extra_label)))
                    has_label.add(child.name)
                    pass
                if (node.name, child.name) in hist:
                    continue
                hist.add((node.name, child.name))
                if hasattr(node, 'highlight') and hasattr(child, 'highlight'):
                    out.write('"%s" -> "%s" [color=red,weight=2];\n' % (child.name, node.name))
                else:
                    out.write('"%s" -> "%s";\n' % (child.name, node.name))
                    pass
                tasks.append(child)
                pass
            pass
        pass
    pass

def create_callflow_tree(conn, name, levels, exclude, remove,
                         highlight, to_callee):
    id = conn.execute("SELECT id FROM symbols WHERE name = ?",
                      (name,)).fetchone()[0]
    tree = CallflowTree(id, name, to_callee)
    if tree.root.is_in_set(highlight):
        tree.root.mark_as_highlight()
        pass
    tasks = [(name, levels)]
    while tasks:
        (name, level) = tasks.pop()
        if level == 0:
            continue
        id = conn.execute("SELECT id FROM symbols WHERE name = ?",
                          (name,)).fetchone()[0]
        if to_callee:
            query = "SELECT callee FROM calls WHERE caller = ?"
        else:
            query = "SELECT caller FROM calls WHERE callee = ?"
            pass
        for row in conn.execute(query, (id,)):
            callee_or_caller = row[0]
            child_name = \
                conn.execute("SELECT name FROM symbols WHERE id = ?",
                             (callee_or_caller,)).fetchone()[0]
            if child_name in remove:
                continue
            if child_name in tree.symbols:
                node = tree.symbols[child_name]
                new_node = False
            else:
                node = CallflowNode(callee_or_caller, child_name, tree)
                tree.symbols[child_name] = node
                new_node = True
                pass
            if node.is_in_set(highlight):
                node.mark_as_highlight()
                pass
            if tree.symbols[name].add_non_existing_child(node) \
               and new_node \
               and child_name not in exclude:
                tasks.append((child_name, level - 1))
                pass
            pass
        pass
    return tree

def create_callflow_tree_target(conn, source, target, levels, highlight):
    '''Create a call flow tree from the source to the target.

    This function creates a call flow tree from the source to the target.
    The function returns the call flow tree.

    Args:
        conn: The database connection.
        source: The source function name.
        target: The target function name.
        levels: The number of levels to follow.
        highlight: The set of symbols to highlight.

    Returns:
        The call flow tree.
    '''
    src_id = conn.execute("SELECT id FROM symbols WHERE name = ?",
                            (source,)).fetchone()[0]
    tgt_id = conn.execute("SELECT id FROM symbols WHERE name = ?",
                            (target,)).fetchone()[0]
    tree = CallflowTree(src_id, source, True)
    if tree.root.is_in_set(highlight):
        tree.root.mark_as_highlight()
        pass
    tasks = [([source], levels)]
    while tasks:
        (path, level) = tasks.pop()
        if level == 0:
            continue
        name = path[-1]
        id = conn.execute("SELECT id FROM symbols WHERE name = ?",
                            (name,)).fetchone()[0]
        for row in conn.execute("SELECT callee FROM calls WHERE caller = ?",
                                (id,)):
            callee = row[0]
            callee_name = \
                conn.execute("SELECT name FROM symbols WHERE id = ?",
                             (callee,)).fetchone()[0]
            if callee_name == target:
                fullpath = path + [callee_name]
                for i in range(1, len(fullpath)):
                    parent_name = fullpath[i - 1]
                    child_name = fullpath[i]

                    parent_id = conn.execute("SELECT id FROM symbols WHERE name = ?",
                                            (parent_name,)).fetchone()[0]
                    child_id = conn.execute("SELECT id FROM symbols WHERE name = ?",
                                            (child_name,)).fetchone()[0]
                    parent_node = tree.symbols[parent_name]
                    if child_name in tree.symbols:
                        node = tree.symbols[child_name]
                    else:
                        node = CallflowNode(child_id, child_name, tree)
                        tree.symbols[child_name] = node
                        pass
                    if node.is_in_set(highlight):
                        node.mark_as_highlight()
                        pass
                    parent_node.add_non_existing_child(node)
                    pass
                pass
            elif callee_name not in path:
                tasks.append((path + [callee_name], level - 1))
                pass
            pass
        pass
    return tree

def usage():
    print("Usage: %s [-f <+caller|-callee>] [-n <levels>]" % sys.argv[0])
    print("          [-t <source>:<target>] [-x <exclude-symbol>] [-r <remove-symbol>] [-o <output-file>] <database>")
    sys.exit(1)
    pass

def main():
    parser = optparse.OptionParser()
    parser.add_option("-f", "--follow", dest="follow", action="append",
                      help="Follow caller to functions called by the caller, or "
                      "follow callee to functions calling the callee.")
    parser.add_option("-n", "--levels", dest="levels", type="int",
                      help="Number of levels to follow.")
    parser.add_option("-t", "--target", dest="target", action="append",
                      help="Follow the call path from the source to the target.")
    parser.add_option("-x", "--exclude", dest="exclude", action="append",
                        help="Exclude the specified symbol. Stop following the "
                        "symbol.")
    parser.add_option("-r", "--remove", dest="remove", action="append",
                        help="Remove the specified symbol. Stop following the "
                        "symbol and remove the edges to it.")
    parser.add_option("-L", "--highlight", dest="highlight", action="append",
                      help="Highlight the specified symbol.")
    parser.add_option("-o", "--output", dest="output",
                      help="Output file name. If not specified, output to stdout.")
    (options, args) = parser.parse_args()

    if len(args) != 1:
        usage()
        pass

    if options.follow is None and options.target is None:
        usage()
        pass

    if options.follow is None:
        options.follow = []
        pass

    if options.levels is None:
        options.levels = 5
        pass

    if options.target is None:
        options.target = []
        pass

    if options.exclude is None:
        options.exclude = []
        pass

    if options.remove is None:
        options.remove = []
        pass

    if options.highlight is None:
        options.highlight = []
        pass

    if options.output is None:
        out = sys.stdout
    else:
        out = open(options.output, "w")
        pass

    conn = sqlite3.connect(args[0])

    tries = []
    for follow in options.follow:
        if follow.startswith("+"):
            tree = create_callflow_tree(conn, follow[1:],
                                        options.levels,
                                        options.exclude,
                                        options.remove,
                                        options.highlight,
                                        True)
        elif follow.startswith("~"):
            tree = create_callflow_tree(conn, follow[1:],
                                        options.levels,
                                        options.exclude,
                                        options.remove,
                                        options.highlight,
                                        False)
        else:
            usage()
            pass
        tries.append(tree)
        pass
    for target in options.target:
        (source, target) = target.split(":")
        source = source.strip()
        target = target.strip()
        tree = create_callflow_tree_target(conn, source, target,
                                           options.levels, options.highlight)
        tries.append(tree)
        pass

    draw_hist = set()
    out.write("digraph callflow {\n")
    for tree in tries:
        tree.draw(out, draw_hist)
        pass
    out.write("}\n")
    pass

if __name__ == "__main__":
    main()
    pass

