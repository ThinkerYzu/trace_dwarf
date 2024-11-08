#-----------------------------------------------------------------------------
# trace_dwarf: setup.py
#
# Setup/installation script.
#
# K.F. Lee <thinker.li@gmail.com>
#-----------------------------------------------------------------------------
import os, sys
from setuptools import setup


try:
    with open('README.md', 'rt') as readme:
        description = '\n' + readme.read()
except IOError:
    # maybe running setup.py from some other dir
    description = ''


setup(
    # metadata
    name='trace_dwarf',
    description='Python tools for parsing DWARF debug information.',
    long_description=description,
    license='BSD',
    version='0.1',
    author='K.F. Lee',
    maintainer='K.F. Lee',
    author_email='thinker.li@gmail.com',
    url='https://github.com/ThinkerYzu/trace_dwarf',
    platforms='Cross Platform',
    classifiers = [
        'Programming Language :: Python :: 3',
        ],
    install_requires=["pyelftools >= 0.30"],
    scripts=['scripts/mk-dwarf-db.py',
             'scripts/draw-callflow.py',
             'scripts/draw-compile-units.py',
             'scripts/draw-types.py'],
)
