#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
import sys
import os.path
curdir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(curdir, 'infra'))

import infra
from instances import DeltaTags
from targets import DeltaTagsTest

setup = infra.Setup(__file__)

setup.add_instance(infra.instances.Clang(DeltaTags.llvm))
setup.add_instance(infra.instances.ClangLTO(DeltaTags.llvm))
for instance in DeltaTags.make_instances():
    setup.add_instance(instance)

# microtest target for debugging
setup.add_target(DeltaTagsTest())

# patched SPEC2006
curdir = os.path.dirname(os.path.abspath(__file__))
patches = ['asan', 'dealII-stddef', 'omnetpp-invalid-ptrcheck']
for name in ('gcc', 'perlbench', 'soplex', 'h264ref-sizetagprop-BCBP'):
    patches.append('%s/patches/spec2006-%s.patch' % (curdir, name))

setup.add_target(infra.targets.SPEC2006(
    # see the following link for more options for source[_type] below:
    # https://github.com/vusec/instrumentation-infra/blob/196171a4fd3a67fd57ef04fda9517bdbcada5256/targets/spec2006/__init__.py#L26
    source='your-git-url', # SET THIS FOR SPEC
    source_type='git',     # SET THIS FOR SPEC
    patches=patches
))

if __name__ == '__main__':
    setup.main()
