#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
import os.path
import infra
from instances import DeltaTags
from targets import DeltaTagsTest

curdir = os.path.dirname(os.path.abspath(__file__))
setup = infra.Setup(curdir)

setup.add_instance(infra.instances.Default(DeltaTags.llvm))
setup.add_instance(infra.instances.DefaultLTO(DeltaTags.llvm))
for instance in DeltaTags.make_instances():
    setup.add_instance(instance)

# microtest target for debugging
setup.add_target(DeltaTagsTest())

# patched SPEC2006
patches = ['asan', 'dealII-stddef', 'omnetpp-invalid-ptrcheck']
for name in ('gcc', 'perlbench', 'soplex', 'h264ref-sizetagprop-BCBP'):
    patches.append('%s/patches/spec2006-%s.patch' % (curdir, name))

setup.add_target(infra.targets.SPEC2006(
    giturl='git@bitbucket.org:vusec/spec-cpu2006-cd.git',
    patches=patches
))

if __name__ == '__main__':
    setup.main()
