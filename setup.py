#!/usr/bin/env python3
import os.path
import infra
from instances import DeltaTags
#from targets import DeltaTagsTest

setup = infra.Setup(os.path.dirname(__file__))

setup.add_instance(infra.instances.Default(DeltaTags.llvm))
setup.add_instance(infra.instances.DefaultLTO(DeltaTags.llvm))
for instance in DeltaTags.make_instances():
    setup.add_instance(instance)

setup.add_target(infra.targets.SPEC2006())
#setup.add_target(DeltaTagsTest())

if __name__ == '__main__':
    setup.main()
