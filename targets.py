import os
from infra import Target
from infra.util import run
from instances import DeltaTags


class DeltaTagsTest(Target):
    name = 'deltatags-test'

    def __init__(self):
        pass

    def is_fetched(self, ctx):
        return os.path.exists('src')

    def fetch(self, ctx):
        os.symlink(os.path.join(ctx.paths.root, self.name), 'src')

    def build(self, ctx, instance):
        self.run_make(ctx, instance, '-j%d' % ctx.jobs)

    def link(self, ctx, instance):
        pass

    def clean(self, ctx, instance):
        self.run_make(ctx, instance, 'clean')

    def binary_paths(self, ctx, instance):
        return self.run_make(ctx, instance, 'bins').stdout.split()

    def run_make(self, ctx, instance, *args):
        os.chdir(self.path(ctx, 'src'))
        env = {
            'TARGETDIR': self.path(ctx, instance.name),
            'LLVM_VERSION': DeltaTags.llvm.version
        }
        return run(ctx, ['make', *args], env=env)
