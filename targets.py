import os
import argparse
from infra import Target
from infra.util import run, qjoin
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
        self.run_make(ctx, instance, '--always-make')

    def link(self, ctx, instance):
        pass

    def binary_paths(self, ctx, instance):
        return self.run_make(ctx, instance, 'bins').stdout.split()

    def run_make(self, ctx, instance, *args):
        os.chdir(self.path(ctx, 'src'))
        env = {
            'TARGETDIR': self.path(ctx, instance.name),
            'LLVM_VERSION': DeltaTags.llvm.version,
            'CC': ctx.cc,
            'CXX': ctx.cxx,
            'CFLAGS': qjoin(ctx.cflags),
            'CXXFLAGS': qjoin(ctx.cxxflags),
            'LDFLAGS': qjoin(ctx.ldflags)
        }
        return run(ctx, ['make', *args], env=env)

    def add_run_args(self, parser):
        parser.add_argument('args', nargs=argparse.REMAINDER,
                help='arguments to pass to run script')

    def run(self, ctx, instance):
        os.chdir('src')
        wrap = ctx.get('target_run_wrapper', '')
        run(ctx, ['bash', 'runtests.sh', instance.name, wrap, *ctx.args.args],
            teeout=True, allow_error=True)
