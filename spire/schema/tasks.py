from bake import *
from scheme import *

from spire.schema import Schema
from spire.support.task import SpireTask
from spire.util import get_package_data

try:
    import alembic
except ImportError:
    alembic = None
else:
    from alembic import command

class CreateSchema(SpireTask):
    name = 'spire.schema.create'
    description = 'creates a spire schema within a database'
    parameters = {
        'incremental': Boolean(description='only create new tables', default=False),
        'schemas': Sequence(Text(nonnull=True), description='the schemas to create'),
    }

    def run(self, runtime):
        schemas = self['schemas']
        if schemas is None:
            schemas = []
            for token, conf in self.assembly.filter_configuration('schema').iteritems():
                schemas.append(conf['schema'])
        if not schemas:
            runtime.report('no schemas specified or configured; aborting')
            return

        from spire.schema import Schema
        for name in schemas:
            interface = Schema.interface(name)
            if not self['incremental']:
                interface.drop_schema()

            runtime.report('creating %r schema' % name)
            interface.create_schema()

class DeploySchema(SpireTask):
    name = 'spire.schema.deploy'
    description = 'deploys a spire schema'
    parameters = {
        'drop': Boolean(default=False),
        'schema': Text(nonempty=True),
    }

    def run(self, runtime):
        from spire.schema import Schema
        name = self['schema']
        interface = Schema.interface(name)

        if self['drop']:
            runtime.report('dropping schema %r' % name)
            interface.drop_schema()

        runtime.report('deploying schema %r' % name)
        interface.deploy_schema()

class MigrationTask(SpireTask):
    supported = bool(alembic)
    parameters = {
        'path': Path(description='path to migrations directory', required=True),
        'schema': Text(description='name of target schema'),
    }

    @property
    def config(self):
        from alembic.config import Config
        config = Config()
        config.set_main_option('script_location', str(self['path']))
        return config

    @property
    def schema(self):
        schema = self['schema']
        if schema:
            return schema

        candidates = Schema.schemas.keys()
        if len(candidates) == 1:
            return candidates[0]

        raise TaskError('no schema specified')

    def prepare_environment(self):
        root = self['path']
        (root / 'versions').mkdir_p()

class InitializeMigrations(MigrationTask):
    name = 'spire.migrations.init'
    description = 'initialize a migrations directory for a schema'

    def run(self, runtime):
        root = self['path']
        schema = self['schema']
        if root.exists():
            runtime.report('migrations directory exists for %r; aborting' % schema)
            return

        root.makedirs_p()
        (root / 'versions').mkdir()

        script = get_package_data('spire.schema:templates/script.py.mako.tmpl')
        (root / 'script.py.mako').write_bytes(script)

        env = get_package_data('spire.schema:templates/env.py.tmpl')
        (root / 'env.py').write_bytes(env % {
            'schema': self.schema,
        })

        runtime.report('created migrations directory for %r' % self.schema)

class CreateMigration(MigrationTask):
    name = 'spire.migrations.create'
    description = 'creates a new schema migration'
    parameters = {
        'autogenerate': Boolean(description='autogenerate migration', default=False),
        'title': Text(description='short title for migration', required=True),
    }

    def run(self, runtime):
        self.prepare_environment()
        command.revision(self.config, message=self['title'], autogenerate=self['autogenerate'])

class Downgrade(MigrationTask):
    name = 'spire.migrations.downgrade'
    description = 'downgrade to an older version of the schema'
    parameters = {
        'revision': Text(description='revision to downgrade to', default='base'),
        'sql': Boolean(description='generate sql instead of downgrading database', default=False),
    }

    def run(self, runtime):
        command.downgrade(self.config, revision=self['revision'], sql=self['sql'])

class Upgrade(MigrationTask):
    name = 'spire.migrations.upgrade'
    description = 'upgrade to an newer version of the schema'
    parameters = {
        'revision': Text(description='revision to upgrade to', default='head'),
        'sql': Boolean(description='generate sql instead of upgrading database', default=False),
    }

    def run(self, runtime):
        command.upgrade(self.config, revision=self['revision'], sql=self['sql'])

class ShowBranches(MigrationTask):
    name = 'spire.migrations.branches'
    description = 'show un-spliced branch points'

    def run(self, runtime):
        command.branches(self.config)

class ShowCurrent(MigrationTask):
    name = 'spire.migrations.current'
    description = 'show current migration revision'

    def run(self, runtime):
        command.current(self.config)

class ShowHistory(MigrationTask):
    name = 'spire.migrations.history'
    description = 'show changeset history'

    def run(self, runtime):
        command.history(self.config)
