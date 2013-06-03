from threading import Lock

from mesh.standard import OperationError, ValidationError

from scheme import Boolean, Text
from scheme.supplemental import ObjectReference
from sqlalchemy import MetaData, Table, create_engine, event
from sqlalchemy.engine.reflection import Inspector
from sqlalchemy.exc import NoSuchTableError
from sqlalchemy.orm.session import Session, sessionmaker

from spire.core import *
from spire.local import ContextLocals
from spire.schema.dialect import get_dialect
from spire.schema.migration import MigrationInterface
from spire.util import get_package_path

__all__ = ('OperationError', 'Schema', 'SchemaDependency', 'SchemaInterface', 'ValidationError')

SessionLocals = ContextLocals.create_prefixed_proxy('schema.session')

class EnhancedSession(Session):
    def call_after_commit(self, function, *args, **params):
        try:
            calls = self._call_after_commit
        except AttributeError:
            self._call_after_commit = [(function, args, params)]
        else:
            calls.append((function, args, params))

    def close(self):
        super(EnhancedSession, self).close()
        try:
            del self._call_after_commit
        except AttributeError:
            pass

    def commit(self):
        super(EnhancedSession, self).commit()
        try:
            calls = self._call_after_commit
        except AttributeError:
            return
        else:
            del self._call_after_commit

        for function, args, params in calls:
            function(*args, **params)

    def rollback(self):
        super(EnhancedSession, self).rollback()
        try:
            del self._call_after_commit
        except AttributeError:
            pass

class Schema(object):
    """A spire schema."""

    guard = Lock()
    schemas = {}

    def __new__(cls, name):
        cls.guard.acquire()
        try:
            try:
                return cls.schemas[name]
            except KeyError:
                instance = cls.schemas[name] = super(Schema, cls).__new__(cls)
                instance.constructors = []
                instance.name = name
                instance.metadata = MetaData()
                SchemaDependency.register(name)
                SessionLocals.declare(name)
                return instance
        finally:
            cls.guard.release()

    def constructor(self):
        def decorator(function):
            self.constructors.append(function)
            return function
        return decorator

    @classmethod
    def interface(cls, name):
        return SchemaDependency(name).get()

class SchemaInterface(Unit):
    configuration = Configuration({
        'admin_url': Text(nonnull=True),
        'echo': Boolean(default=False),
        'hstore': Boolean(default=False),
        'migrations': Text(nonnull=True),
        'schema': Text(nonempty=True),
        'url': Text(nonempty=True),
    })

    def __init__(self, schema, url):
        if isinstance(schema, basestring):
            schema = Schema.schemas[schema]

        params = {'hstore': self.configuration.get('hstore', False)}
        self.dialect = get_dialect(url, **params)

        self.cache = {}
        self.guard = Lock()
        self.schema = schema
        self.url = url

    @property
    def session(self):
        return self.get_session()

    def construct_model(self, base, tablename, attributes, title=None, **params):
        params.update(schema=self.schema, tablename=tablename)
        meta = type('meta', (), params)

        attributes.update(meta=meta)
        return type(str(title or tablename), (base,), attributes)

    def create_or_update_table(self, table, **tokens):
        engine = self.get_engine(**tokens)
        try:
            additions, removals = self._collate_column_changes(engine, table)
            if not additions and not removals:
                return
        except NoSuchTableError:
            table.create(engine)
            return

        sql = self.dialect.construct_alter_table(table.name, additions, removals)
        engine.execute(sql)

    def create_schema(self, **tokens):
        url = self._construct_url(tokens)
        name = url.split('/')[-1]

        admin_url = self.configuration.get('admin_url')
        self.dialect.create_database(admin_url, name)

        engine, sessions = self._acquire_engine(tokens)
        self.schema.metadata.create_all(engine)

        migrations = self._get_migration_interface()
        if migrations and migrations.has_revisions:
            migrations.stamp()

    def deploy_schema(self, **tokens):
        url = self._construct_url(tokens)
        name = url.split('/')[-1]

        admin_url = self.configuration.get('admin_url')
        if self.dialect.is_database_present(admin_url, name):
            migrations = self._get_migration_interface()
            if migrations and migrations.has_revisions:
                migrations.upgrade()
        else:
            self.create_schema(**tokens)

        constructors = self.schema.constructors
        if not constructors:
            return

        engine, sessions = self._acquire_engine(tokens)
        session = sessions()

        try:
            for constructor in constructors:
                constructor(session)
        finally:
            session.close()

    def drop_schema(self, **tokens):
        url = self._construct_url(tokens)
        name = url.split('/')[-1]

        admin_url = self.configuration.get('admin_url')
        if admin_url:
            self.dialect.drop_database(admin_url, name)

    def drop_table(self, table, **tokens):
        engine, sessions = self._acquire_engine(tokens)
        table.drop(engine)

    def drop_tables(self, **tokens):
        engine, sessions = self._acquire_engine(tokens)
        self.schema.metadata.drop_all(engine)

    def enumerate_tables(self, **tokens):
        engine, sessions = self._acquire_engine(tokens)
        inspector = Inspector.from_engine(engine)
        return inspector.get_table_names()

    def get_engine(self, **tokens):
        engine, sessions = self._acquire_engine(tokens)
        return engine

    def get_session(self, independent=False, **tokens):
        if independent:
            engine, sessions = self._acquire_engine(tokens)
            return sessions()

        session = SessionLocals.get(self.schema.name)
        if session:
            return session

        engine, sessions = self._acquire_engine(tokens)
        session = sessions()
        return SessionLocals.push(self.schema.name, session, session.close)

    def is_table_correct(self, table, **tokens):
        engine = self.get_engine(**tokens)
        try:
            additions, removals = self._collate_column_changes(engine, table)
            return (not additions and not removals)
        except NoSuchTableError:
            return False

    def lock_tables(self, session, tables, mode='share row exclusive'):
        if isinstance(tables, basestring):
            tables = [tables]

        for tablename in tables:
            session.execute(self.dialect.construct_lock_table(tablename, mode))

    def purge(self):
        self.guard.acquire()
        try:
            for engine, sessions in self.cache.itervalues():
                engine.dispose()
            self.cache = {}
        finally:
            self.guard.release()

    def table_exists(self, table, **tokens):
        engine, sessions = self._acquire_engine(tokens)
        return table.exists(engine)

    def _acquire_engine(self, tokens=None):
        url = self._construct_url(tokens)
        try:
            return self.cache[url]
        except KeyError:
            pass

        self.guard.acquire()
        try:
            if url in self.cache:
                return self.cache[url]

            engine, sessions = self._create_engine(url)
            self.cache[url] = (engine, sessions)
            return engine, sessions
        finally:
            self.guard.release()

    def _collate_column_changes(self, engine, table):
        inspector = Inspector.from_engine(engine)

        columns = {}
        for column in Inspector.from_engine(engine).get_columns(table.name):
            columns[column['name']] = column

        additions = []
        removals = []

        for column in table.columns:
            existing = columns.get(column.name)
            if existing is not None:
                if self.dialect.type_is_equivalent(column.type, existing['type']):
                    continue
                else:
                    removals.append(column)
            additions.append(column)

        for name in columns:
            if name not in table.columns:
                removals.append(name)

        return additions, removals

    def _construct_url(self, tokens=None):
        url = self.url
        if tokens:
            url = url % tokens
        return url

    def _create_engine(self, url):
        echo = self.configuration.get('echo')
        if echo:
            echo = 'debug'

        engine = self.dialect.create_engine(url, self.schema, echo=echo)
        return engine, sessionmaker(bind=engine, class_=EnhancedSession)

    def _get_migration_interface(self):
        migrations = self.configuration.get('migrations')
        if migrations:
            return MigrationInterface(self.schema, get_package_path(migrations))

class SchemaDependency(Dependency):
    def __init__(self, schema, **params):
        self.schema = schema
        super(SchemaDependency, self).__init__(SchemaInterface, 'schema:%s' % schema, **params)

    def contribute_params(self):
        return {'schema': self.schema}
