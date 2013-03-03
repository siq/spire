import re

from sqlalchemy import Column, create_engine, event
from sqlalchemy.dialects.postgresql.base import ARRAY
from sqlalchemy.engine.url import make_url

class Dialect(object):
    def __init__(self, dialect, hstore=False):
        self.dialect = dialect
        self.hstore = hstore

    def construct_alter_table(self, table, additions=None, removals=None):
        raise NotImplementedError()

    def construct_lock_table(self, tablename, mode):
        raise NotImplementedError()

    def create_database(self, url, name, conditional=True, **params):
        pass

    def create_engine(self, url, schema, echo=False):
        return create_engine(url, echo=echo)

    def create_role(self, url, name, **params):
        pass

    def create_schema(self, url, name, **params):
        pass

    def drop_database(self, url, name, conditional=True):
        pass

    def drop_role(self, url, name, **params):
        pass

    def drop_schema(self, url, name, **params):
        pass

    def is_database_present(self, url, name):
        return False

    def type_is_equivalent(self, left, right):
        return left._type_affinity is right._type_affinity

class PostgresqlDialect(Dialect):
    def construct_alter_table(self, table, additions=None, removals=None):
        actions = []
        if removals:
            for column in removals:
                if isinstance(column, Column):
                    column = column.name
                actions.append('drop %s' % validate_sql_identifier(column))
        if additions:
            for column in additions:
                actions.append('add %s' % self._construct_column(column))

        table = validate_sql_identifier(table)
        return 'alter table %s %s' % (table, ', '.join(actions))

    def construct_lock_table(self, tablename, mode):
        return 'lock table %s in %s mode' % (tablename, mode)

    def create_database(self, url, name, conditional=True, owner=None):
        if conditional and self.is_database_present(url, name):
            return

        sql = 'create database %s' % validate_sql_identifier(name)
        if owner:
            sql += ' owner %s' % validate_sql_identifier(owner)

        self._execute_statement(url, sql)
        if self.hstore:
            url = '%s/%s' % (url.rsplit('/', 1)[0], name)
            self._execute_statement(url, 'create extension hstore')

    def create_engine(self, url, schema, echo=False):
        engine = create_engine(url, echo=echo)
        if self.hstore:
            self._register_hstore_converter(engine)
        return engine
        
    def create_role(self, url, name, login=True, superuser=False):
        sql = ['create role %s' % validate_sql_identifier(name)]
        if login:
            sql.append('login')
        if superuser:
            sql.append('superuser')

        self._execute_statement(url, sql)

    def create_schema(self, url, name, owner=None):
        sql = 'create schema %s' % validate_sql_identifier(name)
        if owner:
            sql += ' authorization %s' % validate_sql_identifier(owner)

        self._execute_statement(url, sql)

    def drop_database(self, url, name, conditional=True):
        sql = ['drop database']
        if conditional:
            sql.append('if exists')

        sql.append(validate_sql_identifier(name))
        self._execute_statement(url, sql)

    def drop_role(self, url, name, if_exists=True):
        sql = ['drop role']
        if if_exists:
            sql.append('if exists')

        sql.append(validate_sql_identifier(name))
        self._execute_statement(url, sql)

    def drop_schema(self, url, name, cascade=False, if_exists=True):
        sql = ['drop schema']
        if if_exists:
            sql.append('if exists')

        sql.append(validate_sql_identifier(name))
        if cascade:
            sql.append('cascade')

        self._execute_statement(url, sql)

    def is_database_present(self, url, name):
        name = validate_sql_identifier(name)
        sql = "select count(*) from pg_database where datname = '%s'" % name

        row = self._execute_statement(url, sql, True)
        return row[0] == 1

    def type_is_equivalent(self, left, right):
        if left._type_affinity is not right._type_affinity:
            return False
        if (left._type_affinity is ARRAY and left.item_type._type_affinity is not
                right.item_type._type_affinity):
            return False
        return True

    def _construct_column(self, column):
        sql = [validate_sql_identifier(column.name), column.type.compile(self.dialect())]
        if not column.nullable:
            sql.append('not null')
        
        return ' '.join(sql)

    def _execute_statement(self, url, sql, result=False):
        if isinstance(sql, list):
            sql = ' '.join(sql)

        cursor = self._get_connection(url).cursor()
        try:
            cursor.execute(sql)
            if result:
                return cursor.next()
        finally:
            cursor.close()

    def _get_connection(self, url, autocommit=True):
        params = make_url(url).translate_connect_args(username='user')
        connection = self.dialect.dbapi().connect(**params)
        connection.autocommit = autocommit
        return connection

    def _register_hstore_converter(self, engine):
        from psycopg2.extras import register_hstore
        from psycopg2 import ProgrammingError

        connection = engine.connect()
        try:
            register_hstore(connection.connection, globally=True)
        except ProgrammingError:
            pass

class SqliteDialect(Dialect):
    def create_engine(self, url, schema, echo=False):
        engine = create_engine(url, echo=echo)

        @event.listens_for(engine, 'connect')
        def handle_checkout(connection, record):
            connection.isolation_level = None

        @event.listens_for(engine, 'begin')
        def handle_begin(connection):
            connection.execute('begin')

        return engine

DIALECTS = {
    ('postgresql', 'psycopg2'): PostgresqlDialect,
    ('sqlite', 'pysqlite'): SqliteDialect,
}

def get_dialect(url, **params):
    dialect = make_url(url).get_dialect()
    implementation = DIALECTS[(dialect.name, dialect.driver)]
    return implementation(dialect, **params)

def validate_sql_identifier(value):
    if re.match(r'^[_a-zA-Z][_a-zA-Z0-9]*$', value):
        return value
    else:
        raise ValueError(value)
