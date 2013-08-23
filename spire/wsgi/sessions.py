from datetime import datetime

from scheme import Boolean, Integer, Object, Structure, Text
from werkzeug.contrib.sessions import FilesystemSessionStore, SessionStore, Session, generate_key
from werkzeug.http import dump_cookie, parse_cookie
from werkzeug.wsgi import ClosingIterator
import pickle
from spire.core import Configuration, Unit, configured_property
from spire.util import pruned
from spire.wsgi.util import Middleware
import os
LONG_AGO = datetime(2000, 1, 1)

class Session(Session):
    def __init__(self, data, sid, new=False):
        super(Session, self).__init__(data, sid, new)
        self.expired = False

    def expire(self):
        self.expired = True

    def rekey(self):
        self.sid = generate_key()

class SessionBackend(Unit):
    """A session backend."""

    configuration = Configuration({
        'store': Structure(
            structure={
                FilesystemSessionStore: {
                    'path': Text(default=None),
                },
            },
            polymorphic_on=Object(name='implementation', nonnull=True),
            default={'implementation': FilesystemSessionStore},
            required=True,
        )
    })

    def __init__(self):
        store = self.configuration['store']
        self.store = store['implementation'](session_class=Session,
            **pruned(store, 'implementation'))

    def remove_filesession_by_user_id(self, subject_id):
        fs = self.store
        list_session = fs.list()
        filename = None
        for sid in list_session:
            filename = fs.get_session_filename(sid)
            session_filedict = pickle.load(open(filename, 'rb'))
            context = session_filedict.get('request.context', None)
            if context:
                user_id = context.get('user-id', None)
                if user_id and user_id == subject_id:
                    os.remove(filename)
        return

class SessionMiddleware(Unit, Middleware):
    """A session middleware."""

    configuration = Configuration({
        'enabled': Boolean(default=True, required=True),
        'cookie': Structure({
            'name': Text(nonnull=True, min_length=1, default='sessionid'),
            'max_age': Integer(minimum=0),
            'secure': Boolean(default=False),
        }, generate_default=True, required=True),
        'store': Structure(
            structure={
                FilesystemSessionStore: {
                    'path': Text(default=None),
                },
            },
            polymorphic_on=Object(name='implementation', nonnull=True),
            default={'implementation': FilesystemSessionStore},
            required=True,
        )
    })

    enabled = configured_property('enabled')

    def __init__(self, prefix='HTTP_X_SPIRE_'):
        self.prefix = prefix
        self.prefix_length = len(prefix)

        store = self.configuration['store']
        self.store = store['implementation'](session_class=Session,
            **pruned(store, 'implementation'))

    def dispatch(self, application, environ, start_response):
        session = None
        if self.enabled:
            session = self._get_session(environ)

        environ['request.session'] = session
        if session is None:
            return application(environ, start_response)

        def injecting_start_response(status, headers, exc_info=None):
            if session.expired:
                headers.append(('Set-Cookie', self._construct_cookie(session, True)))
                self.store.delete(session)
            elif session.should_save:
                self.store.save(session)
                headers.append(('Set-Cookie', self._construct_cookie(session)))
            return start_response(status, headers, exc_info)

        return ClosingIterator(application(environ, injecting_start_response),
            lambda: self.store.save_if_modified(session))

    def _construct_cookie(self, session, unset=False):
        params = self.configuration['cookie']
        expires = (LONG_AGO if unset else params.get('expires'))

        return dump_cookie(params['name'], session.sid, params.get('max_age'),
            expires, params.get('path', '/'), params.get('domain'),
            params.get('secure'), params.get('httponly', True))

    def _get_session(self, environ):
        cookie = parse_cookie(environ.get('HTTP_COOKIE', ''))
        id = cookie.get(self.configuration['cookie']['name'], None)

        if id is None:
            id = self._find_session_id(environ)

        if id:
            return self.store.get(id)
        else:
            return self.store.new()

    def _find_session_id(self, environ):
        prefix = self.prefix
        length = self.prefix_length

        for name, value in environ.iteritems():
            if name[:length] == prefix:
                key = name[length:].lower().replace('_', '-')
                if key == 'session-id':
                    return value

def get_session(environ):
    return environ.get('request.session')
