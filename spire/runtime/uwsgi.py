from __future__ import absolute_import

import os
import sys

from spire.runtime.runtime import Runtime
from spire.util import dump_threads
from spire.wsgi.util import Mount, MountDispatcher

IPYTHON_CONSOLE_TRIGGER = '/tmp/activate-%s-console'
IPYTHON_CONSOLE_SIGNAL = 18

try:
    import uwsgi
except ImportError:
    uwsgi = None

def activate_ipython_console(n):
    from IPython import embed_kernel
    embed_kernel(local_ns={'uwsgi': uwsgi})

class Mule(object):
    def __init__(self, id, name, function):
        self.function = function
        self.id = id
        self.name = name

    def __call__(self):
        if uwsgi.mule_id() == self.id:
            uwsgi.setprocname(self.name)
            self.function(self)

    def send(self, message):
        uwsgi.mule_msg(message, self.id)

    def wait(self):
        return uwsgi.mule_get_msg()

class Runtime(Runtime):
    def __init__(self, configuration=None, assembly=None):
        super(Runtime, self).__init__(assembly=assembly)
        self.mules = {}
        self.postforks = []

        uwsgi.post_fork_hook = self.run_postforks

        for key in ('yaml', 'yml', 'json'):
            filename = uwsgi.opt.get(key)
            if filename:
                self.configure(filename)
                break
        else:
            raise RuntimeError()

        self.deploy()
        self.startup()

        self.dispatcher = MountDispatcher()
        for unit in self.assembly.collate(Mount):
            self.dispatcher.mount(unit)

        self._register_services(self.dispatcher)

        name = self.parameters.get('name')
        if name:
            self.register_ipython_console(name)

    def __call__(self, environ, start_response):
        return self.dispatcher.dispatch(environ, start_response)

    @property
    def host(self):
        return uwsgi.opt['http-socket']

    @property
    def pid(self):
        return uwsgi.masterpid()

    def get_message(self):
        return uwsgi.mule_get_msg()

    def lock(self):
        uwsgi.lock()

    def notify_mule(self, name, message):
        if name in self.mules:
            self.mules[name].send(message)
        else:
            raise ValueError(name)

    def register_ipython_console(self, name):
        trigger = IPYTHON_CONSOLE_TRIGGER % name
        os.close(os.open(trigger, os.O_WRONLY|os.O_CREAT, 0666))

        uwsgi.register_signal(IPYTHON_CONSOLE_SIGNAL, 'mule', activate_ipython_console)
        uwsgi.add_file_monitor(IPYTHON_CONSOLE_SIGNAL, trigger)

    def register_mule(self, name, function):
        mule = self.mules[name] = Mule(len(self.mules) + 1, name, function)
        self.postforks.append(mule)

    def reload(self):
        uwsgi.reload()

    def run_postforks(self):
        for function in self.postforks:
            function()

    def unlock(self):
        uwsgi.unlock()

if uwsgi:
    uwsgi.applications = {'': Runtime()}
