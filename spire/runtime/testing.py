import os

from spire.core.assembly import Assembly
from spire.runtime.runtime import Runtime, current_runtime

class Runtime(Runtime):
    def __init__(self):
        super(Runtime, self).__init__()

        conffiles = os.environ.get('SPIRE_CONFIG')
        if conffiles:
            for conffile in conffiles.strip().split(' '):
                self.configure(conffile)

        self.deploy(ignore_components=True)
