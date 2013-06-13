import os
from glob import glob

from scheme import Json, Text
from werkzeug.exceptions import MethodNotAllowed
from werkzeug.formparser import parse_form_data

from spire.core import Configuration, Unit
from spire.util import uniqid
from spire.wsgi.util import Mount

class UploadEndpoint(Mount):
    configuration = Configuration({
        'upload_directory': Text(nonempty=True, default='/tmp'),
    })

    def _dispatch_request(self, request, response):
        target = self.configuration['target_directory']
        if request.method != 'POST':
            raise MethodNotAllowed()

        mapping = {}
        for name, uploaded_file in request.files.iteritems():
            id = mapping[name] = uniqid()
            uploaded_file.save(self._construct_filename(uploaded_file, id))

        response.mimetype = 'application/json'
        response.data = Json.serialize(mapping)

    def _construct_filename(self, uploaded_file, id):
        target = self.configuration['upload_directory']
        root, ext = os.path.splitext(uploaded_file.filename)
        return os.path.join(target, '%s%s' % (id, ext))

class UploadManager(Unit):
    configuration = Configuration({
        'upload_directory': Text(nonempty=True, default='/tmp'),
    })

    def acquire(self, id):
        filename = self._find_uploaded_file(id)
        return open(filename)

    def dispose(self, id):
        try:
            filename = self._find_uploaded_file(id)
        except ValueError:
            pass
        else:
            os.unlink(filename)

    def _find_uploaded_file(self, id):
        directory = self.configuration['upload_directory']
        paths = glob(os.path.join(directory, id + '.*'))

        if len(paths) == 1:
            return paths[0]
        else:
            raise ValueError(id)
