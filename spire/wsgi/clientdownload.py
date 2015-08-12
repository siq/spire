import os

from werkzeug.exceptions import MethodNotAllowed
from spire.wsgi.util import Mount

class ClientDownloadEndPoint(Mount):

    def _dispatch_request(self, request, response):
        if request.method == 'GET':
            return
        elif request.method != 'POST':
            raise MethodNotAllowed()

        # default is csv
        # but you can specify any mimetype and filename you want from within the form being submitted
        mimetype = request.form.get('mimetype', 'text/csv')
        filename = request.form.get('filename', 'data.csv')
        data = request.form.get('data', '')
        response.headers = {
            'content-type': mimetype + '; charset=utf-8',
            'content-disposition': 'attachment;filename='+filename
        }
        response.data = data
