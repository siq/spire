import uuid
from datetime import date, datetime 

from spire.core import Unit, adhoc_configure

from mesh.constants import OK, DELETE, POST, PUT
from mesh.exceptions import AuditCreateError, RequestError
from audit.constants import *
from scheme.timezone import current_timestamp
from scheme.util import format_structure

# mesh dependency configuration
adhoc_configure({
    'mesh:audit': {
        'bundle': 'audit.API',
        'url': 'http://localhost:9986/api'
    }
})

# ToolDependency class
class ToolDependency(Unit):
    from spire.mesh.units import MeshDependency
    audit = MeshDependency('audit')


__all__ = ('Configurable', 'Registry')

class Auditable(object):
    """ A mixin class which indicates that subclasses are collecting audit information
        and provides basic implementations for the necessary methods
    """
    from audit import API
        
    bundle = API
    config = ToolDependency()
    AuditEvent = config.audit.bind('audit/1.0/record')
    
    
    def _prepare_audit_data(self, method, status, resource_data, audit_data):
        raise NotImplementedError
    
    def send_audit_data(self, request, response, subject, data):

        event_details = {}
        event_payload = {}
        resource_data = data or {}
        
        audit_data = {
            AUDIT_ATTR_EVENT_DATE: current_timestamp(),
            AUDIT_ATTR_DETAILS: event_details,
            'event_payload': event_payload,
        }
        
        # check whether the correlation id is given as part of the data
        # if so, use it for this audit call, too, if not, create a new one
        correlation_id = str(uuid.uuid4())
        if not resource_data is None:
            self._validate_payload(resource_data)
            event_payload.update(resource_data)
            if AUDIT_ATTR_CORRELATION_ID in resource_data:
                correlation_id = resource_data.pop(AUDIT_ATTR_CORRELATION_ID)
            
        audit_data[AUDIT_ATTR_CORRELATION_ID]= correlation_id
        
        # extract audit relevant details
        actor_id = request.context.get('user-id', '')
        method = request.headers['REQUEST_METHOD']
        status = response.status or OK
        
        if method == DELETE:
            delsubj = self.acquire(request.subject)
            resource_data = delsubj.extract_dict()
        
        if method == POST and not subject is None:
            # a POST request passing the subject's id, should normally rather be a PUT request
            # so translate that, accordingly
            method = PUT
                
        if subject is None:
            if status == OK and 'id' in response.content:
                resource_data['id'] = response.content.get('id')
        else:
            resource_data['id'] = subject.id
             
        audit_data[AUDIT_ATTR_ACTOR_ID] = actor_id
        if status == OK:
            audit_data[AUDIT_ATTR_RESULT] = REQ_RESULT_SUCCESS
        else:
            audit_data[AUDIT_ATTR_RESULT] = REQ_RESULT_FAILED


        _debug('+send_audit_data - request actor', str(actor_id))        
        _debug('+send_audit_data - request method', method)        
        _debug('+send_audit_data - response status', status)
        _debug('+send_audit_data - subject id', resource_data.get('id', None))        
        self._prepare_audit_data(method, status, resource_data, audit_data)
        _debug('+send_audit_data - audit record', str(audit_data))        
        
        # insert rest call to SIQ Audit here!
        # assume that failure to create/write the audit event will throw an exception
        # which we'll deliberately NOT catch, here!
        #import sys;sys.path.append(r'/siq/env/python/lib/python2.7/site-packages/pydev/pysrc')
        #import pydevd;pydevd.settrace()
        self._create_audit_event(audit_data)
        
        return correlation_id
    
    def _create_audit_event(self, audit_data):
        # since the following code is NOT calling directly into controller, we must catch
        # exceptions created therein and ensure they are translated back to an AuditError
        try:
            self.AuditEvent.create(**audit_data)
        except RequestError, exc:
            raise AuditCreateError(exc.content)

    def _validate_payload(self, payload):
        
        """ none of the attributes included in the payload may be of type datetime
            so convert these items to an ISO8601 string representation
        """
        for key, val in payload.iteritems():
            _debug('++++++++++++++++ checking type of attribute',key)
            if isinstance(val, (datetime, date)):
                _debug('++++++++++++++++ value is a datetime value',str(val))
                pattern = '%Y-%m-%dT%H:%M:%SZ'
                payload[key] = val.strftime(pattern) 
        

    
def _debug(msg, obj=None, includeStackTrace=False):
    import datetime
    import inspect
    import traceback
    frame = inspect.currentframe()
    fileName  =  frame.f_code.co_filename
    line = ' [%s] %s' % (fileName, msg)
    if obj != None:
        line += ': ' + str(obj)
    print 'DEBUG:' + line
    if includeStackTrace:
        print 'STACK' + ':' * 75
        for s in traceback.format_stack():
            print(s.strip())
        print ':' * 80
    with open('/tmp/_debug_','a') as fout:
        fout.write(str(datetime.datetime.now().time()) + line + '\n')
        if includeStackTrace:
            fout.write('STACK:\n')
            for s in traceback.format_stack():
                fout.write('  ' + s.strip() + '\n')
        fout.flush()
