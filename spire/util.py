import hashlib
import os
import re
import sys
from inspect import getargspec, stack
from traceback import extract_stack
from types import ModuleType
from urllib import urlencode
from urllib2 import urlopen
from urlparse import urlparse, urlunparse
from uuid import uuid4, uuid5

def call_with_supported_params(callable, *args, **params):
    arguments = getargspec(callable)[0]
    for key in params.keys():
        if key not in arguments:
            del params[key]
    return callable(*args, **params)

def dump_threads():
    lines = []
    for id, stack in sys._current_frames().items():
        lines.append('Thread: %s' % id)
        for filename, lineno, name, line in extract_stack(stack):
            lines.append('  File "%s", line %d, in %s' % (filename, lineno, name))
            if line:
                lines.append('    %s' % line.strip())
    return '\n'.join(lines)

def enumerate_modules(package, import_modules=False):
    """Enumerates all modules within ``package``, optionally importing each of them."""

    path = get_package_path(package)
    for filename in os.listdir(path):
        if filename[-3:] == '.py' and filename != '__init__.py':
            module = '%s.%s' % (package, filename[:-3])
            if import_modules:
                module = import_object(module)
            yield module

def enumerate_tagged_methods(instance, tag, expected_value=None):
    """Enumerates all methods of instance which has an attribute named tag."""

    methods = []
    for attr in dir(instance):
        value = getattr(instance, attr)
        if callable(value):
            try:
                tagged_value = getattr(value, tag)
            except AttributeError:
                continue
            if expected_value is None or tagged_value == expected_value:
                methods.append(value)
    else:
        return methods

def find_tagged_method(instance, **attrs):
    """Finds a tagged method of instance which as the specified attributes."""

    for candidate in dir(instance):
        method = getattr(instance, candidate)
        if callable(method):
            for attr, value in attrs.iteritems():
                try:
                    if getattr(method, attr) != value:
                        break
                except AttributeError:
                    break
            else:
                return method

def get_constructor_args(cls, ignore_private=True, _cache={}):
    """Identifies the named arguments of the constructor of ``cls``.

    :param boolean ignore_private: Optional, default is ``True``.
    """

    try:
        return _cache[cls]
    except KeyError:
        pass

    try:
        signature = getargspec(cls.__init__)
    except TypeError:
        arguments = []
    else:
        arguments = signature[0][1:]

    if ignore_private:
        arguments = [value for value in arguments if value[0] != '_']

    _cache[cls] = arguments
    return arguments

def get_package_data(module, path=None):
    openfile = open(get_package_path(module, path))
    try:
        return openfile.read()
    finally:
        openfile.close()

def get_package_path(module, path=None):
    if path is None:
        if ':' in module:
            module, path = module.split(':', 1)
        else:
            raise ValueError(path)

    if isinstance(module, basestring):
        module = __import__(module, None, None, [module.split('.')[-1]])
    if not isinstance(module, list):
        module = module.__path__

    modulepath = module[0]
    for prefix in sys.path:
        if prefix in ('', '..'):
            prefix = os.getcwd()
        fullpath = os.path.abspath(os.path.join(prefix, modulepath))
        if os.path.exists(fullpath):
            break
    else:
        return None

    if path:
        fullpath = os.path.join(fullpath, path)
    return fullpath

def get_url(url, **params):
    if params:
        params = urlencode(params)
        segments = list(urlparse(url))
        if segments[4]:
            segments[4] += '&' + params
        else:
            segments[4] = params
        url = urlunparse(segments)

    return urlopen(url)

def hash_file(filename, hash='md5', window=10485760):
    hash = getattr(hashlib, hash)()
    with open(filename, 'r') as openfile:
        while True:
            chunk = openfile.read(window)
            if chunk:
                hash.update(chunk)
            else:
                return hash.hexdigest()

def identify_object(obj, cache={}):
    """Identifies ``obj`` if possible, returning a string."""

    if isinstance(obj, ModuleType):
        return obj.__name__
    elif isinstance(obj, object) and isinstance(obj, type):
        if obj.__module__ == '__main__':
            return obj.__name__
        return '%s.%s' % (obj.__module__, obj.__name__)

    try:
        return cache[obj]
    except KeyError:
        pass

    for name, module in sys.modules.iteritems():
        if module:
            for attr, value in module.__dict__.iteritems():
                if value is obj:
                    identity = cache[obj] = '%s.%s' % (name, attr)
                    return identity
    else:
        raise TypeError(obj)

def import_object(path):
    """Attempts to import and return the object identified by ``path``."""

    attr = None
    if ':' in path:
        path, attr = path.split(':')
        return getattr(__import__(path, None, None, [attr]), attr)

    try:
        return __import__(path, None, None, [path.split('.')[-1]])
    except ImportError:
        if '.' in path:
            path, attr = path.rsplit('.', 1)
            return getattr(__import__(path, None, None, [attr]), attr)
        else:
            raise

def is_class(obj):
    return (isinstance(obj, object) and isinstance(obj, type))

def is_module(obj):
    return (isinstance(obj, ModuleType))

def is_package(obj):
    return (isinstance(obj, ModuleType) and obj.__name__ == obj.__package__)

def nsuniqid(namespace, name):
    return str(uuid5(namespace, str(name)))

PLURALIZATION_RULES = (
    (re.compile(r'ife$'), re.compile(r'ife$'), 'ives'),
    (re.compile(r'eau$'), re.compile(r'eau$'), 'eaux'),
    (re.compile(r'lf$'), re.compile(r'lf$'), 'lves'),
    (re.compile(r'[sxz]$'), re.compile(r'$'), 'es'),
    (re.compile(r'[^aeioudgkprt]h$'), re.compile(r'$'), 'es'),
    (re.compile(r'(qu|[^aeiou])y$'), re.compile(r'y$'), 'ies'),
)

def pluralize(word, quantity=None, rules=PLURALIZATION_RULES):
    if quantity == 1: 
        return word

    for pattern, target, replacement in rules:
        if pattern.search(word):
            return target.sub(replacement, word)
    else:
        return word + 's'

def pruned(mapping, *keys):
    pruned = {}
    for key, value in mapping.iteritems():
        if key not in keys:
            pruned[key] = value
    return pruned

def recursive_merge(original, addition):
    """Merge the content of ``addition`` into ``original``, recursing when
    both arguments have a dictionary for the same key.
    """

    for key, value in addition.iteritems():
        if key in original:
            source = original[key]
            if isinstance(source, dict) and isinstance(value, dict):
                value = recursive_merge(source, value)
            original[key] = value
        else:
            original[key] = value
    return original

def safe_table_name(value, prefix=None):
    value = re.sub(r'[-:;.,]', '_', value.lower())
    value = re.sub(r'[_]{2,}', '_', value.strip('_'))
    value = re.sub(r'[^a-z_]', '', value)

    if prefix:
        value = prefix + '_' + value
    return value

VALID_CHARS_EXPR = re.compile(r'[^\w\s-]')
SPACER_EXPR = re.compile(r'[-_\s]+')

def slugify(value, spacer='-', lowercase=True):
    if not isinstance(value, unicode):
        value = unicode(value)

    value = value.encode('ascii', 'ignore')
    value = VALID_CHARS_EXPR.sub('', value).strip()

    if lowercase:
        value = value.lower()
    return SPACER_EXPR.sub(spacer, value)

def topological_sort(graph):
    """Conducts a topological sort of a directed acyclic graph and returns
    the sorted nodes as a ``list``.

    :param dict graph: The graph to sort, which must be a ``dict`` mapping
        each node to a ``set`` containing that node's edges (which are 
        other nodes present in the graph). This argument is modified during
        the sort and should be discarded afterward.
    """

    queue = []
    edges = graph.values()

    for node in graph.iterkeys():
        for edge in edges:
            if node in edge:
                break
        else:
            queue.append(node)

    result = []
    while queue:
        node = queue.pop(0)
        result.append(node)
        for target in graph[node].copy():
            graph[node].remove(target)
            for edge in graph.itervalues():
                if target in edge:
                    break
            else:
                queue.append(target)

    result.reverse()
    return result

def trace_stack(indent=''):
    lines = []
    for frame, filename, lineno, context, source, pos in reversed(stack()[1:]):
        lines.append('%sfile "%s", line %d, in %s' % (indent, filename, lineno, context))
        if source:
            lines.append('%s    %s' % (indent, source[0].strip()))
    return '\n'.join(lines)

def uniqid():
    return str(uuid4())
