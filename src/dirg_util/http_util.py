# -*- coding: utf-8 -*-
#
# Copyright (C) Umeå University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#            http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import cgi
import time
import hashlib
import hmac
import json
from urlparse import parse_qs
from StringIO import StringIO
from Cookie import SimpleCookie
from urllib import quote

from dirg_util import time_util

from dirg_util.aes_m2c import aes_encrypt
from dirg_util.aes_m2c import aes_decrypt


class UnsupportedMethod(Exception):
    pass


class HttpHandler:
    GLOBAL_STATIC = "/opt/dirg/dirg-util/"

    def __init__(self, environ, start_response, session, logger):
        """
        Constructor for the class.
        :param environ:        WSGI enviroment
        :param start_response: WSGI start_respose
        :param session:        Beaker session
        :param logger:         Class to perform logging.
        """
        self.environ = environ
        self.start_response = start_response
        self.session = session
        self.logger = logger

    @staticmethod
    def transform_path(path):
        """
        Help method to point robots.txt to the path to the file.
        :param path: Requested path.
        :return: The path to robots.txt if requested, otherwise the unchanged path.
        """
        if path == "robots.txt":
            return "static/robots.txt"
        return path

    def verify_static(self, path):
        """
        Verifies if this is a file that should be in the static folder.
        :param path: Requested resource with path.
        :return: True if the file should be in the static folder, otherwise false.
        """
        path = self.transform_path(path)
        if path.startswith("static/"):
            return True
        return False

    def handle_static(self, path):
        """
        Renders static pages.
        :param path: Requested resource.
        :return: WSGI response.
        """

        path = self.transform_path(path)
        self.logger.info("[static]sending: %s" % (path,))
        try:
            try:
                text = open(self.GLOBAL_STATIC + path).read()
            except IOError:
                text = open(path).read()
            if path.endswith(".ico"):
                self.start_response('200 OK', [('Content-Type', "image/x-icon")])
            elif path.endswith(".html"):
                self.start_response('200 OK', [('Content-Type', 'text/html')])
            elif path.endswith(".json"):
                self.start_response('200 OK', [('Content-Type', 'application/json')])
            elif path.endswith(".txt"):
                self.start_response('200 OK', [('Content-Type', 'text/plain')])
            elif path.endswith(".css"):
                self.start_response('200 OK', [('Content-Type', 'text/css')])
            elif path.endswith(".js"):
                self.start_response('200 OK', [('Content-Type', 'text/javascript')])
            elif path.endswith(".xml"):
                self.start_response('200 OK', [('Content-Type', 'text/xml')])
            else:
                self.start_response('200 OK', [('Content-Type', "text/html")])
            return [text]
        except IOError:
            return self.http404

    def log_response(self, response):
        """
        Logs a WSGI response.
        :param response: WSGI response.
        """
        self.logger.info("response:")
        self.logger.info(response)

    def log_request(self):
        """
        Logs the WSGI request.
        """
        query = self.query_dict()
        if "CONTENT_TYPE" in self.environ:
            self.logger.info("CONTENT_TYPE:" + self.environ["CONTENT_TYPE"])
        if "REQUEST_METHOD" in self.environ:
            self.logger.info("CONTENT_TYPE:" + self.environ["REQUEST_METHOD"])
        self.logger.info("Path:" + self.path())
        self.logger.info("Query:")
        self.logger.info(query)

    @staticmethod
    def query_dictionary(environ):
        """
        Retrieves a dictionary with query parameters.
        Does not matter if the query parameters are POST or GET.
        Can handle JSON and URL encoded POST, otherwise the body is returned in a dictionare with the key post.
        :param environ: The wsgi enviroment.
        :return: A dictionary with query parameters.
        """
        qs = {}
        query = environ.get("QUERY_STRING", "")
        if not query:
            try:
                length = int(environ["CONTENT_LENGTH"])
                body = environ["wsgi.input"].read(length)
                environ['wsgi.input'] = StringIO(body)
                if "CONTENT_TYPE" in environ and environ["CONTENT_TYPE"] == "application/json":
                    return json.loads(body)
                elif "CONTENT_TYPE" in environ and environ["CONTENT_TYPE"] == "application/x-www-form-urlencoded":
                    return parse_qs(body)
                else:
                    return {"post": body}
            except:
                pass

        else:
            qs = dict((k, v if len(v) > 1 else v[0]) for k, v in
                      parse_qs(query).iteritems())
        return qs

    def query_dict(self):
        """
        Retrieves a dictionary with query parameters.
        Does not matter if the query parameters are POST or GET.
        Can handle JSON and URL encoded POST, otherwise the body is returned in a dictionare with the key post.
        :return: A dictionary with query parameters.
        """
        return HttpHandler.query_dictionary(self.environ)

    def path(self):
        """
        Get the requested path.
        :return: Path as a string
        """
        return self.environ.get('PATH_INFO', '').lstrip('/')

    def http404(self):
        """
        WSGI HTTP 404 response.
        :return WSGI response for HTTP 404.
        """
        resp = NotFound()
        return resp(self.environ, self.start_response)


class Response(object):
    _template = None
    _status = '200 OK'
    _content_type = 'text/html'
    _mako_template = None
    _mako_lookup = None

    def __init__(self, message=None, **kwargs):
        self.status = kwargs.get('status', self._status)
        self.response = kwargs.get('response', self._response)
        self.template = kwargs.get('template', self._template)
        self.mako_template = kwargs.get('mako_template', self._mako_template)
        self.mako_lookup = kwargs.get('template_lookup', self._mako_lookup)

        self.message = message

        self.headers = kwargs.get('headers', [])
        _content_type = kwargs.get('content', self._content_type)
        self.headers.append(('Content-type', _content_type))

    def __call__(self, environ, start_response, **kwargs):
        start_response(self.status, self.headers)
        return self.response(self.message or geturl(environ), **kwargs)

    def _response(self, message="", **argv):
        if self.template:
            if ("Content-type", 'application/json') in self.headers:
                return [message]
            else:
                return [str(self.template % message)]
        elif self.mako_lookup and self.mako_template:
            argv["message"] = message
            mte = self.mako_lookup.get_template(self.mako_template)
            return [mte.render(**argv)]
        else:
            return [message]


class Created(Response):
    _status = "201 Created"


class Redirect(Response):
    _template = '<html>\n<head><title>Redirecting to %s</title></head>\n' \
                '<body>\nYou are being redirected to <a href="%s">%s</a>\n' \
                '</body>\n</html>'
    _status = '302 Found'

    def __call__(self, environ, start_response, **kwargs):
        location = self.message
        self.headers.append(('location', location))
        start_response(self.status, self.headers)
        return self.response((location, location, location))


class SeeOther(Response):
    _template = '<html>\n<head><title>Redirecting to %s</title></head>\n' \
                '<body>\nYou are being redirected to <a href="%s">%s</a>\n' \
                '</body>\n</html>'
    _status = '303 See Other'

    def __call__(self, environ, start_response, **kwargs):
        location = self.message
        self.headers.append(('location', location))
        start_response(self.status, self.headers)
        return self.response((location, location, location))


class Forbidden(Response):
    _status = '403 Forbidden'
    _template = "<html>Not allowed to mess with: '%s'</html>"


class BadRequest(Response):
    _status = "400 Bad Request"
    _template = "<html>%s</html>"


class Unauthorized(Response):
    _status = "401 Unauthorized"
    _template = "<html>%s</html>"


class NotFound(Response):
    _status = '404 NOT FOUND'


class NotAcceptable(Response):
    _status = '406 Not Acceptable'


class ServiceError(Response):
    _status = '500 Internal Service Error'


R2C = {
    200: Response,
    201: Created,
    302: Redirect,
    303: SeeOther,
    400: BadRequest,
    401: Unauthorized,
    403: Forbidden,
    404: NotAcceptable,
    406: NotAcceptable,
    500: ServiceError,
}


def factory(code, message):
    return R2C[code](message)


def extract(environ, empty=False, err=False):
    """Extracts strings in form data and returns a dict.

    :param environ: WSGI environ
    :param empty: Stops on empty fields (default: Fault)
    :param err: Stops on errors in fields (default: Fault)
    """
    formdata = cgi.parse(environ['wsgi.input'], environ, empty, err)
    # Remove single entries from lists
    for key, value in formdata.iteritems():
        if len(value) == 1:
            formdata[key] = value[0]
    return formdata


def geturl(environ, query=True, path=True):
    """Rebuilds a request URL (from PEP 333).

    :param query: Is QUERY_STRING included in URI (default: True)
    :param path: Is path included in URI (default: True)
    """
    url = [environ['wsgi.url_scheme'] + '://']
    if environ.get('HTTP_HOST'):
        url.append(environ['HTTP_HOST'])
    else:
        url.append(environ['SERVER_NAME'])
        if environ['wsgi.url_scheme'] == 'https':
            if environ['SERVER_PORT'] != '443':
                url.append(':' + environ['SERVER_PORT'])
        else:
            if environ['SERVER_PORT'] != '80':
                url.append(':' + environ['SERVER_PORT'])
    if path:
        url.append(getpath(environ))
    if query and environ.get('QUERY_STRING'):
        url.append('?' + environ['QUERY_STRING'])
    return ''.join(url)


def getpath(environ):
    """Builds a path."""
    return ''.join([quote(environ.get('SCRIPT_NAME', '')),
                    quote(environ.get('PATH_INFO', ''))])


def _expiration(timeout, time_format=None):
    if timeout == "now":
        return time_util.instant(time_format)
    else:
        # validity time should match lifetime of assertions
        return time_util.in_a_while(minutes=timeout, time_format=time_format)


def cookie_signature(seed, *parts):
    """Generates a cookie signature."""
    sha1 = hmac.new(seed, digestmod=hashlib.sha1)
    for part in parts:
        if part:
            sha1.update(part)
    return sha1.hexdigest()


def make_cookie(name, load, seed, expire=0, domain="", path="", timestamp=""):
    """
    Create and return a cookie

    :param name: Cookie name
    :param load: Cookie load
    :param seed: A seed for the HMAC function
    :param expire: Number of minutes before this cookie goes stale
    :param domain: The domain of the cookie
    :param path: The path specification for the cookie
    :param timestamp: A time stamp
    :return: A tuple to be added to headers
    """
    cookie = SimpleCookie()
    if not timestamp:
        timestamp = str(int(time.mktime(time.gmtime())))
    signature = cookie_signature(seed, load, timestamp)
    cookie[name] = "|".join([load, timestamp, signature])
    if path:
        cookie[name]["path"] = path
    if domain:
        cookie[name]["domain"] = domain
    if expire:
        cookie[name]["expires"] = _expiration(expire,
                                              "%a, %d-%b-%Y %H:%M:%S GMT")

    return tuple(cookie.output().split(": ", 1))


def parse_cookie(name, seed, kaka):
    """Parses and verifies a cookie value

    :param seed: A seed used for the HMAC signature
    :param kaka: The cookie
    :return: A tuple consisting of (payload, timestamp)
    """
    if not kaka:
        return None

    cookie_obj = SimpleCookie(kaka)
    morsel = cookie_obj.get(name)

    if morsel:
        parts = morsel.value.split("|")
        if len(parts) != 3:
            return None
            # verify the cookie signature
        sig = cookie_signature(seed, parts[0], parts[1])
        if sig != parts[2]:
            raise Exception("Invalid cookie signature")

        try:
            return parts[0].strip(), parts[1]
        except KeyError:
            return None
    else:
        return None


def cookie_parts(name, kaka):
    cookie_obj = SimpleCookie(kaka)
    morsel = cookie_obj.get(name)
    if morsel:
        return morsel.value.split("|")
    else:
        return None


def get_post(environ):
    # the environment variable CONTENT_LENGTH may be empty or missing
    try:
        request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    except ValueError:
        request_body_size = 0

    # When the method is POST the query string will be sent
    # in the HTTP request body which is passed by the WSGI server
    # in the file like wsgi.input environment variable.
    return environ['wsgi.input'].read(request_body_size)


def get_or_post(environ):
    _method = environ["REQUEST_METHOD"]

    if _method == "GET":
        data = environ.get["QUERY_STRING"]
    elif _method == "POST":
        data = get_post(environ)
    else:
        raise UnsupportedMethod(_method)

    return data


def wsgi_wrapper(environ, start_response, func, **kwargs):
    request = None
    try:
        request = environ["QUERY_STRING"]
    except KeyError:
        pass

    if not request:
        try:
            request = get_post(environ)
        except KeyError:
            pass

    kwargs["request"] = request
    # authentication information
    try:
        kwargs["authn"] = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        pass

    try:
        kwargs["cookie"] = environ["HTTP_COOKIE"]
    except KeyError:
        pass

    # intended audience
    kwargs["requrl"] = geturl(environ)
    kwargs["url"] = geturl(environ, query=False)
    kwargs["baseurl"] = geturl(environ, query=False, path=False)
    kwargs["path"] = getpath(environ)

    resp = func(**kwargs)
    return resp(environ, start_response)


class CookieDealer(object):
    def __init__(self, srv, ttl=5):
        self.srv = srv
        # minutes before the interaction should be completed
        self.cookie_ttl = ttl  # N minutes

    def delete_cookie(self, cookie_name=None):
        if cookie_name is None:
            cookie_name = self.srv.cookie_name
        return self.create_cookie("", "", cookie_name=cookie_name, ttl=-1, kill=True)

    def create_cookie(self, value, typ, cookie_name=None, ttl=-1, kill=False):
        if kill:
            ttl = -1
        elif ttl < 0:
            ttl = self.cookie_ttl
        if cookie_name is None:
            cookie_name = self.srv.cookie_name
        timestamp = str(int(time.mktime(time.gmtime())))
        info = aes_encrypt(self.srv.symkey,
                           "::".join([value, timestamp, typ]),
                           self.srv.iv)
        cookie = make_cookie(cookie_name, info, self.srv.seed,
                             expire=ttl, domain="", path="")
        return cookie

    def cookie_value(self, cookie=None, cookie_name=None):
        """
        Return information stored in the Cookie

        :param cookie:
        :param cookie_name: The name of the cookie I'm looking for
        :return: tuple (value, timestamp, type)
        """
        if cookie is None or cookie_name is None:
            return None
        else:
            try:
                info, timestamp = parse_cookie(cookie_name,
                                               self.srv.seed, cookie)
                value, _ts, typ = aes_decrypt(self.srv.symkey, info,
                                              self.srv.iv).split("::")
                if timestamp == _ts:
                    return value, _ts, typ
            except Exception:
                pass
        return None