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
import string
from urlparse import parse_qs
from StringIO import StringIO
from Cookie import SimpleCookie
from urllib import quote
from Crypto.Random import random
from dirg_util import time_util

from dirg_util.aes import AESCipher

class UnsupportedMethod(Exception):
    pass


class HttpHandler:
    GLOBAL_STATIC = "/opt/dirg/dirg-util/"

    image_map = {
        ".bmp": "image/bmp",
        ".cod": "image/cis-cod",
        ".gif": "image/gif",
        ".ief": "image/ief",
        ".png": "image/png",
        ".jpe": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".jpg": "image/jpeg",
        ".jfif": "image/pipeg",
        ".svg": "image/svg+xml",
        ".tif": "image/tiff",
        ".tiff": "image/tiff",
        ".ras": "image/x-cmu-raster",
        ".cmx": "image/x-cmx",
        ".ico": "image/x-icon",
        ".pnm": "image/x-portable-anymap",
        ".pbm": "image/x-portable-bitmap",
        ".pgm": "image/x-portable-graymap",
        ".ppm": "image/x-portable-pixmap",
        ".rgb": "image/x-rgb",
        ".xbm": "image/x-xbitmap",
        ".xpm": "image/x-xpixmap",
        ".xwd": "image/x-xwindowdump",
    }

    application_map = {
        ".evy": "application/envoy",
        ".fif": "application/fractals",
        ".spl": "application/futuresplash",
        ".hta": "application/hta",
        ".acx": "application/internet-property-stream",
        ".hqx": "application/mac-binhex40",
        ".doc": "application/msword",
        ".dot": "application/msword",
        ".*": "application/octet-stream",
        ".bin": "application/octet-stream",
        ".class": "application/octet-stream",
        ".dms": "application/octet-stream",
        ".exe": "application/octet-stream",
        ".lha": "application/octet-stream",
        ".lzh": "application/octet-stream",
        ".oda": "application/oda",
        ".axs": "application/olescript",
        ".pdf": "application/pdf",
        ".prf": "application/pics-rules",
        ".p10": "application/pkcs10",
        ".crl": "application/pkix-crl",
        ".ai": "application/postscript",
        ".eps": "application/postscript",
        ".ps": "application/postscript",
        ".rtf": "application/rtf",
        ".setpay": "application/set-payment-initiation",
        ".setreg": "application/set-registration-initiation",
        ".xla": "application/vnd.ms-excel",
        ".xlc": "application/vnd.ms-excel",
        ".xlm": "application/vnd.ms-excel",
        ".xls": "application/vnd.ms-excel",
        ".xlt": "application/vnd.ms-excel",
        ".xlw": "application/vnd.ms-excel",
        ".msg": "application/vnd.ms-outlook",
        ".sst": "application/vnd.ms-pkicertstore",
        ".cat": "application/vnd.ms-pkiseccat",
        ".stl": "application/vnd.ms-pkistl",
        ".pot": "application/vnd.ms-powerpoint",
        ".pps": "application/vnd.ms-powerpoint",
        ".ppt": "application/vnd.ms-powerpoint",
        ".mpp": "application/vnd.ms-project",
        ".wcm": "application/vnd.ms-works",
        ".wdb": "application/vnd.ms-works",
        ".wks": "application/vnd.ms-works",
        ".wps": "application/vnd.ms-works",
        ".hlp": "application/winhlp",
        ".bcpio": "application/x-bcpio",
        ".cdf": "application/x-cdf",
        ".z": "application/x-compress",
        ".tgz": "application/x-compressed",
        ".cpio": "application/x-cpio",
        ".csh": "application/x-csh",
        ".dcr": "application/x-director",
        ".dir": "application/x-director",
        ".dxr": "application/x-director",
        ".dvi": "application/x-dvi",
        ".gtar": "application/x-gtar",
        ".gz": "application/x-gzip",
        ".hdf": "application/x-hdf",
        ".ins": "application/x-internet-signup",
        ".isp": "application/x-internet-signup",
        ".iii": "application/x-iphone",
        ".js": "application/x-javascript",
        ".latex": "application/x-latex",
        ".mdb": "application/x-msaccess",
        ".crd": "application/x-mscardfile",
        ".clp": "application/x-msclip",
        ".dll": "application/x-msdownload",
        ".m13": "application/x-msmediaview",
        ".m14": "application/x-msmediaview",
        ".mvb": "application/x-msmediaview",
        ".wmf": "application/x-msmetafile",
        ".mny": "application/x-msmoney",
        ".pub": "application/x-mspublisher",
        ".scd": "application/x-msschedule",
        ".trm": "application/x-msterminal",
        ".wri": "application/x-mswrite",
        ".nc": "application/x-netcdf",
        ".pma": "application/x-perfmon",
        ".pmc": "application/x-perfmon",
        ".pml": "application/x-perfmon",
        ".pmr": "application/x-perfmon",
        ".pmw": "application/x-perfmon",
        ".p12": "application/x-pkcs12",
        ".pfx": "application/x-pkcs12",
        ".p7b": "application/x-pkcs7-certificates",
        ".spc": "application/x-pkcs7-certificates",
        ".p7r": "application/x-pkcs7-certreqresp",
        ".p7c": "application/x-pkcs7-mime",
        ".p7m": "application/x-pkcs7-mime",
        ".p7s": "application/x-pkcs7-signature",
        ".sh": "application/x-sh",
        ".shar": "application/x-shar",
        ".swf": "application/x-shockwave-flash",
        ".sit": "application/x-stuffit",
        ".sv4cpio": "application/x-sv4cpio",
        ".sv4crc": "application/x-sv4crc",
        ".tar": "application/x-tar",
        ".tcl": "application/x-tcl",
        ".tex": "application/x-tex",
        ".texi": "application/x-texinfo",
        ".texinfo": "application/x-texinfo",
        ".roff": "application/x-troff",
        ".t": "application/x-troff",
        ".tr": "application/x-troff",
        ".man": "application/x-troff-man",
        ".me": "application/x-troff-me",
        ".ms": "application/x-troff-ms",
        ".ustar": "application/x-ustar",
        ".src": "application/x-wais-source",
        ".cer": "application/x-x509-ca-cert",
        ".crt": "application/x-x509-ca-cert",
        ".der": "application/x-x509-ca-cert",
        ".pko": "application/ynd.ms-pkipko",
        ".zip": "application/zip",
        ".ogx": "application/ogg",
        ".anx": "application/annodex",
        ".xspf": "application/xspf+xml",
    }

    audio_map = {
        ".au": "audio/basic",
        ".snd": "audio/basic",
        ".mid": "audio/mid",
        ".rmi": "audio/mid",
        ".mp3": "audio/mpeg",
        ".aif": "audio/x-aiff",
        ".aifc": "audio/x-aiff",
        ".aiff": "audio/x-aiff",
        ".m3u": "audio/x-mpegurl",
        ".ra": "audio/x-pn-realaudio",
        ".ram": "audio/x-pn-realaudio",
        ".wav": "audio/x-wav",
        ".ogg": "audio/ogg",
        ".oga": "audio/ogg",
        ".spx": "audio/ogg",
        ".flac": "audio/flac",
        ".axa": "audio/annodex",
    }

    message_map = {
        ".mht": "message/rfc822",
        ".mhtml": "message/rfc822",
        ".nws": "message/rfc822",
    }

    text_map = {
        ".css": "text/css",
        ".323": "text/h323",
        ".htm": "text/html",
        ".html": "text/html",
        ".stm": "text/html",
        ".uls": "text/iuls",
        ".bas": "text/plain",
        ".c": "text/plain",
        ".h": "text/plain",
        ".txt": "text/plain",
        ".rtx": "text/richtext",
        ".sct": "text/scriptlet",
        ".tsv": "text/tab-separated-values",
        ".htt": "text/webviewhtml",
        ".htc": "text/x-component",
        ".etx": "text/x-setext",
        ".vcf": "text/x-vcard",
    }

    video_map = {
        ".mp2": "video/mpeg",
        ".mpa": "video/mpeg",
        ".mpe": "video/mpeg",
        ".mpeg": "video/mpeg",
        ".mpg": "video/mpeg",
        ".mpv2": "video/mpeg",
        ".mov": "video/quicktime",
        ".qt": "video/quicktime",
        ".lsf": "video/x-la-asf",
        ".lsx": "video/x-la-asf",
        ".asf": "video/x-ms-asf",
        ".asr": "video/x-ms-asf",
        ".asx.": "video/x-ms-asf",
        ".avi.": "video/x-msvideo",
        ".movie.": "video/x-sgi-movie",
        ".ogv": "video/ogg",
        ".axv": "video/annodex",
    }

    xworld_map = {
        ".flr": "x-world/x-vrml",
        ".vrml": "x-world/x-vrml",
        ".wrl": "x-world/x-vrml",
        ".wrz": "x-world/x-vrml",
        ".xaf": "x-world/x-vrml",
        ".xof": "x-world/x-vrml",
    }



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
            ending = '.'+path[::-1].split('.')[0][::-1]
            try:
                text = open(self.GLOBAL_STATIC + path).read()
            except IOError:
                text = open(path).read()
            if ending == ".ico":
                self.start_response('200 OK', [('Content-Type', "image/x-icon")])
            elif ending == ".html":
                self.start_response('200 OK', [('Content-Type', 'text/html')])
            elif ending == ".json":
                self.start_response('200 OK', [('Content-Type', 'application/json')])
            elif ending == ".txt":
                self.start_response('200 OK', [('Content-Type', 'text/plain')])
            elif ending == ".css":
                self.start_response('200 OK', [('Content-Type', 'text/css')])
            elif ending == ".js":
                self.start_response('200 OK', [('Content-Type', 'text/javascript')])
            elif ending == ".xml":
                self.start_response('200 OK', [('Content-Type', 'text/xml')])
            else:
                if ending in self.image_map:
                    self.start_response('200 OK', [('Content-Type', self.image_map[ending])])
                elif ending in self.application_map:
                    self.start_response('200 OK', [('Content-Type', self.application_map[ending])])
                elif ending in self.audio_map:
                    self.start_response('200 OK', [('Content-Type', self.audio_map[ending])])
                elif ending in self.message_map:
                    self.start_response('200 OK', [('Content-Type', self.message_map[ending])])
                elif ending in self.text_map:
                    self.start_response('200 OK', [('Content-Type', self.text_map[ending])])
                elif ending in self.video_map:
                    self.start_response('200 OK', [('Content-Type', self.video_map[ending])])
                elif ending in self.xworld_map:
                    self.start_response('200 OK', [('Content-Type', self.xworld_map[ending])])
            return [text]
        except IOError:
            return self.http404()

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
                if "CONTENT_TYPE" in environ and "application/json" in environ["CONTENT_TYPE"]:
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

class InvalidCookieSign(Exception):
    pass

class CookieDealer(object):
    def __init__(self, srv, ttl=5):
        self.srv = None
        self.init_srv(srv)
        # minutes before the interaction should be completed
        self.cookie_ttl = ttl  # N minutes
        self.pad_chr = " "

    def init_srv(self, srv):
        if srv:
            self.srv = srv

            for param in ["seed", "iv"]:
                if not getattr(srv, param, None):
                    setattr(srv, param, self.random_string())

    def random_string(self, _size=16):
        """
        Returns a string of random ascii characters or digits

        :param size: The length of the string
        :return: string
        """
        return "".join([random.choice(string.ascii_letters + string.digits) for _ in range(_size)])

    def delete_cookie(self, cookie_name=None):
        if cookie_name is None:
            cookie_name = self.srv.cookie_name
        return self.create_cookie("", "", cookie_name=cookie_name, ttl=-1, kill=True)

    def create_cookie(self, value, typ, cookie_name=None, ttl=-1, kill=False, path=""):
        if kill:
            ttl = -1
        elif ttl < 0:
            ttl = self.cookie_ttl
        if cookie_name is None:
            cookie_name = self.srv.cookie_name
        timestamp = str(int(time.mktime(time.gmtime())))
        _msg = "::".join([value, timestamp, typ])
        if self.srv.symkey:
            # Pad the message to be multiples of 16 bytes in length
            lm = len(_msg)
            _msg = _msg.ljust(lm + 16 - lm % 16, self.pad_chr)
            info = AESCipher(self.srv.symkey, self.srv.iv).encrypt(_msg)
        else:
            info = _msg
        cookie = make_cookie(cookie_name, info, self.srv.seed,
                             expire=ttl, domain="", path=path)
        return cookie

    def getCookieValue(self, cookie=None, cookie_name=None):
        return self.get_cookie_value(cookie, cookie_name)

    def get_cookie_value(self, cookie=None, cookie_name=None):
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
                if self.srv.symkey:
                    txt = AESCipher(self.srv.symkey, self.srv.iv).decrypt(info)
                    # strip spaces at the end
                    txt = txt.rstrip(self.pad_chr)
                else:
                    txt = info

                value, _ts, typ = txt.split("::")
                if timestamp == _ts:
                    return value, _ts, typ
            except (TypeError, AssertionError):
                pass
        return None