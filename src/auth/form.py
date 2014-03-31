import logging
import string
from urlparse import parse_qs
from pyYubitool.yubikeyutil import YubikeyValidation
from auth.base import Authenticate
from dirg_util.http_util import Response, HttpHandler, Unauthorized, Redirect

__author__ = 'haho0032'

#Add a logger for this class.
logger = logging.getLogger("dirg_util.auth")


class DirgUsernamePasswordYubikeyMako(Authenticate):

    def __init__(self, username_query_key, mako_template, template_lookup, pwd=None, password_query_key=None,
                 yubikey_db=None, yubikey_server=None, yubikey_otp_key=None,cookie_dict=None, cookie_object=None):
        """

        """
        Authenticate.__init__(self, cookie_dict, cookie_object)
        self.username_query_key = username_query_key
        self.password_query_key = password_query_key
        self.yubikey_db = yubikey_db
        self.yubikey_server = yubikey_server
        self.yubikey_otp_key = yubikey_otp_key
        self.mako_template = mako_template
        self.template_lookup = template_lookup
        self.passwd = pwd
        self.yubikey_validator = None
        if self.yubikey_server is not None:
            self.yubikey_validator = YubikeyValidation(self.yubikey_server)

    def create_response(self, argv=None, cookie=None, **kwargs):
        """
        Put up the login form
        """
        if cookie:
            headers = [cookie]
        else:
            headers = []

        resp = Response(headers=headers)

        logger.info("do_authentication argv: %s" % argv)
        mte = self.template_lookup.get_template(self.mako_template)
        resp.message = mte.render(**argv)
        return resp

    def verify(self, request, **kwargs):
        """
        Verifies that the given username and password was correct
        :param request: Either the query part of a URL a urlencoded
            body of a HTTP message or a parse such.
        :param kwargs: Catch whatever else is sent.
        :return: redirect back to where ever the base applications
            wants the user after authentication.
        """

        logger.debug("verify(%s)" % request)
        if isinstance(request, basestring):
            _dict = parse_qs(request)
        elif isinstance(request, dict):
            _dict = request
        else:
            raise ValueError("Wrong type of input")

        username = None
        password = None

        if isinstance(_dict[self.username_query_key], basestring):
            username = _dict[self.username_query_key]
        else:
            username = _dict[self.username_query_key][0]

        valid = False

        if self.password_query_key is not None:
            if isinstance(_dict[self.password_query_key], basestring):
                password = _dict[self.password_query_key]
            else:
                password = _dict[self.password_query_key][0]
            # verify username and password
            try:
                if self.passwd is not None:
                    valid = password == self.passwd[username]
                if not valid:
                    return False, None, None, None
            except (AssertionError, KeyError):
                if not valid:
                    return False, None, None, None

        if self.yubikey_otp_key is not None and self.yubikey_validator is not None and self.yubikey_db is not None:
            # verify username and password
            otp = None
            if isinstance(_dict[self.yubikey_otp_key], basestring):
                otp = _dict[self.yubikey_otp_key]
            else:
                otp = _dict[self.yubikey_otp_key][0]
            if otp is not None:
                try:
                    valid = self.yubikey_validator.validate_opt(username, otp, self.yubikey_db, 0)
                    if not valid:
                        return False, None, None, None
                except (AssertionError, KeyError):
                    if not valid:
                        return False, None, None, None

        if valid:
            return True, username, _dict

        return False, None, None, None
