import logging
import time
from dirg_util.aes import AESCipher
from dirg_util.http_util import CookieDealer, InvalidCookieSign


__author__ = 'haho0032'

#Add a logger for this class.
logger = logging.getLogger("dirg_util.auth")


class ToOld(Exception):
    pass


class CookieObject(object):
    def __init__(self):
        self.cookie_name = None
        self.symkey  = None
        self.iv = None
        self.seed = None
        self.ttl = None


class Authenticate(CookieDealer):
    def __init__(self, cookie_dict=None, cookie_object=None):
        self.aes_chipher = None
        if cookie_object is not None:
            CookieDealer.__init__(self, cookie_object)
        elif cookie_dict is not None:
            CookieDealer.__init__(self, self.create_cookie_object(cookie_dict), cookie_dict["ttl"])
        else:
            CookieDealer.__init__(self, None)

    def aes(self):
        if self.aes_chipher is None and self.srv is not None:
            self.aes_chipher = AESCipher(self.srv.symkey, self.srv.iv)
        return self.aes_chipher

    def encrypt_dict(self, dict):
        message = ""
        first = True
        for key, value in dict.iteritems():
            if not first:
                message += ","
            message += key + "::" + value
            first = False
        return self.aes().encrypt(message)

    def decrypt_dict(self, message):
        dict = {}
        if message is not None and len(message) > 1:
            message = self.aes().decrypt(message)
            items = message.split(",")
            for item in items:
                values = item.split("::")
                if len(values) == 2:
                    dict[values[0]] = values[1]
        return dict


    def encrypt_list(self, list):
        message = ""
        first = True
        for item in list:
            if not first:
                message += "::"
            message += item
            first = False
        return self.aes().encrypt(message)

    def decrypt_list(self, message):
        list = []
        if message is not None and len(message) > 1:
            message = self.aes().decrypt(message)
            items = message.split("::")
            for item in items:
                list.append(item)
        return list

    def set_cookie_object(self, cookie_object):
        if cookie_object is not None:
            self.srv = cookie_object

    def set_cookie_dict(self, cookie_dict):
        if cookie_dict is not None:
            self.srv = self.create_cookie_object(cookie_dict)

    def create_cookie_object(self, cookie_dict):
        if cookie_dict is not None:
            cookie_object = CookieObject()
            cookie_object.cookie_name = cookie_dict["cookie_name"]
            cookie_object.symkey = cookie_dict["symkey"]
            if "iv" not in cookie_dict:
                cookie_dict["iv"] = self.random_string()
            cookie_object.iv = cookie_dict["iv"]
            if "seed" not in cookie_dict:
                cookie_dict["seed"] = self.random_string()
            cookie_object.seed = cookie_dict["seed"]
            return cookie_object
        return None

    def dict_value(self, _dict, key):
        if isinstance(_dict[key], basestring):
            return _dict[key]
        else:
            return _dict[key][0]

    def can_use_cookie(self):
        if self.srv is not None:
            return True

    def create_response(self, *args, **kwargs):
        raise NotImplemented

    def verify(self, **kwargs):
        raise NotImplemented

    def create_authentication_cookie(self, uid, type="base"):
        cookie = None
        if self.can_use_cookie():
            cookie = self.create_cookie(uid, type)
        return cookie

    def authenticated_as(self, cookie=None, **kwargs):
        if not self.can_use_cookie():
            return None

        if cookie is None:
            return None
        else:
            logger.debug("kwargs: %s" % kwargs)

            try:
                val = self.getCookieValue(cookie, self.srv.cookie_name)
            except InvalidCookieSign:
                val = None

            if val is None:
                return None
            else:
                uid, _ts, type = val

            if type == "uam":  # shortlived
                _now = int(time.mktime(time.gmtime()))
                if _now > (int(_ts) + int(self.cookie_ttl * 60)):
                    logger.debug("Authentication timed out")
                    raise ToOld("%d > (%d + %d)" % (_now, int(_ts),
                                                    int(self.cookie_ttl * 60)))
            else:
                if "max_age" in kwargs and kwargs["max_age"]:
                    _now = int(time.mktime(time.gmtime()))
                    if _now > (int(_ts) + int(kwargs["max_age"])):
                        logger.debug("Authentication too old")
                        raise ToOld("%d > (%d + %d)" % (
                            _now, int(_ts), int(kwargs["max_age"])))

            return {"uid": uid}
