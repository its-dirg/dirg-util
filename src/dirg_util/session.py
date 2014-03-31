# -*- coding: utf-8 -*-
#
# Copyright (C) University
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
"""
The session class can be used as a session dictionary.

    session = Session(environ)
    print session["test"]
    session["test"] = 1

This makes it hard to know which parameter that can be used.

Extend this class and use getters and setters if you want to make it more easy to understand the content.
"""
from uuid import uuid4
import pickle
from dirg_util.dict import Sqllite3Dict
from dirg_util.http_util import CookieDealer


class Session(object):
    BEAKER = 'beaker.session'

    def __init__(self, environ):
        self.environ = environ

    def clear_session(self):
        session = self.environ[Session.BEAKER]
        for key in session:
            session.pop(key, None)
        session.save()

    def __setitem__(self, item, val):
        if item not in self.environ[Session.BEAKER]:
            self.environ[Session.BEAKER].get(item, val)
        self.environ[Session.BEAKER][item] = val

    def __getitem__(self, item):
        return self.environ[Session.BEAKER].get(item, None)

    def __contains__(self, item):
        return item in self.environ[Session.BEAKER]


class SessionSqllite3(object):

    def __init__(self, environ, cookie_name, dict_path):
        self.environ = environ
        self.cookie_dealer = CookieDealer()
        self.cookie_name = cookie_name
        self.session_dict = Sqllite3Dict(dict_path)

    def get_current_session(self, environ):
        session_key = self.cookie_dealer.get_cookie_value(self.get_cookie(), self.cookie_name)
        if session_key is None:
            session_key = uuid4().urn
            self.cookie_dealer.create_cookie(session_key, 'session', self.cookie_name)
            self.session_dict[session_key] = {}
        self.session_key = session_key
        return self

    def get_cookie(self):
        return self.environ['HTTP_COOKIE']

    def clear_session(self):
        for key in self.session_dict[self.session_key]:
            del self.session_dict[self.session_key][key]

    def __setitem__(self, item, val):
        self.session_dict[self.session_key][item] = val

    def __getitem__(self, key):
        return self.session_dict[self.session_key][key]

    def __contains__(self, item):
        return item in self.session_dict[self.session_key]

    def __delitem__(self, key):
        del self.session_dict[self.session_key][key]

    def keys(self):
        return self.session_dict[self.session_key].keys()
