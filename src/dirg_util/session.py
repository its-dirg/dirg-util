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


class Session:
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