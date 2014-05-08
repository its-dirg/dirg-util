import time

__author__ = 'haho0032'
# -*- coding: iso-8859-1 -*-
import os
import pickle
import os.path
import UserDict
from sqlite3 import dbapi2 as sqlite
import UserDict
import ldap
from _ldap import SCOPE_SUBTREE


class Sqllite3Dict(UserDict.DictMixin):
    def __init__(self, dict_path):
        self.dict_path = dict_path
        con = self.connect()
        con.execute("delete from data")
        con.commit()
        con.close()

    def connect(self):
        con = None
        if not os.path.isfile(self.dict_path):
            con = sqlite.connect(self.dict_path)
            con.execute("create table data (key PRIMARY KEY,value)")
        else:
            con = sqlite.connect(self.dict_path)
        return con

    def __getitem__(self, key):
        con = self.connect()
        row = con.execute("select value from data where key=?", (key,)).fetchone()
        if not row:
            raise KeyError
        item = row[0]
        con.close()
        item = pickle.loads(item)

        return item

    def __setitem__(self, key, item):
        con = self.connect()
        item = pickle.dumps(item)
        if con.execute("select key from data where key=?", (key,)).fetchone():
            con.execute("update data set value=? where key=?", (item, key))
        else:
            con.execute("insert into data (key,value) values (?,?)", (key, item))
        con.commit()
        con.close()

    def __delitem__(self, key):
        con = self.connect()
        if con.execute("select key from data where key=?", (key,)).fetchone():
            con.execute("delete from data where key=?", (key,))
            con.commit()
        else:
            con.close()
            raise KeyError
        con.close()

    def keys(self):
        con = self.connect()
        keys = [row[0] for row in con.execute("select key from data").fetchall()]
        con.close()
        return


class ReadOnlyLDAPDictException(Exception):
    pass


class TooWideLDAPSearchException(Exception):
    pass


class LDAPDict(UserDict.DictMixin):
    def __init__(self, ldapuri, base, filter_pattern, scope=SCOPE_SUBTREE, attr=None, user="", passwd="",
                 firsonly=False, keymap=None, attrsonly=False, static_values=None, exact_match=False,
                 firstonly_len1=False, timeout=15):
        self.ldapuri = ldapuri
        self.base = base
        self.filter_pattern = filter_pattern
        self.scope = scope
        self.attr = attr
        self.ldapuser = user
        self.ldappasswd = passwd
        self.firstonly = firsonly
        self.keymap = keymap
        self.static_values = static_values
        self.attrsonly = attrsonly
        self.exact_match = exact_match
        self.firstonly_len1 = firstonly_len1
        self.timeout=timeout*60
        self.cache_timeout = {}
        self.cache = {}

    def bind(self):
        self.ld = ldap.initialize(self.ldapuri)
        self.ld.protocol_version = ldap.VERSION3
        self.ld.simple_bind_s(self.ldapuser, self.ldappasswd)

    def __getitem__(self, key):
        if key in self.cache and key in self.cache_timeout:
            if (time.time() - self.cache_timeout[key]) > self.timeout:
                del self.cache_timeout[key]
                del self.cache[key]
        if key in self.cache:
            return self.cache[key]

        _filter = self.filter_pattern % key
        arg = [self.base, self.scope, _filter, self.attr, self.attrsonly]
        try:
            result = self.ld.search_s(*arg)
        except:
            try:
                self.ld.close()
            except:
                pass
            self.bind()
            result = self.ld.search_s(*arg)
        if len(result) == 1:
            # should only be one entry and the information per entry is
            # the tuple (dn, ava)
            newres = {}
            self.dict = result[0][1]
            for tmp_key, tmp_val in self.dict.items():
                if (self.firstonly and len(tmp_val) > 0) or (self.firstonly_len1 and len(tmp_val) == 1):
                    tmp_val = tmp_val[0].decode('utf-8', 'ignore')
                else:
                    for i in range(0, len(tmp_val)-1):
                        tmp_val[i] = tmp_val[i].decode('utf-8', 'ignore')
                if self.keymap is not None and tmp_key in self.keymap:
                    newres[self.keymap[tmp_key]] = tmp_val
                else:
                    if (not self.exact_match) or (self.exact_match and tmp_key in self.attr):
                        newres[tmp_key] = tmp_val
            if self.static_values is not None:
                newres.update(self.static_values)
            self.cache_timeout[key] = time.time()
            self.cache[key] = newres
            return newres
        if len(result) > 1:
            raise TooWideLDAPSearchException("You must have a more narrow ldap search!")
        return {}


    def __setitem__(self, key, item):
        raise ReadOnlyLDAPDictException("Forbidden to update items!")

    def __delitem__(self, key):
        raise ReadOnlyLDAPDictException("Forbidden to delete items!")