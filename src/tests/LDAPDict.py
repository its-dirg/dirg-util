import unittest
import time
from dirg_util.dict import LDAPDict, ReadOnlyLDAPDictException

__author__ = 'haho0032'


class RuleRoleTest(unittest.TestCase):

    def __init__(self, methodName='runTest'):
        unittest.TestCase.__init__(self, methodName)

    def testSearcUserExists(self):

        ldap_settings = {
            "ldapuri": "ldaps://ldap.test.umu.se",
            "base": "dc=umu, dc=se",
            "filter_pattern": "(uid=%s)",
            "user": "",
            "passwd": "",
            "attr": [
                "eduPersonScopedAffiliation",
                "eduPersonAffiliation",
                "eduPersonPrincipalName",
                "givenName",
                "sn",
                "mail",
                "uid",
                "o",
                "c",
                "labeledURI",
                "ou",
                "displayName",
                "norEduPersonLIN"
            ],
            "keymap": {
                "mail": "email",
                "labeledURI": "labeledURL",
            },
            "static_values": {
                "eduPersonTargetedID": "one!for!all",
            },
            "exact_match": True,
            "firstonly_len1": True,
            "timeout": 15,
        }
        ldap_dict = LDAPDict(**ldap_settings)
        try:
            ldap_dict['daev0001'] = {}
            self.fail("Not allowed to update the dictionary")
        except ReadOnlyLDAPDictException as ex:
            pass
        user_dict = ldap_dict['pejo0100']
        self.assertTrue("eduPersonTargetedID" in user_dict)

