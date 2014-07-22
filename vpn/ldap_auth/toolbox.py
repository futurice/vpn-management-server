"""
The module :mod:`ldap_auth.toolbox`, is a toolbox of functions that allow to realize various operations (related to vmm) in the ldap directory.

In order for this module to work correctly, here are the settings that have to be defined :

:attr:`LDAP_SERVER`
    
    This string variable defines the LDAP server address

:attr:`LDAP_PASSWORD`
    
    This is LDAP password

.. note:: All LDAP calls are made synchronously.

.. todo:: this is no very robust. Would deserve more verifications, better testing and better error handling ; if it happen more used than now...
"""
from django.conf import settings
import ldap
import datetime
import re
import string
from random import choice

def get_binded_connection():
    """
    Returns a binded LDAP connection, with the LDAP parameters in defined in the settings.
    """
    con = ldap.initialize(settings.LDAP_SERVER)
    con.simple_bind_s(settings.LDAP_USER, settings.LDAP_PASSWORD)
    return con

def get_user(username) :
    """
    Returns a dictionnary containing the user's attributes as recorded in the LDAP directory ; or None if no user with such a username could be found. 
    
    The dictionnary has the following format : ::
    
        {"fieldname1": [<fieldvalue11>, <fieldvalue12>, ...], ...}
    """
    username = _unicode_to_str(username)
    con = get_binded_connection()
    user = con.search_s("ou=People,dc=Futurice,dc=com", ldap.SCOPE_ONELEVEL, "(&(objectClass=inetOrgPerson)(uid=%s))" % username)
    con.unbind_s()
    if user :
        return user[0][1]
    else :
        return None

def get_sudoers(machine_name) :
    """
    This function returns a list of usernames that are sudoers on the machine passed as a parameter.
    """
    machine_name = _unicode_to_str(machine_name)
    con = get_binded_connection()
    sudoers = con.search_s("ou=Hosts,ou=Groups,dc=Futurice,dc=com", ldap.SCOPE_ONELEVEL,
            "(&(objectClass=posixGroup)(uniqueMember=uid=*,ou=People,dc=Futurice,dc=com)(cn=%s))" % machine_name, ["uniqueMember"])
    con.unbind_s()
    if sudoers :
        return[re.match("^uid=(?P<uid>[a-z]{4}).*$", result).group("uid") for result in sudoers[0][1]["uniqueMember"]]
    else :
        return []

def get_free_uidNumber() :
    """
    Returns a user ID that is not yet in use in the LDAP.
    """
    #we find the first gid available
    con = get_binded_connection()
    nbrs = [int(result[1]["uidNumber"][0]) for result in\
                                  con.search_s("ou=People,dc=futurice,dc=com",
                                  ldap.SCOPE_SUBTREE, "(uidNumber=*)",  ['uidNumber'])]
    con.unbind_s()
    return max(nbrs) + 1

def get_project_groups(keyword):
    """
    This function returns a list of project groups that contains `keyword`, from the LDAP directory.
    """
    con = get_binded_connection()
    groups = [result[1]["cn"][0] for result in\
                                  con.search_s("ou=Projects,ou=Groups,dc=futurice,dc=com",
                                  ldap.SCOPE_SUBTREE, "(cn=*)",  ['cn'])]
    con.unbind_s()
    return filter(lambda proj: re.search(keyword, proj, re.IGNORECASE), groups)

def get_usernames(keyword):
    """
    This function returns a list of usernames that contains `keyword`, from the LDAP directory.
    """
    con = get_binded_connection()
    usernames = [result[1]["uid"][0] for result in\
                                  con.search_s("ou=People,dc=futurice,dc=com",
                                  ldap.SCOPE_SUBTREE, "(uid=*)",  ['uid'])]
    con.unbind_s()
    return filter(lambda username: re.search(keyword, username, re.IGNORECASE), usernames)

def get_admin_usernames():
    """
    This function returns the list of all the admins usernames
    """
    con = get_binded_connection()
    users = con.search_s("ou=Teams,ou=Groups,dc=futurice,dc=com",
                                  ldap.SCOPE_SUBTREE, "(cn=TeamIT)",  ['uniqueMember'])[0][1]["uniqueMember"]
    users = [user[4:8] for user in users]
    con.unbind_s()
    return users

def _unicode_to_str (a_str):
    """
    Transtype the unicode str passed as a parameter to a normal str. If the parameter is not a unicode, it returns it as it is.
    """
    if (isinstance(a_str, unicode)) :
        return str(a_str)
    else :
        return a_str
