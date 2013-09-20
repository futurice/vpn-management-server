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
    con.simple_bind_s("cn=vimma,dc=futurice,dc=com", settings.LDAP_PASSWORD)
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

def get_machine_group(machine_name) :
    """
    Returns a dictionnary containing the machine group's attributes as recorded in the LDAP directory ; or None if no group could be found for this machine name. 
    
    The dictionnary has the following format : ::
    
        {"fieldname1": [<fieldvalue11>, <fieldvalue12>, ...], ...} 
    """
    machine_name = _unicode_to_str(machine_name)
    con = get_binded_connection()
    machine_group = con.search_s("ou=Hosts,ou=Groups,dc=Futurice,dc=com", ldap.SCOPE_ONELEVEL,
                "(&(objectClass=posixGroup)(cn=%s))" % machine_name, ["cn"])
    con.unbind_s()
    if machine_group :
        return machine_group[0][1]
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

def create_machine_group(machine_name) :
    """
    This function creates a machine group in LDAP directory, and the sudoer group associated.

    :raises: ldap.ALREADY_EXISTS -- if the machine group or sudoer group already exist
    """
    machine_name = _unicode_to_str(machine_name)
    attrs = [("objectClass", ["labeledURIObject", "posixGroup", "groupofuniquenames", "top"]),
     ("cn", [machine_name]),
     ("description", ["access to %s.futurice.com" % machine_name]),
     ("gidNumber", [str(get_free_gidNumber())])
    ]
    con = get_binded_connection()
    con.add_s('cn=%s,ou=Hosts,ou=Groups,dc=futurice,dc=com' % machine_name, attrs)
    con.unbind_s()

def create_sudoer_group (machine_name) :
    """
    This function creates a sudoer group for a machine in LDAP directory.

    :raises: ldap.ALREADY_EXISTS -- if the sudoer group already exist
    """
    machine_name = _unicode_to_str(machine_name)
    attrs = [("objectClass", ["top", "sudoRole"]),
     ("cn", [machine_name]),
     ("description", ["access to %s.futurice.com" % machine_name]),
     ("sudoHost", ["%s.futurice.com" % machine_name]),
     ("sudoCommand", ["ALL"]),
     ("sudoRunAs", ["ALL"]),
     ("description", ["Permissions to use sudo on %s" % machine_name])
    ]
    con = get_binded_connection()
    con.add_s('cn=%s,ou=SUDOers,dc=futurice,dc=com' % machine_name, attrs)
    con.unbind_s()

def add_sudoer (sudoer_name, machine_name) :
    """
    This function add a sudoer to machine group and sudoer group.

    :param sudoer_name: The username of the sudoer to add. Should be 4 lowercase letters. 

    :raises: ldap.ALREADY_EXISTS -- if the sudoer already belong to the group.
    :raises: ldap.TYPE_OR_VALUE_EXISTS
    :raises: ldap.NO_SUCH_OBJECT -- if the sudoer or machine group doesn't exist
    """
    machine_name = _unicode_to_str(machine_name)
    sudoer_name = _unicode_to_str(sudoer_name)
    con = get_binded_connection()
    attrs = [(ldap.MOD_ADD, "sudoUser", sudoer_name)]
    con.modify_s('cn=%s,ou=SUDOers,dc=futurice,dc=com' % machine_name, attrs)
    attrs = [(ldap.MOD_ADD, "uniqueMember", "uid=%s,ou=People,dc=futurice,dc=com" % sudoer_name)]
    con.modify_s('cn=%s,ou=Hosts,ou=Groups,dc=futurice,dc=com' % machine_name, attrs)
    con.unbind_s()

def get_free_gidNumber() :
    """
    Returns a group ID that is not yet in use in the LDAP for machine groups.

    :raises: NoGIDfreeError -- If there are no free GID available in LDAP.
    """
    #we find the first gid available
    con = get_binded_connection()
    nbrs = [int(result[1]["gidNumber"][0]) for result in\
                                  con.search_s("ou=Hosts,ou=Groups,dc=futurice,dc=com",
                                  ldap.SCOPE_SUBTREE, "(gidNumber=*)",  ['gidNumber'])]
    con.unbind_s()
    gidNumber = max(nbrs) + 1
    if gidNumber <= 5999 :
        return gidNumber
    else :
        raise NoGIDfreeError

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

def create_ci_user(machine_name) :
    """
    Add user for continuous integration in LDAP directory.
    
    :returns: (username, password)
    :raises: ldap.ALREADY_EXISTS -- if the user already exist in the directory.
    """
    machine_name = _unicode_to_str(machine_name)
    user_name = "ci%s" % machine_name
    user_pw = _generate_password(10) 

    attrs = [("objectClass", ["top", "person", "organizationalPerson", "inetorgperson", "account", "posixAccount", "shadowAccount"]),
     ("cn", ["%s CI" % machine_name]),
     ("gidNumber", ["%s" % 2000]),
     ("homeDirectory", ["/home/ci/%s" % user_name]),
     ("sn", ["CI"]),
     ("uid", ["%s" % user_name]),
     ("uidNumber", [str(get_free_uidNumber())]),
     ("givenName", ["%s" % machine_name]),
     ("userPassword", ["%s" % user_pw]),
     ("shadowLastChange", ["%s" % (datetime.datetime.now() - datetime.datetime(1970, 1, 1)).days]),
     ("shadowMax", ["%s" % 360]),
     ("shadowMin", ["%s" % 10]),
     ("shadowWarning", ["%s" % 10])
    ]
    con = get_binded_connection()
    con.add_s('uid=%s,ou=People,dc=futurice,dc=com' % user_name, attrs)
    con.unbind_s()
    return user_name, user_pw

class NoGIDfreeError (Exception) :
    """
    This exception is raised in case there are no free group id in the LDAP directory
    """
    pass

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

def _generate_password(size):
    """
    Generates a password that contains at least one lower-case letter, one capital letter and one special character
    """
    while 1 :
        user_pw = ''.join([choice(string.letters + string.punctuation) for i in range(size)])
        if not re.search(r"[^\w\s]", user_pw):
            continue
        if not re.search(r"[a-b]", user_pw):
            continue
        if not re.search(r"[A-B]", user_pw):
            continue
        break
    return user_pw

def _unicode_to_str (a_str):
    """
    Transtype the unicode str passed as a parameter to a normal str. If the parameter is not a unicode, it returns it as it is.
    """
    if (isinstance(a_str, unicode)) :
        return str(a_str)
    else :
        return a_str
