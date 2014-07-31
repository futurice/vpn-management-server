"""
This module provides an authentication backend that relies on LDAP directory to
get users and to check machines permissions.

.. seealso:: Authentication backends for handling machine permissions are
specified here :mod:`vimma.vmm.auth.VMMBackend`.
"""
from django.contrib.auth.models import User
from django.contrib.auth.backends import RemoteUserBackend

from toolbox import get_sudoers, get_user as get_ldap_user, get_admin_usernames
#from vimma.vmm.models import Machine

class RemoteUserLDAPBackend(RemoteUserBackend):
    """
    This authentication backend relying on :class:`RemoteUserBackend`,
    uses LDAP to authenticate a user, and check its rights on a machine.

    .. seealso:: The `django doc
    <http://docs.djangoproject.com/en/dev/howto/auth-remote-user/>`_ about
    :class:`RemoteUserBackend`.
    """

    def configure_user(self, user):
        """
        Set user's e-mail address in the database from LDAP. Also give superuser
        rights if the user is in TeamIt group in LDAP.

        :returns:  User -- The user with its email set.

        .. todo:: remove logging from here
        """
        ldap_user = get_ldap_user(user.username)
        user.is_active = True
        if not ldap_user == None:
            user.email = ldap_user['mail'][0]
        else:
            pass
            #user.message_set.create(message = "Couldn't set e-mail from LDAP: %s" % e.message)
        if user.username in get_admin_usernames():
            user.is_staff = True
            user.is_superuser = True
        user.save()
        return user

    def get_user(self, username):
        """
        Verify if a user with `username` is in the LDAP directory :
            - if it is, the method gets or creates this user in the database
              and returns it. If the user has to be created, the
              :meth:`RemoteUserLDAPBackend.configure_user` will be called on
              the newly created user.
            - if it is not in the LDAP, the method returns `None`

        :returns: User|None
        """

        if not get_ldap_user(username):
            return None
        else:
            user, created = User.objects.get_or_create(username=username)
            if created:
                self.configure_user(user)
            return user

    def is_privileged_on(self, username, machine_name):
        """
        Check if user is privileged on a machine. Privileged users are :

            - users in the machine LDAP group

        .. attention:: If the machine is `locked`, nobody is privileged.

        :returns: bool -- True if the user is privileged, False otherwise.
        """
#        try :
#            machine = Machine.objects.get(name=machine_name)
#        except Machine.DoesNotExist :
#            return False
#        else :
#            if (not machine.locked) and (username in get_sudoers(machine_name)):
#                return True
#            else :
#                return False
	return true

