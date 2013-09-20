"""
This module provide a custom authentication backend, view decorators to handle machine permissions and a validator for `username` form fields. The :class:`VMMBackend` can be seen as an interface specifying the methods that third-party authentication backends should provide to be used properly by the :mod:`vmm` application.  

.. seealso:: `Django authentication backends <http://docs.djangoproject.com/en/dev/topics/auth/#specifying-authentication-backends>`_

.. warning::
    As the interface is ambiguous on what the *get_user* method should take as a parameter, we specify that all our custom authentication backends must take a username as a parameter for this method.
"""
import re
from functools import wraps

from django.core.exceptions import PermissionDenied, ValidationError
from django.contrib.auth import get_backends
from django.contrib.auth.models import User
from django.contrib.auth.backends import ModelBackend

from models import *

class VMMBackend (ModelBackend):
    """
    This authentication backend mostly adds new methods to the standard :class:`ModelBackend` that ships with Django.
    """

    def get_user(self, username):
        """
        This overrides the *get_user* method of :class:`ModelBackend` to accept a *username* as a parameter instead of a database *id*.
        
        :returns: User|None

        .. todo:: when using Client.login, apparently it doesn't work if "get_user" doesn't accept a user id... django bug (I don't understand why the client would need this method)?
        """
        # to solve the bug
        if isinstance(username, int) :
            return super(VMMBackend, self).get_user(username)

        users = User.objects.filter(username=username)
        if users :
            return users[0]
        else :
            return None
    
    def is_privileged_on(self, username, machine_name):
        """
        Check if user is privileged on a machine. Privileged users are :
            
            - the machine owner
            - superusers
        
        .. attention:: If the machine is `locked`, nobody is privileged.

        :returns: bool -- True if the user is privileged, False otherwise and if the machine doesn't exist.
        """
        try :
            machine = Machine.objects.get(name=machine_name)
        except Machine.DoesNotExist :
            return False
        else :
            if machine.locked :
                return False
            
        user = self.get_user(username)
        if user and (user.is_superuser or machine.owner == user):
            return True
        else :
            return False

def validate_username (username):
    """
    This is a validator that returns the user whose username is `username`, but raises ValidationError if :

        - the user with `username` is couldn't be found in the authentication backends installed.
        - if the username contains something else than only letters
    """
    if not re.match(r'^\w+$', username):
        raise ValidationError("Username may only contain characters.")
    
    #We'll try the username against all the authentication backends provided in the settings.
    for auth_backend in get_backends() :
        try :
            user = auth_backend.get_user(str(username))
        except :
            pass

        if isinstance(user, User) and user.username == username :
            return user
    else :
        raise ValidationError("No such user.")
    

def check_privileges (view_func):
    """
    This is a decorator to put before a view. The view has to have the following signature : ::
        
        view_func(request, machine_name, **kwargs)

    The decorator sets a keyword argument `privileged` that the view can use. It is True if the user that issued the request is privileged on the machine, and False otherwise

    .. seealso:: the method :meth:`is_privileged_on` of the authentication backend you are using (those registered in the settings), for an explanation on how privilege is granted.
    """
    def _decorated_view (request, **kwargs):
        return True

    return wraps(view_func)(_decorated_view)

def privilege_required (view_func):
    """
    This is a decorator to put before a view. The view has to have the following signature : ::
        
        view_func(request, machine_name, **kwargs)
    
    :raise: PermissionDenied if the user that issued the request is not privileged on the machine.

    .. seealso:: the method :meth:`is_privileged_on` of the authentication backend you are using (those registered in the settings), for an explanation on how privilege is granted.
    """
    def _decorated_view (request, machine_name, **kwargs):
        if _is_privileged_on(request, machine_name) :
            return view_func(request, machine_name, **kwargs)
        else :
            raise PermissionDenied
    return wraps(view_func)(_decorated_view)

def _is_privileged_on(request, machine_name):
    """
    Return a bool telling whether a user that issued a request is privileged or not on a machine.
    """
    if not hasattr(request, "user") :
        return False
    else :
        username = request.user.username
        for auth_backend in get_backends():
            if hasattr(auth_backend, "is_privileged_on") :
                privileged = auth_backend.is_privileged_on(username, machine_name)
                if privileged :
                    return True
        return False
    
