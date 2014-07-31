from django.http import HttpResponse

from .toolbox import *

def search_project_group(request):
    """
    This view returns a list of the project groups from the LDAP directory that
    contain the keyword 'q' passed as a parameter with the GET request.
    """
    if request.method == "GET":
        keyword = request.GET.get("q")
        response = ""
        if keyword:
            for group in get_project_groups(keyword):
                response += group + "\n"
        return HttpResponse(response, content_type="text/plain")

def search_username(request):
    """
    This view returns a list of usernames from the LDAP directory that contain
    the keyword 'q' passed as a parameter with the GET request.
    """
    if request.method == "GET":
        keyword = request.GET.get("q")
        response = ""
        if keyword:
            for username in get_usernames(keyword):
                response += username + "\n"
        return HttpResponse(response, content_type="text/plain")
