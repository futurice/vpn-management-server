""" Views for VPN management API """

from django.template import RequestContext, loader
from django.contrib.auth import get_backends
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect
from django.conf import settings
from django.shortcuts import render_to_response, get_object_or_404
from vpnconf.auth import check_privileges, privilege_required
from ldap_auth.toolbox import get_user
from django.core.exceptions import PermissionDenied
from django.views.decorators.csrf import csrf_exempt

import json
from tempfile import mkstemp
import os
import subprocess
import vpncert
from sign import sign, repository
from models import State
from utils import *
from piwikapi.tracking import PiwikTracker


@csrf_exempt
def post_csr(request):
    pt = PiwikTracker(settings.PIWIK_SITE_ID, request)
    pt.set_api_url(settings.PIWIK_SERVER_ADDRESS)
    pt.set_ip(request.META.get("REMOTE_ADDR"))
    
    if request.method == 'POST':
        try:
            State.objects.get(username=request.user.username).delete()
        except:
            pass
        session = State.objects.create(username=request.user.username)
        cert_repository = repository()
        cert_repository.prepare_repository()
        csr = request.REQUEST.get("csr")
        if csr is None:
            pt.do_track_page_view("API CSR: No CSR posted")
            return HttpResponse(json.dumps({"success": False, "message": "Invalid request. Post CSR."}))
        filehandle, filename = mkstemp()
        os.close(filehandle)
        filehandle = open(filename, "w")
        filehandle.write(csr)
        filehandle.close()
        status, errors, fields = api_validate_csr(request.user.username, filename)

        if not status:
            os.remove(filename)
            pt.do_track_page_view("API CSR: Invalid CSR posted")
            return HttpResponse(json.dumps({"success": False, "message": "Invalid CSR"}))

        session.valid_csr = True
        session.csr_filename = filename
        session.save()


        status = api_gen_and_send_password(request.user.username)
        if not status.get("success"):
            pt.do_track_page_view("API CSR: Generating and sending password failed")
            return HttpResponse(json.dumps(status))
        session.password = status.get("password")
        session.save()

        pt.do_track_page_view("API CSR: Successfully received CSR")
        return HttpResponse(json.dumps({"success": True}))
        
    else:
        pt.do_track_page_view("API CSR: Invalid request. Post CSR")
        return HttpResponse(json.dumps({"success": False, "message": "Invalid request. Post CSR."}))

@csrf_exempt
def post_verification(request):
    pt = PiwikTracker(settings.PIWIK_SITE_ID, request)
    pt.set_api_url(settings.PIWIK_SERVER_ADDRESS)
    pt.set_ip(request.META.get("REMOTE_ADDR"))

    try:
        session = State.objects.get(username=request.user.username)
    except:
        pt.do_track_page_view("API verification: no session available")
        return HttpResponse(json.dumps({"success": False, "message": "No session available."}))
    if session.expired():
        pt.do_track_page_view("API verification: session expired")
        return HttpResponse(json.dumps({"success": False, "message": "Session expired."}))
    if not session.valid_csr:
        pt.do_track_page_view("API verification: no valid CSR uploaded")
        return HttpResponse(json.dumps({"success": False, "message": "No valid CSR uploaded."}))
    
    if request.method == 'POST':
        password = request.REQUEST.get("password")
        if password is None:
            pt.do_track_page_view("API verification: missing password")
            return HttpResponse(json.dumps({"success": False, "message": "No password in request." }))

        valid_password = session.password
        csr_filename = session.csr_filename
        if password == valid_password:
            signing = api_sign_and_deploy(request.user.username, csr_filename)
            cn = signing.get_cn()
            if cn is None:
                pt.do_track_page_view("API verification: internal error while signing")
                return HttpResponse(json.dumps({"success": False, "message": "Internal error while signing."}))

            pt.do_track_page_view("API verification: ZIP created successfully")
            return HttpResponse(json.dumps({"success": True, "zip_url": "https://vpnmanagement.futurice.com/vpn/api/zip/%s.zip" % cn}))
        pt.do_track_page_view("API verification: wrong password")
        return HttpResponse(json.dumps({"success": False, "message": "Wrong password"}))

    else:
        pt.do_track_page_view("API verification: invalid request")
        return HttpResponse(json.dumps({"success": False, "message": "Invalid request. Post password."}))

