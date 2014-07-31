""" Views for VPN management API """

from django.http import HttpResponse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt

import json
from tempfile import mkstemp
import os
from sign import repository
from models import State
from utils import *


@csrf_exempt
def post_csr(request):
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
            return HttpResponse(json.dumps({"success": False,
                                            "message": "Invalid request. Post CSR."}))
        filehandle, filename = mkstemp()
        os.close(filehandle)
        filehandle = open(filename, "w")
        filehandle.write(csr)
        filehandle.close()
        status, errors, fields = api_validate_csr(request.user.username,
                                                  filename)

        if not status:
            os.remove(filename)
            return HttpResponse(json.dumps({"success": False,
                                            "message": "Invalid CSR"}))

        session.valid_csr = True
        session.csr_filename = filename
        session.save()


        status = api_gen_and_send_password(request.user.username)
        if not status.get("success"):
            return HttpResponse(json.dumps(status))
        session.password = status.get("password")
        session.save()

        return HttpResponse(json.dumps({"success": True}))
    else:
        return HttpResponse(json.dumps({"success": False,
                                        "message": "Invalid request. Post CSR."}))

@csrf_exempt
def post_verification(request):
    try:
        session = State.objects.get(username=request.user.username)
    except:
        return HttpResponse(json.dumps({"success": False,
                                        "message": "No session available."}))
    if session.expired():
        return HttpResponse(json.dumps({"success": False,
                                        "message": "Session expired."}))
    if not session.valid_csr:
        return HttpResponse(json.dumps({"success": False,
                                        "message": "No valid CSR uploaded."}))

    if request.method == 'POST':
        password = request.REQUEST.get("password")
        if password is None:
            return HttpResponse(json.dumps({"success": False,
                                            "message": "No password in request."}))

        valid_password = session.password
        csr_filename = session.csr_filename
        if password == valid_password:
            signing = api_sign_and_deploy(request.user.username, csr_filename)
            cn = signing.get_cn()
            if cn is None:
                return HttpResponse(json.dumps({"success": False,
                                                "message": "Internal error while signing."}))

            return HttpResponse(json.dumps({"success": True,
                                            "zip_url": settings.BASE_URL + "/api/zip/%s.zip" % cn}))
        return HttpResponse(json.dumps({"success": False, "message": "Wrong password"}))

    else:
        return HttpResponse(json.dumps({"success": False,
                                        "message": "Invalid request. Post password."}))

