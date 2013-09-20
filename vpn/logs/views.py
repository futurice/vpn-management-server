from django.views.decorators.csrf import csrf_exempt
from django.template import RequestContext, loader
from django.http import HttpResponse, HttpResponseRedirect
from django.conf import settings
from django.shortcuts import render_to_response, get_object_or_404
from ldap_auth.toolbox import get_user
from django.core.exceptions import PermissionDenied
from django.views.decorators.http import require_POST, require_GET

import json

from models import *
from utils import ajax_request


@csrf_exempt
@require_POST
@ajax_request
def push_log_entries(request, server):
    data = request.POST.get("data", "")
    success_count = 0
    for item in json.loads(data):
        item = Log(server_name=server, **item)

        try:
            item.save()
            success_count += 1
        except:
            pass
    return {"status": "ok", "success": True, "count": success_count}

@require_GET
@ajax_request
def get_last_timestamp(request, server):
    last_item = Log.objects.latest("timestamp")
    return {"server": server, "timestamp": str(last_item)}

