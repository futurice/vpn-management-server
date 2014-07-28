""" Views for VPN management user interface """

from django.template import RequestContext, loader
from django.contrib.auth import get_backends
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect
from django.conf import settings
from django.shortcuts import render_to_response, get_object_or_404
from auth import check_privileges, privilege_required
from ldap_auth.toolbox import get_user
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse



from tempfile import mkstemp
import os
import subprocess
from forms import UploadFileForm, SMSForm, PreferencesForm
import vpncert
from sign import sign, repository
from vpnapi.utils import *

def is_valid_session(request):
    if request.session.get("session_enabled"):
        return True
    return False

@login_required
def admin_view(request, template_name):
    if not request.user.is_superuser:
        raise PermissionDenied
    certmanager = vpncert.vpncert(request.user.username)
    certs = certmanager.list_all_certs()
    certs = sorted(certs, key=lambda cert: cert["not_after_days"])
    return render_to_response(template_name, {'certs': certs}, context_instance=RequestContext(request))

@login_required
def indexview(request, template_name):
    """ Index: shows user certificates """
    certmanager = vpncert.vpncert(request.user.username)
    certs = certmanager.listcerts()
    if not request.session.get('updated_repository'):
        request.session['updated_repository'] = True
        cert_repository = repository()
        cert_repository.prepare_repository()

    return render_to_response(template_name, {'certs': certs}, context_instance=RequestContext(request))

@login_required
def create_new(request, template_name):
    """ Start process of creating new VPN certificate """
    if request.method == "POST":
        if not request.session.test_cookie_worked():
            return render_to_response("please_enable_cookies.html", {}, context_instance=RequestContext(request))
        request.session.delete_test_cookie()
        form = PreferencesForm(request.POST)
        if form.is_valid():
            data = {'email': get_user(request.user.username)['mail'][0], 'computer_type': form.cleaned_data['computer_type'], 'computer_owner': form.cleaned_data['computer_owner'], 'employment': form.cleaned_data['employment']}
            request.session['preferences'] = data
            return HttpResponseRedirect(reverse('create_new_upload'))
    else:
        request.session.flush()
        request.session['session_enabled'] = True
        form = PreferencesForm()
    request.session.set_test_cookie()
    return render_to_response(template_name, {'form': form}, context_instance=RequestContext(request))
    

@login_required
def create_new_upload(request, template_name):
    """ Create new request (upload or paste) """
    errors = False
    if not is_valid_session(request):
        return HttpResponseRedirect(reverse('invalid_session'))

    if not request.session.get("preferences"):
        return HttpResponseRedirect(reverse('invalid_session'))
      
    if request.method == "POST":
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            #process
            filehandle, filename = mkstemp()
            os.close(filehandle)
            filehandle = open(filename, "w")
            chunks = ""
            if request.FILES.get('file'):
                for chunk in request.FILES['file'].chunks():
                    filehandle.write(chunk)
            else:
                filehandle.write(request.REQUEST.get('certificatefield'))
            filehandle.close()

            status, errors, fields = api_validate_csr(request.user.username, filename)
            request.session['fields'] = fields
            if status:
                request.session['csrfilename'] = filename
                return HttpResponseRedirect(reverse('create_new_csr'))
            else:
                # handle cleanup
                os.remove(filename)
    else:
        form = UploadFileForm()

    preferences = request.session.get("preferences")
    if not preferences:
        errors = []
        errors.append("Invalid preferences")
    user = request.user.username
    employment = ""
    owner = ""
    ctype = preferences["computer_type"].name
    if preferences["employment"].name != "":
        employment = preferences["employment"].name+"-"
    if preferences["computer_owner"].name != "":
        owner = preferences["computer_owner"].name+"-"
    cn = "%s-%s%s%s" % (user, employment, owner, ctype)

    request.session.set_test_cookie()
    return render_to_response(template_name, { 'form': form, 'errors': errors, 'preferences': preferences, 'cn': cn }, context_instance=RequestContext(request))

@login_required
def create_new_csr(request, template_name):
    """ Validates uploaded CSR """
    if not is_valid_session(request):
        return HttpResponseRedirect(reverse('invalid_session'))
    if not request.session.get("csrfilename"):
        return HttpResponseRedirect(reverse('invalid_session'))

    filename = request.session.get("csrfilename")

    status, errors, fields = api_validate_csr(request.user.username, filename)

    if not status:
        return HttpResponse("Umm, your CSR file just disappeared or corrupted. Oops.")
    
    return render_to_response(template_name, {'fields': fields}, context_instance=RequestContext(request))

@login_required
def create_new_send_password(request):
    """ Creates new password and sends it using SMS gateway on backupmaster """

    if not is_valid_session(request):
        return HttpResponseRedirect(reverse('invalid_session'))

    if not request.session.get("smssent"): # send SMS only once
        status = api_gen_and_send_password(request.user.username)
        if not status.get("valid_sms", True):
            return HttpResponseRedirect(reverse('invalid_session'))
        if not status.get("success"):
            return HttpResponse("Fatal error: %s" % status.get("message"))

        request.session['password'] = status.get("password")
        request.session['smssent'] = True

    return HttpResponseRedirect(reverse('create_new_password'))

@login_required
def create_new_password(request, template_name):
    if not is_valid_session(request):
        return HttpResponseRedirect(reverse('invalid_session'))

    error = None
    if request.method == "POST":
        form = SMSForm(request.POST)
        if form.is_valid():
            if form.cleaned_data['passwordfield'] == request.session.get('password'):
                if request.session.get("valid"):
                    return HttpResponseRedirect(reverse('create_new_finished'))

                preferences = request.session.get("preferences")
                email = preferences.get("email")

                api_sign_and_deploy(request.user.username, request.session["csrfilename"], email)
                request.session['valid'] = True # there is valid certificate
                return HttpResponseRedirect(reverse('create_new_finished'))

        error = "Invalid password. Password is case sensitive."
    else:
        form = SMSForm()
    return render_to_response(template_name, {'form': form, 'error': error}, context_instance=RequestContext(request))

@login_required
def create_new_finished(request, template_name):
    if not is_valid_session(request):
        return HttpResponseRedirect(reverse('invalid_session'))

    if not request.session.get('valid'):
        return HttpResponse("Nice try.")
    try:
        del request.session['password']
    except KeyError:
        pass
    fields = request.session['fields']

    return render_to_response(template_name, {'cn': fields["common_name"]}, context_instance=RequestContext(request))

def invalid_session(request, template_name):
    return render_to_response(template_name, {}, context_instance=RequestContext(request))

def invalid_phone(request, template_name):
    return render_to_response(template_name, {}, context_instance=RequestContext(request))

def login(request):
    return HttpResponse("Placeholder")
