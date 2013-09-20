import os
from django.conf.urls.defaults import *
from django.conf import settings
from django.contrib.auth.views import login, logout
from django.contrib import admin
from django.views.generic.simple import direct_to_template

from django.contrib import admin
admin.autodiscover()

from vpn.vpnconf.views import indexview, create_new, create_new_csr, create_new_password, create_new_finished, create_new_send_password, invalid_session, create_new_upload, invalid_phone, admin_view
from vpn.vpnapi.views import post_csr, post_verification

from vpn.logs.views import push_log_entries, get_last_timestamp

from django.http import HttpResponse

def ping(request):
    return HttpResponse('status: OK')

urlpatterns = patterns('',
    url(r'^ping/$', ping),
    url(r'^logs/update/push_entries/(?P<server>[a-z]+)$', push_log_entries, name='push_log_entries'),
    url(r'^logs/update/get_last_timestamp/(?P<server>[a-z]+)$', get_last_timestamp, name='get_last_timestamp'),
    url(r'^api/post_csr', post_csr),
    url(r'^api/post_verification', post_verification),

    url(r'^accounts/login', 'vpn.vpnconf.views.login'),
    url(r'^$', 'django.views.generic.simple.redirect_to', {'url': '/vpn/vpnconf/'}),

    url(r'^vpnconf/$', indexview, name="index", kwargs={"template_name": "index.html"}),

    url(r'^vpnconf/create_new$', create_new, name='create_new', kwargs={"template_name": "create_new.html"}),
    url(r'^vpnconf/admin$', admin_view, name='admin_list', kwargs={"template_name": "admin_view.html"}),
    url(r'^vpnconf/invalid_session$', invalid_session, name='invalid_session', kwargs={"template_name": "invalid_session.html"}),
    url(r'^vpnconf/invalid_phone$', invalid_phone, name='invalid_phone', kwargs={"template_name": "invalid_phone.html"}),
    url(r'^vpnconf/create_new/upload$', create_new_upload, name='create_new_upload', kwargs={"template_name": "create_new_upload.html"}),
    url(r'^vpnconf/create_new/csr$', create_new_csr, name='create_new_csr', kwargs={"template_name": "create_new_csr.html"}),
    url(r'^vpnconf/create_new/send_password$', create_new_send_password, name='create_new_send_password', kwargs={}),
    url(r'^vpnconf/create_new/password$', create_new_password, name='create_new_password', kwargs={"template_name": "create_new_password.html"}),
    url(r'^vpnconf/create_new/finished$', create_new_finished, name='create_new_finished', kwargs={"template_name": "create_new_finished.html"}),
    url(r'^vpn/static/(?P<path>.*)$', 'django.views.static.serve',  {'document_root': os.path.join(os.path.dirname(__file__), 'static')}),
    (r'^admin/', include(admin.site.urls)),
)
