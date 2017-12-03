#from django.template.loader import get_template
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
import django.db.models as models

from django.http import (
    HttpResponse,
    HttpResponseRedirect,
    JsonResponse,
    Http404,
    HttpResponseBadRequest,
)
from django.conf.urls import url
from rest_framework.decorators import api_view, parser_classes
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser

import datetime
import time
import logging as log

from easyca.settings import CA_PATH

import dev_ssl_ca as dev_ca


BASE_URL = "v1/"


def annotate_urls(items, request=None, tpl=None, key='url'):
    """
    Returns a new list from dicts with annotation. This does

    :param items: list of dicts to be annotated (left untouched)
    :param request: the request object used to derive hostname etc
    :param tpl: template with named objects like {id}
    :param key: key to add, defaults to 'url'
    :returns: a list of annotated dicts.
    """
    host = request.get_host()
    tpl = "http://{}/{}{}".format(host, BASE_URL, tpl)
    ret = []
    for item in items:
        item_copy = {}
        item_copy.update(item)
        item_copy[key] = tpl.format(**item)
        ret.append(item_copy)
    return ret

def annotate_url(item, request=None, tpl=None, key='url'):
    """
    Convinience function for a single item, see @annotate_urls
    """
    return annotate_urls([item], request=request, tpl=tpl, key=key)[0]


@api_view(['GET', 'POST'])
#@parser_classes((MultiPartParser,))
#  @login_required
def ca_all(request):
    """Lists all files readable by the current user"""
    method = request.method
    ca = dev_ca.CA(CA_PATH)

    if method == 'POST':
        keys = ['c', 'st', 'l', 'o', 'ou', 'cn', 'email']
        values = {}
        for key in keys:
            if request.data.get(key):
                values[key] = request.data.get(key)

        try:
            res = ca.initialize(
                dn=values
            )
            success = res['success']
            message = res['message']
        except Exception as e:
            success = False
            message = str(e)

        return Response({
            "message": message,
            "success": success,
        })
    res = ca.get_info()

    return Response(res)


@api_view(['GET', 'POST'])
#@parser_classes((MultiPartParser,))
#  @login_required
def csr_all(request):
    """Certificate Signing Request - GET to list, POST to sign"""
    method = request.method
    ca = dev_ca.CA(CA_PATH)

    if method == 'POST':
        if "csr" not in request.data:
            return HttpResponseBadRequest("required field 'csr' missing")
        csr = request.data['csr']
        log.warning("CSR is\n{}".format(csr))
        try:
            res = ca.sign_request(
                csr=csr,
            )
        except Exception as e:
            raise

        return Response(res)
    items = ca.list_requests()
    ret = []
    for item in items:
        ret.append({
            'id': item['id'],
            'last_modified': item.get('last_modified'),
        })

    annotated = annotate_urls(ret, request=request, tpl='csr/{id}')

    return Response(annotated)

@api_view(['GET'])
#@parser_classes((MultiPartParser,))
#  @login_required
def signed_all(request):
    """List all signed certificates"""
    ca = dev_ca.CA(CA_PATH)
    items = ca.list_certificates()

    ret = []
    for item in items:
        d = {}
        d.update(item)
        ret.append(d)

    annotated = annotate_urls(ret, request=request, tpl='signed/{id}')

    return Response(annotated)


@api_view(['GET'])
#@parser_classes((MultiPartParser,))
#  @login_required
def signed_single(request, serial):
    """View details of a single certificate"""
    ca = dev_ca.CA(CA_PATH)
    ret = ca.get_certificate(serial=serial)


#    ret = []
#    for name in names:
#        ret.append({
#            "id": name
#        })

#    annotated = annotate_urls(ret, request=request, tpl='signed/{id}')

    return Response(ret)


# http://www.tldp.org/HOWTO/SSL-Certificates-HOWTO/x195.html

@api_view(['GET', 'POST'])
@parser_classes((MultiPartParser,))
def self_signed_all(request):
    method = request.method

    if method == 'POST':
        dn = dict(cn='Dev Certificate by EasyCA (self-signed)')
        res = dev_ca.create_self_signed(dn=dn)

        return Response(res)
#        raise ValueError("Not implemented")

    res = []

    return Response(res)



urlpatterns = [
    url(r'^{}ca/$'.format(BASE_URL), ca_all),
    url(r'^{}signed/$'.format(BASE_URL), signed_all),
    url(r'^{}signed/(?P<serial>[a-fA-F0-9]+)$'.format(BASE_URL), signed_single),
#    url(r'^{}ca/(?P<item_id>[0-9]+)$'.format(BASE_URL), file_single),
    url(r'^{}self-signed/$'.format(BASE_URL), self_signed_all),
    url(r'^{}csr/$'.format(BASE_URL), csr_all),

]