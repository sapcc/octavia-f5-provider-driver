# Copyright 2018 SAP SE
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from octavia_f5.restclient.as3classes import IRule
from octavia_f5.common import constants

PROXY_PROTOCOL_INITIATIOR = """when CLIENT_ACCEPTED {
    set proxyheader "PROXY TCP[IP::version] [getfield [IP::remote_addr] "%" 1] [getfield [IP::local_addr] "%" 1] [TCP::remote_port] [TCP::local_port]\\r\\n"
}
 
when SERVER_CONNECTED {
    TCP::respond $proxyheader
}"""
X_FORWARDED_FOR = """when HTTP_REQUEST {
    HTTP::header remove "X-Forwarded-For"
    HTTP::header insert "X-Forwarded-For" [getfield [IP::remote_addr] "%" 1]
}"""
X_FORWARDED_PORT = """when HTTP_REQUEST {
    HTTP::header remove "X-Forwarded-Port"
    HTTP::header insert "X-Forwarded-Port" [TCP::local_port]
}"""
X_FORWARDED_PROTO = """when CLIENT_ACCEPTED {
    if { [PROFILE::exists clientssl] } then {
        set client_protocol "https"
    } else {
        set client_protocol "http"
    }
}
when HTTP_REQUEST {
    HTTP::header remove "X-Forwarded-Proto"
    HTTP::header insert "X-Forwarded-Proto" $client_protocol
}"""
X_SSL_CLIENT_VERIFY = """when CLIENTSSL_CLIENTCERT {
    if { [SSL::cert count] > 0 }{
        set verify_result [SSL::verify_result]
    }
}
when HTTP_REQUEST {
    if { [info exists verify_result] } {
        HTTP::header insert "X-SSL-Client-Verify" $verify_result
    }
}"""
X_SSL_CLIENT_HAS_CERT = """when CLIENTSSL_CLIENTCERT {
  set cert_count [SSL::cert count]
}
when HTTP_REQUEST {
    if { [info exists cert_count] && $cert_count > 0 }{
        HTTP::header insert "X-SSL-CLIENT-HAS-CERT" 1
    } else {
        HTTP::header insert "X-SSL-CLIENT-HAS-CERT" 0
    }
}"""
X_SSL_CLIENT_ISSUER = """when CLIENTSSL_CLIENTCERT {
    if { [SSL::cert count] > 0 }{
        set issuer [X509::issuer [SSL::cert 0]]
    }
}
when HTTP_REQUEST {
    if { [info exists issuer] } {
        HTTP::header insert "X-SSL-Client-Issuer" $issuer
    }
}"""
X_SSL_CLIENT_DN = """when CLIENTSSL_CLIENTCERT {
    if { [SSL::cert count] > 0 }{
        set subject_dn [X509::subject [SSL::cert 0]]
    }
}
when HTTP_REQUEST {
    if { [info exists subject_dn] } {
        HTTP::header insert "X-SSL-Client-DN" $subject_dn
    }
}"""
X_SSL_CLIENT_CN = """proc x509CNExtract { str } {
    set res "CN notFound"
    foreach field [ split $str " "] {
        foreach { fname  fval } [ split $field "=" ]  break
        if { $fname eq "CN" } {
            set res $fval
            break
        }
    }
    return $res
}
when CLIENTSSL_CLIENTCERT {
    if { [SSL::cert count] > 0 }{
        set subject_cn [X509::issuer [SSL::cert 0]]
    }
}
when HTTP_REQUEST {
    if { [info exists subject_cn] } {
        HTTP::header insert "X-SSL-Client-CN" [call x509CNExtract $subject_cn]
    }
}"""
X_SSL_CLIENT_SHA1 = """when CLIENTSSL_CLIENTCERT {
    if { [SSL::cert count] > 0 }{
        set hash [X509::hash [SSL::cert 0]]
    }
}
when HTTP_REQUEST {
    if { [info exists hash] } {
        HTTP::header insert "X-SSL-Client-SHA1" $hash
    }
}"""
X_SSL_CLIENT_NOT_BEFORE = """when CLIENTSSL_CLIENTCERT {
    if { [SSL::cert count] > 0 }{
        set validity [X509::not_valid_before [SSL::cert 0]]
    }
}
when HTTP_REQUEST {
    if { [info exists validity] } {
        HTTP::header insert "X-SSL-Client-Not-Before" $validity
    }
}"""
X_SSL_CLIENT_NOT_AFTER = """when CLIENTSSL_CLIENTCERT {
    if { [SSL::cert count] > 0 }{
        set validity [X509::not_valid_after [SSL::cert 0]]
    }
}
when HTTP_REQUEST {
    if { [info exists validity] } {
        HTTP::header insert "X-SSL-Client-Not-After" $validity
    }
}"""


def get_proxy_irule():
    """
    Returns iRule for proxy protocol initiation.
    :return: iRule entity (tuple with iRule name and definition)
    """
    irule = IRule(PROXY_PROTOCOL_INITIATIOR,
                  remark="Insert Proxy Protocol Header V1")
    name = '{}proxy_protocol_initiator'.format(constants.PREFIX_IRULE)
    return name, irule


def get_header_irules(insert_headers):
    """
    Translate Octavia listener header insertions into F5 iRules.
    :param insert_headers: headers of listener (listener.insert_headers)
    :return: List of iRule entities (tuples with iRule name and definition)
    """

    # Entities is a list of tuples, which each describe AS3 objects
    # which may reference each other but do not form a hierarchy.
    entities = []
    if insert_headers.get('X-Forwarded-For', False):
        irule = IRule(X_FORWARDED_FOR,
                      remark="Insert X-Forwarded-For Header")
        entities.append(('irule_x_forwarded_for', irule))

    if insert_headers.get('X-Forwarded-Port', False):
        irule = IRule(X_FORWARDED_PORT,
                      remark="Insert X-Forwarded-Port Header")
        entities.append(('irule_x_forwarded_port', irule))

    if insert_headers.get('X-Forwarded-Proto', False):
        irule = IRule(X_FORWARDED_PROTO,
                      remark="Insert X-Forwarded-Proto Header")
        entities.append(('irule_x_forwarded_proto', irule))

    if insert_headers.get('X-SSL-Client-Verify', False):
        irule = IRule(X_SSL_CLIENT_VERIFY,
                      remark="Insert X-SSL-Client-Verify Header")
        entities.append(('irule_x_ssl_client_verify', irule))

    if insert_headers.get('X-SSL-Client-Has-Cert', False):
        irule = IRule(X_SSL_CLIENT_HAS_CERT,
                      remark="Insert X-SSL-Client-Has-Cert Header")
        entities.append(('irule_x_ssl_client_has_cert', irule))

    if insert_headers.get('X-SSL-Client-DN', False):
        irule = IRule(X_SSL_CLIENT_DN,
                      remark="Insert X-SSL-Client-DN Header")
        entities.append(('irule_x_ssl_client_dn', irule))

    if insert_headers.get('X-SSL-Client-CN', False):
        irule = IRule(X_SSL_CLIENT_CN,
                      remark="Insert X-SSL-Client-CN Header")
        entities.append(('irule_x_ssl_client_cn', irule))

    if insert_headers.get('X-SSL-Issuer', False):
        irule = IRule(X_SSL_CLIENT_ISSUER,
                      remark="Insert X-SSL-Client-Issuer Header")
        entities.append(('irule_x_ssl_client_issuer', irule))

    if insert_headers.get('X-SSL-Client-SHA1', False):
        irule = IRule(X_SSL_CLIENT_SHA1,
                      remark="Insert X-SSL-Client-SHA1 Header")
        entities.append(('irule_x_ssl_client_sha1', irule))

    if insert_headers.get('X-SSL-Client-Not-Before', False):
        irule = IRule(X_SSL_CLIENT_NOT_BEFORE,
                      remark="Insert X-SSL-Client-Not-Before Header")
        entities.append(('irule_x_ssl_client_not_before', irule))

    if insert_headers.get('X-SSL-Client-Not-After', False):
        irule = IRule(X_SSL_CLIENT_NOT_AFTER,
                      remark="Insert X-SSL-Client-Not-After Header")
        entities.append(('irule_x_ssl_client_not_after', irule))

    return entities