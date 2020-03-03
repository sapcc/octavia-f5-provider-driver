# Copyright 2020 SAP SE
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

from octavia.certificates.common import local as local_common
from octavia.certificates.manager import cert_mgr


class NoopCertManager(cert_mgr.CertManager):
    def store_cert(self, context, certificate, private_key, intermediates=None, private_key_passphrase=None,
                   expiration=None, name=None):
        pass

    def get_cert(self, context, cert_ref, resource_ref=None, check_only=False, service_name=None):
        cert_data = {}

        # Self-Signed test.example key:
        cert_data['private_key'] = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDO1ZiNs+E/NBX9
yfWjojTILtHtD2yfYJxSn4QKYReoAb49SDczfR+N/0ncYDuwbKH6EjC7tl6t97lV
oM4ZbE0UZX0our0/WqE0TwKK6svS55iztbdB3rMBOVLtmwtCG6hyG1JYVEcW5OcX
u+pAVHuViWI1IGqt57/FfCUlJg0BeeS2fheSckRsmWITIdr9gIwR3eHIEHKjLiJH
e5xJKhUErrFS4DmYeh3ZC91q7KxBWObBBXgYD/Pg8NyVj9GvF3VFKlVhytH/coKt
zyiCx4NQs9Z+Ly/fvEQcHc7DJoXvdu6fFFfZjqpSaLngYCR0z7TfRfZYsCh13dt7
dYZyF4Q/AgMBAAECggEAXgEiNrUcmLc5j4EszVQ5nQn6iz3JZp5oLf0l6/m44Lj6
F6wsupARuV3f2fM67bJR4/BEiewXGAZRC6PsSA268pw1yD8nKBYu0jFevHh+brqn
4nWidqOaw+Gj2S3wbflYE5RrVo3nSXZ7uYPEsbwz9wDby72R/rwnosALudiTbKmC
GHKuoGxdpczRTB4ziOA6EOo71cdIFKsG9f3iTmSYjgbos9dI/PE+v0GH/7tZURDS
EwIyxenR6P3ri+Y+2eiE2+xZy1K3kvAyWOaBliL8oNSFwaOBl3+DV2KNsx7JiQGC
JceL7+7RMLlUFp5Dhb5eZlVCDB0U/fLM+GvPjQgBoQKBgQD3opJGex6LGXuuETYk
DSMEBmfMUOE1mG441e/ToBaoFeuj8Z4aXA3xFGIGRpvi7+DhddbWbIoFPOQL48w/
0c5voMZ7EDO2FCAeIgwYwB+U43ZQyDbAcJUfrG5n6yGmyqtz9pwHD72Vw0XUvS1y
EopnJA1Z/HLQM9iYE3KY9K/QFwKBgQDV0jMpBaF4bwcFZAY5NQ5H3gtq+23lBB9M
ZLuVrLZWX/4KJFKH2RnS3SxHch6wFK+0Q848Y8mFn9/gt2L6DB1AZC18S89uPd3j
0rqrRCwcQUKfWxjX/OutaPKncacUz3m3jHQ+gOBIfezlhCAYx8Y9PaOgxCOevgad
BU3JijKeGQKBgQDazBB0J7pf6r8lmF1+0wCaQNKbaubhhPH2U8hX8n2yO9P9AbHQ
1n8XAAxwQRjhFVNbwdN1l2cHo7pWawp/ZPACH0rfVvxppzSNi0Wm5LHCyosyawQ9
WfvYhXDzboRIK4/7oOxRLO40kdl0U0YBITKaWPdXB7+mB/kavSwmyyNANwKBgQCL
lyPhNxTYTBuYUFmjxVhiYLqxiB2RcqSAOg8gwtVzBE4UDux2Vax/NfcvWXhhWc/v
bojYcgjhHKOK0A5k0b3TCNONHuz3upn+ntdQ8jud4pj88fsBHtQ5rJcl65O5iU2c
H6zQFVDW4qbim+RcaSepWXFWhlX+z23/2rOSzI8JGQKBgADvpEmnndRFs4oDCPs7
SrFHMnr44JBz11aJs9tzOvTbox17xpgWeSxA0oppaa59B5HCp1EBT7IRtyuU7SBo
W3JrC0JjYlMhuH/qsooPi1eH+jYryrJlwsBwOwkOd5V4xPpDge5+2jWc06TGuaeC
f5IVJc3ipPIWWC8IW8+pClHq
-----END PRIVATE KEY-----""".encode("utf-8")

        cert_data['certificate'] = """-----BEGIN CERTIFICATE-----
MIICqjCCAZICCQC6b92nP8oPhTANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDDAx0
ZXN0LmV4YW1wbGUwHhcNMjAwMzAyMTU0MTU1WhcNMjEwMzAyMTU0MTU1WjAXMRUw
EwYDVQQDDAx0ZXN0LmV4YW1wbGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDO1ZiNs+E/NBX9yfWjojTILtHtD2yfYJxSn4QKYReoAb49SDczfR+N/0nc
YDuwbKH6EjC7tl6t97lVoM4ZbE0UZX0our0/WqE0TwKK6svS55iztbdB3rMBOVLt
mwtCG6hyG1JYVEcW5OcXu+pAVHuViWI1IGqt57/FfCUlJg0BeeS2fheSckRsmWIT
Idr9gIwR3eHIEHKjLiJHe5xJKhUErrFS4DmYeh3ZC91q7KxBWObBBXgYD/Pg8NyV
j9GvF3VFKlVhytH/coKtzyiCx4NQs9Z+Ly/fvEQcHc7DJoXvdu6fFFfZjqpSaLng
YCR0z7TfRfZYsCh13dt7dYZyF4Q/AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAAop
5YS7QPpDhGBs191rWgp00xnIJUtJfxvYJPdQ4M+yRAhlT3ioU4YLpEngLVsHtgtA
+NGw/zoSEZAnQ+BqmIbB6DX3nR83za/LSEr8f6O7rKQrnRR/mYiFj1baR+i3i6fF
76FdzA/1ERn4l5XoWsu+InUiKx6mfyQc1C/EUjHcMF8CY9AK2LpicDhxaF/wtzNh
83/U96EXvpvcyaRlOIIv4qNNA2VtP0vjKEqSwZaauwwaPBKGMXr8iwBBrfQJkt7k
xGfp3W7NmA9RJTWG7b7y1G5eZJZSKd7RqseUa6Xs5ddlirW5bNx6ebNBiwFTu+cX
Bn8MYJefqUlQYyi745g=
-----END CERTIFICATE-----""".encode("utf-8")
        return local_common.LocalCert(**cert_data)

    def delete_cert(self, context, cert_ref, resource_ref, service_name=None):
        pass

    def set_acls(self, context, cert_ref):
        pass

    def unset_acls(self, context, cert_ref):
        pass

    def get_secret(self, context, secret_ref):
        return ""
