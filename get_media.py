#!/usr/bin/env python
import json
import requests
from requests.auth import HTTPBasicAuth

customer_id = "59413e246cfe7a0f2e6788bf" # tenant000_customer006
file_id = "594144fb6cfe7a0f89a41641"
tenant_adm = "tenant000_adm_005"
tenant_pass = "tenant000_pass_005"
# files = {'swarm_pdf': ('Swarm_SDK.pdf', open('/home/koen/Swarm_SDK.pdf', 'rb'), 'application/pdf')}
res = requests.get("http://localhost:5000/api/file/{}/{}".format(customer_id,file_id), auth=HTTPBasicAuth(tenant_adm,tenant_pass))
fh = open("/tmp/download.pdf","wb")
fh.write(res.content)
fh.close()
