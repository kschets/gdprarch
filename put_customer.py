#!/usr/bin/env python
import json
import requests
from requests.auth import HTTPBasicAuth

# r = requests.get("https://localhost:5000/tenant",verify=False,auth=HTTPBasicAuth("admin","passw0rd"))
# print r.text

"""
for i in range(50):
    suffix = "{:02d}".format(i)
    tenant_name = "tenant{:02d}".format(i)
    tenant_pwd = "passw{:02d}rd".format(i)
    tenant_salt = bcrypt.gensalt().encode("utf-8")
    hashed_pwd = bcrypt.hashpw(tenant_pwd.encode("utf-8"), tenant_salt)
    headers = {"content-type": "application/json"}
    form_data = {"naam": tenant_name, "password": hashed_pwd, "salt": tenant_salt}
    r = requests.post("https://localhost:5000/tenant",verify=False, headers=headers, auth=HTTPBasicAuth("admin","passw0rd"),data=json.dumps(form_data))
    print r.text

tenant_name = "StorageTeam"
headers = {"content-type": "application/json"}
payload = {"name": tenant_name,"company":"fortune500","street":"Notenstraat","number":12}
r = requests.post("http://localhost:5000/api/tenant",headers=headers, auth=HTTPBasicAuth("admin","passw0rd"),data=json.dumps(payload))
print r.text
# get the tenant id
r = requests.get("https://localhost:5000/tenant/{}".format(company),verify=False, headers=headers, auth=HTTPBasicAuth("admin","passw0rd"))
if "_id" in r.json():
    tenant_id = r.json()["_id"]
    # now add some admins for this tenant
    for acc_list in ("adm01","adm02","adm03","adm04","adm05","adm06","adm07","adm08","adm09","adm10"):
        acc_name = "{}_{}".format(acc_list,company)
        acc_pass = "pass_{}".format(acc_name)
        hashed_pwd = bcrypt.hashpw(acc_pass.encode("utf-8"), bcrypt.gensalt())
        payload = {"username": acc_name,"password": hashed_pwd,"tenant": tenant_id, "roles": ["admin"]}
        r = requests.post("https://localhost:5000/account", verify=False, headers=headers, auth=HTTPBasicAuth("admin","passw0rd"), data=json.dumps(payload))
        print r.text
else:
    print "company {}: id not found".format(company)
"""

tenant_id = "593f8a766cfe7a058aca1917"
headers = {"content-type": "application/json"}
# payload = {"username": "admin002","password":"passw0rd","tenant_id":tenant_id}
payload = {"name": "Filip","lastname":"Detest","mail":"filip.detest@testers.be"}
r = requests.post("http://localhost:5000/api/customer", headers=headers, auth=HTTPBasicAuth("admin002","passw0rd"),data=json.dumps(payload))
print r.text
