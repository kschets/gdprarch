#!/usr/bin/env python
import sys
import json
import random
import requests
from requests.auth import HTTPBasicAuth

create_tenants = True
create_accounts = True
create_customers = True

headers = {"Content-Type": "application/json"}
if create_tenants:
    for i in range(10):
        tenant_name = "tenant{:03d}".format(i)
        form_data = {"name": tenant_name}
        r = requests.post("http://localhost:5000/api/tenant", headers=headers,auth=HTTPBasicAuth("admin","passw0rd"),data=json.dumps(form_data))
        print r.text
        
if create_accounts:
    # get tenants
    r = requests.get("http://localhost:5000/api/tenant", headers=headers, auth=HTTPBasicAuth("admin","passw0rd"))
    if "tenant" in r.json():
        tenant_list = r.json()["tenant"]
        for tenant in tenant_list:
            # check if any accounts exist for this tenant
            r = requests.get("http://localhost:5000/api/account/{}".format(tenant["_id"]["$oid"]), headers=headers, auth=HTTPBasicAuth("admin","passw0rd"))
            if r.status_code == 404:
                # create accounts
                for i in range(10):
                    account_name = "{}_adm_{:03d}".format(tenant["name"], i)
                    account_pass = "{}_pass_{:03d}".format(tenant["name"],i)
                    form_data = {"username": account_name,"password": account_pass,"tenant":"{}".format(tenant["_id"]["$oid"])}
                    r = requests.post("http://localhost:5000/api/account", headers=headers,auth=HTTPBasicAuth("admin","passw0rd"),data=json.dumps(form_data))
                    print r.text
            else:
                print "Tenant {} has accounts defined".format(tenant["name"])
                
if create_customers:
    # get current customers per tenant, use a tenant admin to get
    r = requests.get("http://localhost:5000/api/tenant", headers=headers, auth=HTTPBasicAuth("admin","passw0rd"))
    if "tenant" in r.json():
        tenant_list = r.json()["tenant"]
        for tenant in tenant_list:
            # check if any accounts exist for this tenant
            r = requests.get("http://localhost:5000/api/account/{}".format(tenant["_id"]["$oid"]), headers=headers, auth=HTTPBasicAuth("admin","passw0rd"))
            if r.status_code == 404:
                # no accounts found, make sure to run the previous step
                sys.stderr.write("ERROR no accounts exist for tenant {}\n".format(tenant["name"]))
                sys.stderr.flush()
                sys.exit(1)
            else:
                account_list = r.json()["account"]
                # pick one
                account = random.choice(account_list)
                account_name = account["username"]
                account_pass = account_name.replace("adm","pass")
                # get the customers defined for this tenant
                r = requests.get("http://localhost:5000/api/customer", headers=headers, auth=HTTPBasicAuth(account_name,account_pass))
                if r.status_code == 404:
                    # no customer exists yet
                    for i in range(20):
                        customer_name = "{}_customer{:03d}".format(tenant["name"],i)
                        form_data = {"name": customer_name}
                        r = requests.post("http://localhost:5000/api/customer", headers=headers, auth=HTTPBasicAuth(account_name,account_pass),data=json.dumps(form_data))
                        print r.text
                
                
    
    
