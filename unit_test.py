#!/usr/bin/env python
#
# Test the GDPR Archive backend
#
import sys
import json
import random
import string
import requests
from requests.auth import HTTPBasicAuth
import cStringIO

create_tenants = True
create_accounts = True
create_customers = True
create_files = True
test_customer = True
test_delete = True

num_tenants = 20
num_accounts = 50
num_customers = 30
num_files = 50

def print_banner(content):
    banner_len = len(content) + 10
    print "=" * banner_len
    print "     " + content.upper()
    print "=" * banner_len
    
headers = {"Content-Type": "application/json"}

if create_tenants:
    print_banner("CREATE TENANTS START ")
    for i in range(num_tenants):
        tenant_name = "tenant{:03d}".format(i)
        form_data = {"name": tenant_name}
        r = requests.post("http://localhost:5000/api/tenant", headers=headers,auth=HTTPBasicAuth("admin","passw0rd"),data=json.dumps(form_data))
        print r.text
    print_banner("CREATE TENANTS END ")
        
if create_accounts:
    print_banner("CREATE ACCOUNTS START ")
    # get tenants
    r = requests.get("http://localhost:5000/api/tenant", headers=headers, auth=HTTPBasicAuth("admin","passw0rd"))
    if "tenant" in r.json():
        tenant_list = r.json()["tenant"]
        for tenant in tenant_list:
            # check if any accounts exist for this tenant
            r = requests.get("http://localhost:5000/api/account/{}".format(tenant["_id"]["$oid"]), headers=headers, auth=HTTPBasicAuth("admin","passw0rd"))
            if r.status_code == 404:
                # none found, first create the tenant admin account
                tenant_admin_name = "{}_admin".format(tenant["name"])
                tenant_admin_pass = "{}_admin".format(tenant["name"])
                form_data = {"username": tenant_admin_name,"password": tenant_admin_pass,"parent":"{}".format(tenant["_id"]["$oid"]),"role":"tenant_admin"}
                r = requests.post("http://localhost:5000/api/account", headers=headers,auth=HTTPBasicAuth("admin","passw0rd"),data=json.dumps(form_data))
                print r.text
                if r.status_code == 200:
                    # tenant admin created, now use the tenant admin to create the customer admins
                    for i in range(num_accounts):
                        account_name = "{}_customeradmin_{:03d}".format(tenant["name"], i)
                        account_pass = "{}_customeradmin_{:03d}".format(tenant["name"], i)
                        form_data = {"username": account_name,"password": account_pass,"parent":"{}".format(tenant["_id"]["$oid"]),"role":"customer_admin"}
                        r = requests.post("http://localhost:5000/api/account", headers=headers,auth=HTTPBasicAuth(tenant_admin_name,tenant_admin_pass),data=json.dumps(form_data))
                        print r.text
            else:
                print "Tenant {} has accounts defined".format(tenant["name"])
    print_banner("CREATE ACCOUNTS END ")
                
if create_customers:
    print_banner("CREATE CUSTOMERS START")
    # get current customers per tenant, use a tenant admin to get
    r = requests.get("http://localhost:5000/api/tenant", headers=headers, auth=HTTPBasicAuth("admin","passw0rd"))
    if "tenant" in r.json():
        tenant_list = r.json()["tenant"]
        for tenant in tenant_list:
            tenant_admin_name = "{}_admin".format(tenant["name"])
            tenant_admin_pass = "{}_admin".format(tenant["name"])
            # check if any accounts exist for this tenant
            # r = requests.get("http://localhost:5000/api/account/{}".format(tenant["_id"]["$oid"]), headers=headers, auth=HTTPBasicAuth(tenant_admin_name,tenant_admin_pass))
            r = requests.get("http://localhost:5000/api/account", headers=headers, auth=HTTPBasicAuth(tenant_admin_name,tenant_admin_pass))
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
                # account_pass = account_name.replace("adm","pass")
                account_pass = account_name
                # get the customers defined for this tenant
                r = requests.get("http://localhost:5000/api/customer", headers=headers, auth=HTTPBasicAuth(account_name,account_pass))
                if r.status_code == 404:
                    # no customer exists yet
                    for i in range(num_customers):
                        customer_name = "{}_customer{:03d}".format(tenant["name"],i)
                        form_data = {"name": customer_name}
                        r = requests.post("http://localhost:5000/api/customer", headers=headers, auth=HTTPBasicAuth(account_name,account_pass),data=json.dumps(form_data))
                        print r.text
    print_banner("CREATE CUSTOMERS END")
                
if create_files:
    print_banner("CREATE FILES START ")
    # get current customers per tenant, use a tenant admin to get
    r = requests.get("http://localhost:5000/api/tenant", headers=headers, auth=HTTPBasicAuth("admin","passw0rd"))
    print r.text
    if "tenant" in r.json():
        tenant_list = r.json()["tenant"]
        for tenant in tenant_list:
            print "current tenant : {}".format(tenant)
            # check if any accounts exist for this tenant
            r = requests.get("http://localhost:5000/api/account/{}".format(tenant["_id"]["$oid"]), headers=headers, auth=HTTPBasicAuth("admin","passw0rd"))
            if r.status_code == 404:
                # no accounts found, make sure to run the previous step
                sys.stderr.write("ERROR no accounts exist for tenant {}\n".format(tenant["name"]))
                sys.stderr.flush()
                sys.exit(1)
            else:
                account_list = r.json()["account"]
                print "found {} accounts for tenant {}".format(len(account_list), tenant)
                # pick one
                account = random.choice(account_list)
                account_name = account["username"]
                # account_pass = account_name.replace("adm","pass")
                account_pass = account_name
                # get the customers defined for this tenant
                r = requests.get("http://localhost:5000/api/customer", headers=headers, auth=HTTPBasicAuth(account_name,account_pass))
                if "customer" in r.json():
                    customer_list = r.json()["customer"]
                    print "found {} customers for tenant {}".format(len(customer_list), tenant)
                    for customer in customer_list:
                        print "generating files for customer {}".format(customer)
                        # upload files to each customer
                        for i in range(num_files):
                            file_name = "{}_{}_file{:03d}".format(tenant["name"], customer["name"], i)
                            file_handle = cStringIO.StringIO()
                            file_handle.seek(0,0)
                            for r in range(500):
                                n = random.choice(string.ascii_uppercase + string.digits)
                                file_handle.write(n)
                            file_handle.seek(0,0)
                            files = {file_name: ("{}.txt".format(file_name), file_handle, "application/txt")}
                            r = requests.post("http://localhost:5000/api/file/{}".format(customer["_id"]["$oid"]), auth=HTTPBasicAuth(account_name,account_pass), files=files)
                            print r.text
    print_banner("CREATE FILES END ")
    
if test_customer:
    print_banner("TEST CUSTOMER ACCESS START ")
    r = requests.get("http://localhost:5000/api/tenant", headers=headers, auth=HTTPBasicAuth("admin","passw0rd"))
    if "tenant" in r.json():
        tenant_list = r.json()["tenant"]
        for tenant in tenant_list:
            tenant_admin_name = "{}_admin".format(tenant["name"])
            tenant_admin_pass = "{}_admin".format(tenant["name"])
            # get the customers
            r = requests.get("http://localhost:5000/api/customer", headers=headers, auth=HTTPBasicAuth(tenant_admin_name,tenant_admin_pass))
            if "customer" in r.json():
                customer_list = r.json()["customer"]
                for customer in customer_list:
                    print "creating an account for customer {}".format(customer)
                    account_name = "acc_{}".format(customer["name"])
                    # if the account exists already we can skip the post
                    r = requests.get("http://localhost:5000/api/account/{}".format(account_name), headers=headers,auth=HTTPBasicAuth(tenant_admin_name,tenant_admin_pass))
                    if r.status_code == 200:
                        print "{} exists already".format(account_name)
                    else:
                        print "{} about to be created".format(account_name)
                        form_data = {"username": account_name ,"password": account_name ,"parent":"{}".format(customer["_id"]["$oid"]),"role":"customer"}
                        r = requests.post("http://localhost:5000/api/account", headers=headers,auth=HTTPBasicAuth(tenant_admin_name,tenant_admin_pass),data=json.dumps(form_data))
                        print r.text
                # get the customer record
                for customer in customer_list:
                    print "getting customer record for customer {}".format(customer)
                    account_name = "acc_{}".format(customer["name"])
                    r = requests.get("http://localhost:5000/api/customer", headers=headers, auth=HTTPBasicAuth(account_name,account_name))
                    print r.text
                # get the customer file list
                for customer in customer_list:
                    print "getting files for customer {}".format(customer)
                    account_name = "acc_{}".format(customer["name"])
                    customer_id = customer["_id"]["$oid"]
                    r = requests.get("http://localhost:5000/api/file", headers=headers, auth=HTTPBasicAuth(account_name,account_name))
                    if "file" in r.json():
                        file_list = r.json()["file"]
                        for file_obj in file_list:
                            # get the file
                            file_id = file_obj["_id"]["$oid"]
                            r = requests.get("http://localhost:5000/api/file/{}/{}".format(customer_id,file_id), headers=headers, auth=HTTPBasicAuth(account_name,account_name))
                            print r.text
    print_banner("TEST CUSTOMER ACCESS END ")

if test_delete:
    print_banner("TEST DELETE START")
    r = requests.get("http://localhost:5000/api/tenant", headers=headers, auth=HTTPBasicAuth("admin","passw0rd"))
    if "tenant" in r.json():
        tenant_list = r.json()["tenant"]
        for tenant in tenant_list:
            tenant_admin_name = "{}_admin".format(tenant["name"])
            tenant_admin_pass = "{}_admin".format(tenant["name"])
            # get the customers
            r = requests.get("http://localhost:5000/api/customer", headers=headers, auth=HTTPBasicAuth(tenant_admin_name,tenant_admin_pass))
            if "customer" in r.json():
                customer_list = r.json()["customer"]
                for customer in customer_list:
                    customer_id = customer["_id"]["$oid"]
                    r = requests.get("http://localhost:5000/api/file/{}".format(customer_id), headers=headers, auth=HTTPBasicAuth(tenant_admin_name,tenant_admin_pass))
                    if "file" in r.json():
                        file_list = r.json()["file"]
                        if len(file_list) > 0:
                            file_obj = file_list.pop()
                            # delete the file
                            file_id = file_obj["_id"]["$oid"]
                            r = requests.delete("http://localhost:5000/api/file/{}/{}".format(customer_id,file_id), headers=headers, auth=HTTPBasicAuth(tenant_admin_name,tenant_admin_pass))
                            print r.text
            # delete some customers
            r = requests.get("http://localhost:5000/api/customer", headers=headers, auth=HTTPBasicAuth(tenant_admin_name,tenant_admin_pass))
            if "customer" in r.json():
                customer_list = r.json()["customer"]
                if len(customer_list) > 0:
                    customer = customer_list.pop()
                    customer_id = customer["_id"]["$oid"]
                    r = requests.delete("http://localhost:5000/api/customer/{}".format(customer_id), headers=headers, auth=HTTPBasicAuth(tenant_admin_name,tenant_admin_pass))
                    print r.text
    # delete all tenants
    r = requests.get("http://localhost:5000/api/tenant", headers=headers, auth=HTTPBasicAuth("admin","passw0rd"))
    if "tenant" in r.json():
        tenant_list = r.json()["tenant"]
        for tenant in tenant_list:
            tenant_id = tenant["_id"]["$oid"]
            r = requests.delete("http://localhost:5000/api/tenant/{}".format(tenant_id), headers=headers, auth=HTTPBasicAuth("admin","passw0rd"))
            print r.text
    print_banner("TEST DELETE END")
    
    
    
    
    
