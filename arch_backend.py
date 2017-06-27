#!/usr/bin/python
####################################################################################################
#
# TITLE : GDPR Archive
#
# AUTHOR : Koen Schets / StorageTeam
#
# DESCRIPTION : Provide a metadata and document repository in-line with GDPR
#
# VERSION :
#       0.1 Initial version
#       0.2 Framework changed to Flask
#       0.3 Swarm integration
#       0.4 Logging enabled
#       0.5 Customer DELETE update
#       0.6 MongoDB secure access
#       0.7 extend error handling 
#       0.8 adding methods for file 
#
# LOG : gdprarch.log
#
# TODO :
#   allow for a tenant to self-service it's accounts ( one admin which can create/update/delete other accounts)
#
####################################################################################################
import os
import json
import logging
import time
import re
import bcrypt
import hashlib
import copy
import cStringIO
from bson import json_util
from bson.objectid import ObjectId
from functools import wraps
from pymongo import MongoClient
from pymongo import errors as mongoerrors
from flask import Flask, abort, make_response, request, Response, send_file
from logging.handlers import RotatingFileHandler
from castorsdk.scspHeaders import ScspHeaders, ScspAuthentication, ScspAuthorization, ScspLifepoint
from castorsdk.scspClient import ScspClient
from castorsdk.scspQueryArgs import ScspQueryArgs
from castorsdk.realm.scspBucket import ScspBucket
from castorsdk.realm.scspDomain import ScspDomain
from werkzeug.routing import BaseConverter

##########################################
###  VARIABLES
##########################################
clusterHosts = ["10.50.1.84", "10.50.1.85", "10.50.1.86"]
scspPort = "80"
swarm_adm = "admin"
swarm_pass = "caringo"
swarm_client = ScspClient(clusterHosts,scspPort, 8, 8, 8)
mongo_uri = "mongodb://gdprarch:gdprarch@10.0.1.42/gdprarch"
role_set = set(["superuser","tenant_admin","customer_admin","customer"])

mongo_client = MongoClient(mongo_uri)
arch_db = mongo_client.gdprarch
app = Flask(__name__)

def check_auth(username, password):
    if username == "admin":
        return password == "passw0rd"
    else:
        # search an account with username
        account = arch_db.accounts.find_one({"username": username})
        return account and bcrypt.hashpw(password.encode("utf-8"), account["password"].encode("utf-8")) == account["password"]
    
def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        "Could not verify your access for the URL\n",
        401,
        {"WWW-Authenticate": "Basic realm='Login required'"}
    )

def requires_superuser_auth(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        err_msg = make_response(json.dumps({"error":"not authorized"}),401)
        err_msg.headers["WWW-Authenticate"] ="Basic realm='Login required'"
        auth = request.authorization
        if not auth:
            return err_msg
        if not auth.username == "admin":
            return err_msg
        if not auth.password == "passw0rd":
            return err_msg
        return f(*args,**kwargs)
    return decorated

def requires_admin_auth(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        err_msg = make_response(json.dumps({"error":"not authorized"}),401)
        err_msg.headers["WWW-Authenticate"] ="Basic realm='Login required'"
        auth = request.authorization
        if not auth:
            return err_msg
        account = arch_db.accounts.find_one({"username": auth.username})
        if not account:
            return err_msg
        if not "role" in account:
            return err_msg
        if not account["role"] in ("tenant_admin","customer_admin" ):
            return err_msg
        if not bcrypt.hashpw(auth.password.encode("utf-8"), account["password"].encode("utf-8")) == account["password"]:
            return err_msg
        return f(*args,**kwargs)
    return decorated

def requires_customer_auth(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        err_msg = make_response(json.dumps({"error":"not authorized"}),401)
        err_msg.headers["WWW-Authenticate"] ="Basic realm='Login required'"
        auth = request.authorization
        if not auth:
            return err_msg
        account = arch_db.accounts.find_one({"username": auth.username})
        if not account:
            return err_msg
        if not "role" in account:
            return err_msg
        if not account["role"] in ("customer","tenant_admin","customer_admin"):
            return err_msg
        if not bcrypt.hashpw(auth.password.encode("utf-8"), account["password"].encode("utf-8")) == account["password"]:
            return err_msg
        return f(*args,**kwargs)
    return decorated

def requires_tenant_admin_auth(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        err_msg = make_response(json.dumps({"error":"not authorized"}),401)
        err_msg.headers["WWW-Authenticate"] ="Basic realm='Login required'"
        auth = request.authorization
        if not auth:
            return err_msg
        if auth.username == "admin":
            if not auth.password == "passw0rd":
                return err_msg
        else:
            account = arch_db.accounts.find_one({"username": auth.username})
            if not account:
                return err_msg
            if not "role" in account:
                return err_msg
            if not account["role"] == "tenant_admin":
                return err_msg
            if not bcrypt.hashpw(auth.password.encode("utf-8"), account["password"].encode("utf-8")) == account["password"]:
                return err_msg
        return f(*args,**kwargs)
    return decorated

##########################################
###  TENANTS
##########################################
@app.route("/api/tenant",methods=["POST"])
@requires_superuser_auth
def tenant_post():
    if not request.json or not "name" in request.json:
        abort(400)
    tenant = request.json
    try:
        res = arch_db.tenants.insert_one(tenant)
    except mongoerrors, e:
        app.logger.error("Tenant insert failed: {}".format(e))
        abort(500)
    app.logger.debug("new tenant inserted: {}".format(tenant))
    
    # prepare query args and header
    swarm_auth = ScspAuthentication()
    query_args = ScspQueryArgs()
    swarm_auth.user = swarm_adm
    swarm_auth.password = swarm_pass
    swarm_auth.realm = "SWARM admin"
    
    # create a swarm domain for each tenant
    tenant_domain_name = "{}".format(res.inserted_id)
    swarm_client.hostHeaderValue = tenant_domain_name
    tenant_domain = ScspDomain(swarm_client,tenant_domain_name)
    try:
        res = tenant_domain.fetchMetadata(None,query_args)
    except Exception, e:
        app.logger.error("Tenant domain {} check error: {}".format(tenant_domain_name,e))
        abort(500)
    if 200 == res.httpStatusCode:
        app.logger.debug("Tenant domain {} exists already".format(tenant_domain_name))
    else:
        app.logger.debug("Tenant domain {} does not exist and needs to be created".format(tenant_domain_name))
        open_access_meta = ScspHeaders()
        open_access_meta.addValue(ScspAuthorization.AUTHORIZATION_HEADER_NAME, ScspAuthorization().getAuthSpec())
        try:
            res = tenant_domain.create(open_access_meta,swarm_auth,None)
        except Exception, e:
            app.logger.error("Tenant domain {} creation error: {}".format(tenant_domain_name,e))
            abort(500)
        if 201 == res.httpStatusCode:
            app.logger.debug("Tenant domain {} created".format(tenant_domain_name))
            time.sleep(2)
        else:
            app.logger.error("Tenant domain {} not created: {}".format(tenant_domain_name,res))
            abort(500)
        
    # prepare the domain realm user 
    domain_realm = tenant_domain_name + "/_administrators"
    domain_auth = ScspAuthentication()
    domain_auth.user = tenant["name"]
    domain_auth.realm = domain_realm
    domain_auth.password = tenant["name"]
    domain_args = ScspQueryArgs()
    domain_args.setValue("domain", tenant_domain_name)
    
    # hash the password
    md5 = hashlib.md5()
    md5.update(":".join([domain_auth.user, domain_realm, domain_auth.password]))
    passwords = ":".join([domain_auth.user, domain_realm, md5.hexdigest()])
    passwords = passwords + "\r\n"
    
    # prepare the file to be written
    password_stream = cStringIO.StringIO(passwords)
    password_stream.seek(0,2)
    password_stream_size = password_stream.tell()
    password_stream.seek(0,0)
    
    # write the _administrators stream to the domain 
    authz = ScspAuthorization()
    authz.addAuthorization(ScspAuthorization.ALL_OP, tenant_domain_name)
    admin_headers = ScspHeaders()
    admin_headers.addValue("Castor-Authorization", authz.getAuthSpec())
    admin_headers.addValue("Castor-Stream-Type", "admin")
    admin_headers.addLifepoint(reps=16)
    admin_headers.authentication = swarm_auth
    admin_args = ScspQueryArgs()
    admin_args.setValue("admin","yes")
    res = swarm_client.updateMutable("",password_stream, password_stream_size, queryArgs=admin_args, metaData=admin_headers, path="_administrators")
    if 201 == res.httpStatusCode:
        app.logger.debug("Tenant domain {} updated with domain user".format(tenant_domain_name))
        time.sleep(3)
    else:
        app.logger.error("Tenant domain {} update with domain user failed: {}".format(tenant_domain_name, res))
        abort(500)
    
    # check the domain
    domain_headers = ScspHeaders()
    domain_headers.authentication = domain_auth
    res = swarm_client.info("", queryArgs=domain_args, metaData=domain_headers)
    if 200 == res.httpStatusCode:
        app.logger.debug("Tenant domain {} check OK".format(tenant_domain_name))
    else:
        app.logger.error("Tenant domain {} check failed".format(tenant_domain_name))
    return json.dumps({"tenant":"{}".format(tenant)}, default=json_util.default)
    
@app.route('/api/tenant',methods=["GET"])
@app.route('/api/tenant/<lookup>',methods=["GET"])
@requires_superuser_auth
def tenant_get(lookup=None):
    if lookup is not None:
        try:
            obj_id = ObjectId(lookup)
        except:
            # by lookup
            regx = re.compile(lookup, re.IGNORECASE)
            res = arch_db.tenants.find({"name": regx})
        else:
            # by object_id
            res = arch_db.tenants.find({"_id": obj_id})
    else:
        res = arch_db.tenants.find()
    res_list = [x for x in res]
    if len(res_list) == 0:
        abort(404)
    return json.dumps({"tenant":res_list}, default=json_util.default)

@app.route('/api/tenant/<tenant_id>',methods=["PUT","PATCH"])
@requires_superuser_auth
def tenant_update(tenant_id=None):
    try:
        new_tenant = request.json
    except:
        app.logger.error("body does not contain valid json")
        abort(400)
    app.logger.debug("new tenant : {}".format(new_tenant))
    if tenant_id is not None:
        try:
            tenant_obj_id = ObjectId(tenant_id)
        except:
            app.logger.error("Tenant id not valid")
            abort(400)
        tenant_obj = arch_db.tenants.find_one({"_id": tenant_obj_id})
        if not tenant_obj:
            app.logger.error("Tenant id not found")
            abort(400)
        # tenant doc to update found
        if request.method == "PUT":
            try:
                arch_db.tenants.replace_one({"_id": tenant_obj_id}, new_tenant)
            except mongoerrors, e:
                app.logger.error("tenant {} update failed: {}".format(tenant_obj,e))
                abort(500)
            else:
                app.logger.debug("tenant {} put: {}".format(tenant_obj, request.json))
        else:
            try:
                arch_db.tenants.update_one({"_id": tenant_obj_id}, {"$set": new_tenant}, upsert=True)
            except mongoerrors, e:
                app.logger.error("tenant {} update failed: {}".format(tenant_obj,e))
                abort(500)
            else:
                app.logger.debug("tenant {} patch: {}".format(tenant_obj, request.json))
        # refresh tenant doc
        tenant_obj = arch_db.tenants.find_one({"_id": tenant_obj_id})
        return json.dumps({"tenant": tenant_obj}, default=json_util.default)
    else:
        app.logger.error("Tenant id not provided")
        abort(400)
            
@app.route('/api/tenant/<tenant_id>', methods=['DELETE'])
@requires_superuser_auth
def tenant_delete(tenant_id=None):
    if tenant_id is not None:
        try:
            tenant_doc_id = ObjectId(tenant_id)
        except:
            abort(400)
        tenant_doc = arch_db.tenants.find_one({"_id": tenant_doc_id})
        if not tenant_doc:
            abort(400)
        # tenant to delete found
        app.logger.debug("Tenant {} about to be deleted".format(tenant_doc))
        res = arch_db.customers.find({"tenant": tenant_doc_id})
        res_list = [x for x in res]
        app.logger.debug("Tenant {} has {} customers".format(tenant_doc, len(res_list)))
        for customer_doc in res_list:
            # find all customer files
            app.logger.debug("Customer {} about to be deleted".format(customer_doc))
            res = arch_db.files.find({"customer": customer_doc["_id"]})
            res_list = [x for x in res]
            app.logger.debug("Customer {} has {} files".format(customer_doc,len(res_list)))
            for file_doc in res_list:
                # delete file on swarm
                app.logger.debug("File {} about to be deleted".format(file_doc))
                tenant_domain_name = "{}".format(customer_doc["tenant"])
                domain_realm = tenant_domain_name + "/_administrators"
                tenant_doc = arch_db.tenants.find_one({"_id": customer_doc["tenant"]})
                domain_auth = ScspAuthentication()
                domain_auth.user = tenant_doc["name"]
                domain_auth.password = tenant_doc["name"]
                domain_auth.realm = domain_realm
                authz = ScspAuthorization()
                authz.addAuthorization(ScspAuthorization.ALL_OP, domain_realm)
                admin_headers = ScspHeaders()
                admin_headers.addValue("Castor-Authorization", authz.getAuthSpec())
                admin_headers.authentication = domain_auth
                admin_args = ScspQueryArgs()
                admin_args.setValue("domain", tenant_domain_name)
                customer_bucket_name = "{}".format(customer_doc["_id"])
                res = swarm_client.info("", queryArgs = admin_args, metaData=admin_headers, path=customer_bucket_name + "/" + file_doc["filename"]) 
                if 200 == res.httpStatusCode:
                    app.logger.debug("file {}/{} found".format(customer_bucket_name,file_doc["filename"]))
                    res = swarm_client.delete("",queryArgs=admin_args, metaData=admin_headers, path=customer_bucket_name + "/" + file_doc["filename"])
                    if 200 == res.httpStatusCode:
                        app.logger.debug("File {}/{} deleted".format(
                            customer_bucket_name, file_doc["filename"]))
                    else:
                        app.logger.error("File {}/{} delete failed: {}".format(
                            customer_bucket_name, file_doc["filename"], res ))
                    # delete file doc
                    try:
                        arch_db.files.delete_one({"_id": file_doc["_id"]})
                    except mongoerrors, e:
                        app.logger.error("File {} delete failed: {}".format(file_doc["filename"],e))
                        abort(500)
                else:
                    app.logger.error("file {}/{} not found".format(customer_bucket_name, file_doc["filename"]))
            # delete customer accounts
            res = arch_db.accounts.find({"parent": customer_doc["_id"]})
            res_list = [x for x in res]
            app.logger.debug("Tenant {} has {} customer accounts".format(tenant_doc,len(res_list)))
            for cust_acct in res_list:
                try:
                    arch_db.accounts.delete_one({"_id": cust_acct["_id"]})
                except mongoerrors,e:
                    app.logger.error("Account {} could not be deleted: {}".format(cust_acct,e))
                    abort(500)
            # delete customer doc
            try:
                arch_db.customers.delete_one({"_id": customer_doc["_id"]})
            except mongoerrors,e:
                app.logger.error("Customer {} could not be deleted: {}".format(customer_doc,e))
                abort(500)
        # delete all tenant accounts
        res = arch_db.accounts.find({"parent": tenant_doc_id})
        res_list = [x for x in res]
        app.logger.debug("Tenant {} has {} accounts".format(tenant_doc, len(res_list)))
        for account_doc in res_list:
            app.logger.debug("Account {} about to be deleted".format(account_doc))
            try:
                arch_db.accounts.delete_one({"_id":account_doc["_id"]})
            except:
                app.logger.error("Account {} could not be deleted: {}".format(account_doc,e))
                abort(500)
        # getting here means we can delete the tenant
        try:
            arch_db.tenants.delete_one({"_id": tenant_doc_id})
        except:
            app.logger.error("Tenant {} could not be deleted".format(tenant_doc))
            abort(500)
        app.logger.debug("Tenant {} deleted".format(tenant_doc))
        return json.dumps({"tenant":"deleted"})
        
##########################################
###  ACCOUNTS
##########################################
@app.route("/api/account", methods=["POST"])
@requires_tenant_admin_auth
def account_post():
    # body needs be json formatted
    if not request.json:
        app.logger.error("not json body")
        abort(400)
    # check for the mandatory fields to be present 
    if not all(k in request.json for k in ("username","password","role","parent")):
        app.logger.error("mandatory field missing")
        abort(400)
    # check for the provided role to exist
    if not request.json["role"] in role_set:
        app.logger.error("role does not exist")
        abort(400)
    # convert to object_id
    try:
        parent_doc_id = ObjectId(request.json["parent"])
    except:
        app.logger.error("parent id invalid")
        abort(400)
    # get the issuing admin account 
    auth = request.authorization
    if auth.username != "admin":
        adm_account = arch_db.accounts.find_one({"username": auth.username})
        if request.json["role"] == "customer":
            parent_doc = arch_db.customers.find_one({"_id": parent_doc_id})
        else:
            parent_doc = arch_db.tenants.find_one({"_id": parent_doc_id})
        if not parent_doc:
            app.logger.error("parent doc not found")
            abort(400)
        # check for the customer/tenant id to match the issuing admin's
        if request.json["role"] == "customer":
            if adm_account["parent"] != parent_doc["tenant"]:
                app.logger.error("customer tenant does not match current admins")
                abort(400)
        else:
            if adm_account["parent"] != parent_doc_id:
                app.logger.error("account tenant does not match current admins")
                abort(400)
    # prepare for insert
    account = {
        "username": request.json["username"],
        "password": bcrypt.hashpw(request.json["password"].encode("utf-8"), bcrypt.gensalt().encode("utf-8")),
        "role": request.json["role"],
        "parent": parent_doc_id
    }
    try:
        arch_db.accounts.insert_one(account)
    except mongoerror, e:
        app.logger.error("Account insert failed: {}".format(e))
        abort(500)
    return json.dumps({"account": account}, default=json_util.default)

@app.route("/api/account/<account_id>", methods=["PATCH","PUT"])
@requires_tenant_admin_auth
def account_update(account_id=None):
    # body needs be json formatted
    if not request.json:
        app.logger.error("body does not contain valid json")
        abort(400)
    # find the document to update
    try:
        account_doc_id = ObjectId(account_id)
    except:
        app.logger.error("Account id not valid")
        abort(400)
    account_doc = arch_db.accounts.find_one({"_id": account_doc_id})
    if not account_doc:
        app.logger.error("Account id not found")
        abort(400)
    # get the issuing admin account
    auth = request.authorization
    adm_account = arch_db.accounts.find_one({"username": auth.username})
    if not adm_account:
        app.logger.error("Admin account not found")
        abort(404)
    # check for the mandatory fields to be present 
    if request.method == "PUT" and not all(k in request.json for k in ("username","password","role","parent")):
        app.logger.error("PUT requires username,password,role and parent to be provided")
        abort(400)
    # account_doc found, if tenant_admin check if it matches
    if adm_account["parent"] != account_doc["parent"]:
        app.logger.error("cannot update other tenant accounts")
        abort(404)
    # check for the provided parent id to exist ( if provided )
    if "parent" in request.json:
        try:
            parent_doc_id = ObjectId(request.json["parent"])
        except:
            app.logger.error("parent id not valid")
            abort(400)
        parent_doc = arch_db.tenants.find_one({"_id": parent_doc_id})
        if not parent_doc:
            app.logger.error("parent id not found")
            abort(400)
    # now update
    if request.method == "PUT":
        new_account = {
            "username": request.json["username"],
            "password": bcrypt.hashpw(request.json["password"].encode("utf-8"), bcrypt.gensalt().encode("utf-8")),
            "role": request.json["role"],
            "parent": parent_doc_id
        }
        try:
            arch_db.accounts.replace_one({"_id": account_doc_id}, new_account )
        except mongoerrors, e:
            app.logger.error("Account {} update failed: {}".format(account_doc, e))
            abort(500)
        app.logger.debug("Account {} put : {}".format(account_doc, new_account))
    else:
        new_account = copy.deepcopy(request.json)
        if "password" in new_account:
            clear_passwd = new_account["password"]
            new_account["password"] = bcrypt.hashpw(clear_passwd.encode("utf-8"), bcrypt.gensalt().encode("utf-8"))
        if "parent" in new_account:
            new_account["parent"] = parent_doc_id
        try:
            arch_db.accounts.update_one({"_id": account_doc_id}, {"$set": new_account}, upsert=True)
        except mongoerrors, e:
            app.logger.error("account {} update failed: {}".format(account_doc, e))
            abort(500)
        app.logger.debug("account {} patch: {}".format(account_doc, request.json))
    # refresh account doc
    account = arch_db.accounts.find_one({"_id": account_doc_id})
    return json.dumps({"account": account}, default=json_util.default)

@app.route("/api/account/<account_id>", methods=["DELETE"])
@requires_tenant_admin_auth
def account_delete(account_id=None):
    # try to find the account
    try:
        account_doc_id = ObjectId(account_id)
    except:
        abort(400)
    account_doc = arch_db.accounts.find_one({"_id": account_doc_id})
    if not account_doc:
        abort(400)
    # account found, if tenant_admin check if it matches
    auth = request.authorization
    adm_account = arch_db.accounts.find_one({"username":auth.username})
    if not adm_account:
        abort(400)
    if adm_account["parent"] != account_doc["parent"]:
        abort(404)
    # delete the account
    try:
        arch_db.accounts.delete_one({"_id": account_doc_id})
    except mongoerror, e:
        app.logger.error("Account delete failed: {}".format(e))
        abort(500)
    return json.dumps({"account": "deleted"})

@app.route("/api/account", methods=["GET"])
@app.route("/api/account/<lookup>", methods=["GET"])
@requires_tenant_admin_auth
def account_get(lookup=None):
    tenant_obj_id = None
    res_list = []
    auth = request.authorization
    if auth.username == "admin":
        # get all accounts
        if lookup is not None:
            # lookup can be a tenant_id or username
            try:
                tenant_obj_id = ObjectId(lookup)
            except:
                # definitely not a tenant_id
                regx = re.compile(lookup, re.IGNORECASE)
                res = arch_db.accounts.find({"username":regx})
            else:
                res = arch_db.accounts.find({"parent": tenant_obj_id})
        else:
            res = arch_db.accounts.find()
        res_list = [x for x in res]
    else:
        # get this tenants accounts
        account = arch_db.accounts.find_one({"username": auth.username})
        if account:
            tenant_obj_id = account["parent"]
            if lookup is not None:
                regx = re.compile(lookup, re.IGNORECASE)
                res = arch_db.accounts.find({"$and":[{"parent": tenant_obj_id},{"username": regx} ]})
            else:
                res = arch_db.accounts.find({"parent": tenant_obj_id})
            res_list = [x for x in res]
    if len(res_list) == 0:
        abort(404)
    else:
        return json.dumps({"account": res_list}, default=json_util.default)
    
##########################################
###  CUSTOMERS 
##########################################
@app.route("/api/customer", methods=["POST"])
@requires_admin_auth
def customer_post():
    if not request.json:
        app.logger.debug("body does not contain valid json")
        abort(400)
    # tenant id is found by matching the account tenant_id
    auth = request.authorization
    account = arch_db.accounts.find_one({"username": auth.username})
    if not account:
        app.logger.error("admin account not found")
        abort(400)
    tenant_obj_id = account["parent"]
    customer = request.json
    customer["tenant"] = tenant_obj_id
    try:
        arch_db.customers.insert_one(customer)
    except mongoerror, e:
        app.logger.error("Customer {} insert failed: {}".format(customer,e))
        abort(500)
    app.logger.debug("customer created: {}".format(customer))
    return json.dumps({"customer":"{}".format(customer)})
    
@app.route("/api/customer", methods=["GET"])
@app.route("/api/customer/<lookup>", methods=["GET"])
@requires_customer_auth
def customer_get(lookup=None):
    tenant_obj_id = None
    res_list = []
    auth = request.authorization
    if auth.username == "admin":
        # search all customers
        if lookup is not None:
            # check for lookup to be a customer id
            try:
                customer_doc_id = ObjectId(lookup)
            except:
                # not an object id, maybe regex
                regx = re.compile(lookup,re.IGNORECASE)
                res = arch_db.accounts.find({"name": regx})
            else:
                res = arch_db.customers.find({"_id": customer_doc_id})
        else:
            res = arch_db.customers.find()
    else:
        # search this admin/tenant customers
        account_doc = arch_db.accounts.find_one({"username": auth.username})
        if account_doc["role"] == "customer":
            res = arch_db.customers.find({"_id": account_doc["parent"]})
        else:
            tenant_obj_id = account_doc["parent"]
            if lookup is not None:
                # check for lookup to be a customer id
                try:
                    customer_doc_id = ObjectId(lookup)
                except:
                    # not
                    regx = re.compile(lookup, re.IGNORECASE)
                    res = arch_db.customers.find({"$and":[{"name":regx},{"tenant":tenant_obj_id}]})
                else:
                    res = arch_db.customers.find({"$and":[{"_id": customer_doc_id},{"tenant": tenant_obj_id}]})
            else:
                res = arch_db.customers.find({"tenant": tenant_obj_id})
    res_list = [x for x in res]
    if len(res_list) == 0:
        abort(404)
    return json.dumps({"customer": res_list}, default=json_util.default)

@app.route("/api/customer/<customer_id>", methods=["PUT","PATCH"])
@requires_admin_auth
def customer_update(customer_id):
    try:
        new_customer = request.json
    except:
        app.logger.error("body does not contain valid json")
        abort(400)
    app.logger.debug("new customer data : {}".format(new_customer))
    try:
        customer_obj_id = ObjectId(customer_id)
    except:
        app.logger.error("Customer id is not valid")
        abort(400)
    customer_obj = arch_db.customers.find_one({"_id": customer_obj_id})
    if not customer_obj:
        app.logger.error("Customer id not found")
        abort(400)
    # customer doc to update found
    if request.method == "PUT":
        new_customer["tenant"] = customer_obj["tenant"]
        try:
            arch_db.customers.replace_one({"_id": customer_obj_id}, new_customer)
        except mongoerrors,e:
            app.logger.error("customer {} update failed: {}".format(customer_obj,e))
        else:
            app.logger.debug("customer {} put {}".format(customer_obj, new_customer))
    else:
        # same goes here
        if "tenant" in new_customer:
            del(new_customer["tenant"])
        try:
            arch_db.customers.update_one({"_id": customer_obj_id}, {"$set": new_customer}, upsert=True)
        except mongoerrors,e:
            app.logger.error("customer {} update failed: {}".format(customer_obj, e))
        else:
            app.logger.debug("customer {} patch {}".format(customer_obj, new_customer))
    # refresh customer doc
    customer_obj = arch_db.customers.find_one({"_id": customer_obj_id})
    return json.dumps({"customer": customer_obj}, default=json_util.default)
            
@app.route("/api/customer/<customer_id>", methods=["DELETE"])
@requires_admin_auth
def customer_delete(customer_id=None):
    # keep_around is set to True in case the customer has files which need be preserved
    # it marks the fact that not all customer data can be discarded yet
    keep_around = False
    try:
        customer_obj_id = ObjectId(customer_id)
    except Exception,e:
        app.logger.error("customer id provided is not valid")
        abort(400)
    customer_obj = arch_db.customers.find_one({"_id": customer_obj_id})
    if not customer_obj:
        app.logger.error("customer id not found")
        abort(404)
    auth = request.authorization
    account = arch_db.accounts.find_one({"username": auth.username})
    if not account:
        app.logger.error("admin account not found")
        abort(400)
    if customer_obj["tenant"] != account["parent"]:
        app.logger.error("cannot delete other tenant customers")
        abort(404)
    # check if the customer has got files
    res = arch_db.files.find({"customer": customer_obj_id})
    res_list = [x for x in res]
    if len(res_list) > 0:
        for file_doc in res_list:
            app.logger.debug("DELETE requested for file {}".format(file_doc))
            # file exists on SWARM
            tenant_domain_name = "{}".format(customer_obj["tenant"])
            domain_realm = tenant_domain_name + "/_administrators"
            tenant_obj = arch_db.tenants.find_one({"_id": customer_obj["tenant"]})
            domain_auth = ScspAuthentication()
            domain_auth.user = tenant_obj["name"]
            domain_auth.password = tenant_obj["name"]
            domain_auth.realm = domain_realm
            authz = ScspAuthorization()
            authz.addAuthorization(ScspAuthorization.ALL_OP, domain_realm)
            admin_headers = ScspHeaders()
            admin_headers.addValue("Castor-Authorization", authz.getAuthSpec())
            admin_headers.authentication = domain_auth
            admin_args = ScspQueryArgs()
            admin_args.setValue("domain", tenant_domain_name)
            customer_bucket_name = "{}".format(customer_obj["_id"])
            res = swarm_client.info("", queryArgs = admin_args, metaData=admin_headers, path=customer_bucket_name + "/" + file_doc["filename"]) 
            if 200 == res.httpStatusCode:
                app.logger.debug("file {}/{} found".format(customer_bucket_name,file_doc["filename"]))
                if "retention" in file_doc:
                    keep_around = True
                    # put a lifepoint on it
                    lp1 = ScspLifepoint(constraint="deletable=no", days=file_doc["retention"], reps=3)
                    lp2 = ScspLifepoint(constraint="delete")
                    admin_headers.addValue("Lifepoint",str(lp1))
                    admin_headers.addValue("Lifepoint",str(lp2))
                    # put back the content-type header as well
                    if "content-type" in file_doc:
                        admin_headers.addValue("Content-Type", file_doc["content-type"])
                    res = swarm_client.copyMutable("",queryArgs=admin_args, metaData=admin_headers, path=customer_bucket_name + "/" + file_doc["filename"])
                    if 201 == res.httpStatusCode:
                        app.logger.debug("File {}/{} updated with lifepoint {}".format(
                            customer_bucket_name, file_doc["filename"], str(lp1)))
                    else:
                        app.logger.error("File {}/{} update with lifepoint {} failed: {}".format(
                            customer_bucket_name, file_doc["filename"], str(lp1), res ))
                    # update the file_doc
                    new_file_doc  = copy.deepcopy(file_doc)
                    del(new_file_doc["_id"])
                    new_file_doc["deleted"] = "yes"
                    try:
                        arch_db.files.update_one({"_id": file_doc["_id"]}, {"$set":new_file_doc})
                    except mongoerrors, e:
                        app.logger.error("File update failed: {}".format(e))
                    app.logger.debug("File {} updated with deleted=yes".format(file_doc["filename"]))
                else:
                    # delete right away
                    res = swarm_client.delete("",queryArgs=admin_args, metaData=admin_headers, path=customer_bucket_name + "/" + file_doc["filename"])
                    if 200 == res.httpStatusCode:
                        app.logger.debug("File {}/{} deleted".format(
                            customer_bucket_name, file_doc["filename"]))
                    else:
                        app.logger.error("File {}/{} delete failed: {}".format(
                            customer_bucket_name, file_doc["filename"], res ))
                    # delete file doc
                    try:
                        arch_db.files.delete_one({"_id": file_doc["_id"]})
                    except mongoerrors, e:
                        app.logger.error("File {} deleted".format(file_doc["filename"]))
                    else:
                        app.logger.debug("File metadata deleted")
            else:
                app.logger.error("file {}/{} not found".format(customer_bucket_name, file_doc["filename"]))
    else:
        app.logger.debug("No files found to delete for customer {}".format(customer_id))
    # then clear the customer metadata
    if keep_around:
        # update the customer doc as deleted
        new_customer_doc = copy.deepcopy(customer_obj)
        del(new_customer_doc["_id"])
        new_customer_doc["deleted"] = "yes"
        try:
            arch_db.customers.update_one({"_id": customer_obj_id},{"$set": new_customer_doc})
        except mongoerrors, e:
            app.logger.error("Customer {} update failed: {}".format(customer_obj, e))
        else:
            app.logger.debug("customer {} delete field added".format(new_customer_doc))
    else:
        # delete the customer doc
        try:
            arch_db.customers.delete_one({"_id": customer_obj_id})
        except mongoerrors, e:
            app.logger.error("Customer {} delete failed: {}".format(customer_obj, e))
        else:
            app.logger.debug("customer {} deleted".format(customer_obj))
    return json.dumps({"customer": "deleted"}, default=json_util.default)

##########################################
###  FILES
##########################################
@app.route("/api/file/<customer_id>",methods=["POST"])
@requires_admin_auth
def post_file(customer_id=None):
    try:
        customer_obj_id = ObjectId(customer_id)
    except:
        app.logger.error("customer id not valid")
        abort(400)
    customer_obj = arch_db.customers.find_one({"_id": customer_obj_id})
    if not customer_obj:
        app.logger.error("customer id not found")
        abort(400)
    auth = request.authorization
    account_obj = arch_db.accounts.find_one({"username":auth.username})
    if not account_obj or account_obj["parent"] != customer_obj["tenant"]:
        app.logger.error("cannot accept other tenant files")
        abort(403)
        
    # get tenant for domain user
    tenant_domain_name = "{}".format(customer_obj["tenant"])
    domain_realm = tenant_domain_name + "/_administrators"
    tenant_obj = arch_db.tenants.find_one({"_id": customer_obj["tenant"]})
    domain_auth = ScspAuthentication()
    domain_auth.user = tenant_obj["name"]
    domain_auth.password = tenant_obj["name"]
    domain_auth.realm = domain_realm
        
    # check for the tenant domain to exist
    app.logger.debug("About to check if tenant domain {} exists".format(tenant_domain_name))
    tenant_domain = ScspDomain(swarm_client, tenant_domain_name)
    query_args = ScspQueryArgs()
    try:
        res = tenant_domain.fetchMetadata(None, query_args)
    except Exception, e:
        app.logger.error("GET tenant domain {} error".format(tenant_domain_name))
        abort(500)
    if 200 == res.httpStatusCode:
        app.logger.info("tenant domain {} found".format(tenant_domain_name))
    else:
        app.logger.error("tenant domain {} does not exist".format(tenant_domain_name))
        abort(500)
        
    # check the customer bucket
    # swarm_auth = ScspAuthentication()
    # swarm_auth.user = swarm_adm
    # swarm_auth.password = swarm_pass
    # swarm_auth.realm = "SWARM admin"
    authz = ScspAuthorization()
    authz.addAuthorization(ScspAuthorization.ALL_OP, domain_realm)
    admin_headers = ScspHeaders()
    admin_headers.addValue("Castor-Authorization", authz.getAuthSpec())
    admin_headers.authentication = domain_auth
    admin_args = ScspQueryArgs()
    admin_args.setValue("domain", tenant_domain_name)
    # admin_args.setValue("admin","yes")
    customer_bucket_name = "{}".format(customer_obj["_id"])
    res = swarm_client.info("", queryArgs = admin_args, metaData=admin_headers, path=customer_bucket_name)
    app.logger.debug("customer bucket check: {}".format(res))
    if 200 == res.httpStatusCode:
        app.logger.debug("customer bucket {} found".format(customer_bucket_name))
    else:
        app.logger.debug("customer bucket {} needs be created first".format(customer_bucket_name))
        fwrite = cStringIO.StringIO("")
        fwrite.seek(0,2)
        size = fwrite.tell()
        fwrite.seek(0,0)
        # authz, admin_headers and admin_args unaltered
        res = swarm_client.write(fwrite, size, queryArgs=admin_args, metaData=admin_headers, path=customer_bucket_name)
        if 201 == res.httpStatusCode:
            app.logger.debug("customer bucket {} created".format(customer_bucket_name))
            time.sleep(3)
        else:
            app.logger.debug("customer bucket {} creation failed: {}".format(customer_bucket_name,res))
            abort(500)
        
    # finally write the files 
    if len(request.files) > 0:
        for fn in request.files:
            f = request.files[fn]
            app.logger.debug("about to write a file to SWARM :")
            app.logger.debug("filename {}".format(f.filename))
            app.logger.debug("form name {}".format(f.name))
            app.logger.debug("content-length {}".format(f.content_length))
            app.logger.debug("content-type {}".format(f.content_type))
            # get size
            f.seek(0,os.SEEK_END)
            fsize = f.tell()
            f.seek(0)
            # write named object
            # headers = ScspHeaders()
            admin_headers.addValue("Content-Type",f.content_type)
            swarm_client.hostHeaderValue = tenant_domain_name
            write_response = swarm_client.write(f,fsize,queryArgs=admin_args, metaData=admin_headers, path=customer_bucket_name + "/" + f.filename)
            if 201 == write_response.httpStatusCode:
                app.logger.info("file stream {}/{} created".format(customer_bucket_name, f.filename))
                # insert file_doc
                file_doc = {
                    "filename": f.filename,
                    "content-type": f.content_type,
                    "customer": customer_obj["_id"]
                }
                try:
                    arch_db.files.insert_one(file_doc)
                except mongoerror, e:
                    app.logger.error("File insert failed: {}".format(e))
                    abort(500)
                app.logger.debug("file {} inserted".format(file_doc))
            else:
                app.logger.error("file stream {}/{} not created : {}".format(customer_bucket_name, f.filename, write_response))
    else:
        app.logger.debug("no files provided")
    return json.dumps({"result": "upload complete"})

@app.route("/api/file", methods=["GET"])
@app.route("/api/file/<customer_id>", methods=["GET"])
@requires_customer_auth
def file_list(customer_id=None):
    if customer_id is not None:
        try:
            customer_obj_id = ObjectId(customer_id)
        except:
            abort(400)
        try:
            customer_obj_id = ObjectId(customer_id)
        except:
            abort(400)
        customer_obj = arch_db.customers.find_one({"_id": customer_obj_id})
        if not customer_obj:
            abort(400)
        auth = request.authorization
        if auth.username != "admin":
            account_obj = arch_db.accounts.find_one({"username": auth.username})
            if not account_obj or account_obj["parent"] != customer_obj["tenant"]:
                abort(403)
        # list the files for this customer
        res = arch_db.files.find({"customer": customer_obj_id})
    else:
        # get all files in scope
        auth = request.authorization
        account_obj = arch_db.accounts.find_one({"username": auth.username})
        if account_obj and account_obj["role"] == "customer":
            # get this customers files
            res = arch_db.files.find({"customer": account_obj["parent"]})
    res_list = [x for x in res]
    if len(res_list) == 0:
        abort(404)
    return json.dumps({"file": res_list}, default=json_util.default)
    
@app.route("/api/file/<customer_id>/<file_id>", methods=["GET"])
@requires_customer_auth
def file_get(customer_id=None, file_id=None):
    try:
        customer_obj_id = ObjectId(customer_id)
    except:
        abort(400)
    customer_obj = arch_db.customers.find_one({"_id": customer_obj_id})
    if not customer_obj:
        abort(400)
    auth = request.authorization
    account_obj = arch_db.accounts.find_one({"username": auth.username})
    if not account_obj:
        abort(403)
    if account_obj["role"] == "customer":
        if account_obj["parent"] != customer_obj_id:
            abort(403)
    else:
        if account_obj["parent"] != customer_obj["tenant"]:
            abort(403)
    try:
        file_obj_id = ObjectId(file_id)
    except:
        abort(400)
    file_obj = arch_db.files.find_one({"_id": file_obj_id})
    if not file_obj:
        abort(400)
    # go get them
    tenant_domain_name = "{}".format(customer_obj["tenant"])
    domain_realm = tenant_domain_name + "/_administrators"
    tenant_obj = arch_db.tenants.find_one({"_id": customer_obj["tenant"]})
    domain_auth = ScspAuthentication()
    domain_auth.user = tenant_obj["name"]
    domain_auth.password = tenant_obj["name"]
    domain_auth.realm = domain_realm
    
    # check for the tenant domain to exist
    app.logger.debug("About to check if tenant domain {} exists".format(tenant_domain_name))
    tenant_domain = ScspDomain(swarm_client, tenant_domain_name)
    query_args = ScspQueryArgs()
    try:
        res = tenant_domain.fetchMetadata(None, query_args)
    except Exception, e:
        app.logger.error("GET tenant domain {} error".format(tenant_domain_name))
        abort(500)
    if 200 == res.httpStatusCode:
        app.logger.debug("tenant domain {} found".format(tenant_domain_name))
    else:
        app.logger.error("tenant domain {} does not exist".format(tenant_domain_name))
        abort(500)
        
    # check the customer bucket
    authz = ScspAuthorization()
    authz.addAuthorization(ScspAuthorization.ALL_OP, domain_realm)
    admin_headers = ScspHeaders()
    admin_headers.addValue("Castor-Authorization", authz.getAuthSpec())
    admin_headers.authentication = domain_auth
    admin_args = ScspQueryArgs()
    admin_args.setValue("domain", tenant_domain_name)
    customer_bucket_name = "{}".format(customer_obj["_id"])
    res = swarm_client.info("", queryArgs = admin_args, metaData=admin_headers, path=customer_bucket_name)
    if 200 == res.httpStatusCode:
        app.logger.debug("customer bucket {} found".format(customer_bucket_name))
        # get the file
        fread = cStringIO.StringIO()
        res = swarm_client.read("", fread, queryArgs=admin_args, metaData=admin_headers, path=customer_bucket_name + "/" + file_obj["filename"])
        if 200 == res.httpStatusCode:
            fread.seek(0,0)
            return send_file(fread, attachment_filename=file_obj["filename"])
        else:
            app.logger.error("could not read file object")
            abort(500)
    else:
        app.logger.info("customer bucket {} does not exist".format(customer_bucket_name))
        abort(500)
                    
@app.route("/api/file/<customer_id>/<file_id>", methods=["PATCH"])
@requires_admin_auth
def file_patch(customer_id=None, file_id=None):
    try:
        customer_obj_id = ObjectId(customer_id)
    except:
        abort(400)
    customer_obj = arch_db.customers.find_one({"_id": customer_obj_id})
    if not customer_obj:
        abort(400)
    auth = request.authorization
    account_obj = arch_db.accounts.find_one({"username": auth.username})
    if not account_obj or account_obj["parent"] != customer_obj["tenant"]:
        abort(403)
    try:
        file_obj_id = ObjectId(file_id)
    except:
        abort(400)
    file_obj = arch_db.files.find_one({"_id": file_obj_id})
    if not file_obj:
        abort(400)
    # file found, update can start
    try:
        arch_db.files.update_one({"_id": file_obj_id},{"$set":request.json})
    except mongoerrors, e:
        app.logger.error("File updated failed: {}".format(e))
    app.logger.debug("file {} patched with {}".format(file_obj_id, request.json))
    return json.dumps({"file": file_obj}, default=json_util.default)
        
@app.route("/api/file/<customer_id>/<file_id>", methods=["DELETE"])
@requires_admin_auth
def file_delete(customer_id,file_id):
    try:
        customer_doc_id = ObjectId(customer_id)
    except Exception,e:
        app.logger.error("customer id provided is not valid")
        abort(400)
    customer_doc = arch_db.customers.find_one({"_id": customer_doc_id})
    if not customer_doc:
        abort(400)
    auth = request.authorization
    account = arch_db.accounts.find_one({"username": auth.username})
    if not account:
        abort(404)
    if customer_doc["tenant"] != account["parent"]:
        abort(404)
    try:
        file_doc_id = ObjectId(file_id)
    except Exception,e:
        app.logger.error("file id provided is not valid")
        abort(400)
    file_doc = arch_db.files.find_one({"_id": file_doc_id})
    if not file_doc:
        app.logger.error("file id provided does not exist")
        abort(400)
    app.logger.debug("DELETE requested for file {}".format(file_doc))
    # file exists on SWARM
    tenant_domain_name = "{}".format(customer_doc["tenant"])
    domain_realm = tenant_domain_name + "/_administrators"
    tenant_obj = arch_db.tenants.find_one({"_id": customer_doc["tenant"]})
    domain_auth = ScspAuthentication()
    domain_auth.user = tenant_obj["name"]
    domain_auth.password = tenant_obj["name"]
    domain_auth.realm = domain_realm
    authz = ScspAuthorization()
    authz.addAuthorization(ScspAuthorization.ALL_OP, domain_realm)
    admin_headers = ScspHeaders()
    admin_headers.addValue("Castor-Authorization", authz.getAuthSpec())
    admin_headers.authentication = domain_auth
    admin_args = ScspQueryArgs()
    admin_args.setValue("domain", tenant_domain_name)
    customer_bucket_name = "{}".format(customer_doc["_id"])
    res = swarm_client.info("", queryArgs = admin_args, metaData=admin_headers, path=customer_bucket_name + "/" + file_doc["filename"]) 
    if 200 == res.httpStatusCode:
        app.logger.debug("file {}/{} found".format(customer_bucket_name,file_doc["filename"]))
        if "retention" in file_doc:
            # put a lifepoint on it
            lp1 = ScspLifepoint(constraint="deletable=no", days=file_doc["retention"], reps=3)
            lp2 = ScspLifepoint(constraint="delete")
            admin_headers.addValue("Lifepoint",str(lp1))
            admin_headers.addValue("Lifepoint",str(lp2))
            # put back the content-type header as well
            if "content-type" in file_doc:
                admin_headers.addValue("Content-Type", file_doc["content-type"])
            res = swarm_client.copyMutable("",queryArgs=admin_args, metaData=admin_headers, path=customer_bucket_name + "/" + file_doc["filename"])
            if 201 == res.httpStatusCode:
                app.logger.debug("File {}/{} updated with lifepoint {}".format(
                    customer_bucket_name, file_doc["filename"], str(lp1)))
            else:
                app.logger.error("File {}/{} update with lifepoint {} failed: {}".format(
                    customer_bucket_name, file_doc["filename"], str(lp1), res ))
            # update the file_doc
            new_file_doc  = copy.deepcopy(file_doc)
            del(new_file_doc["_id"])
            new_file_doc["deleted"] = "yes"
            try:
                arch_db.files.update_one({"_id": file_doc["_id"]}, {"$set":new_file_doc})
            except mongoerrors, e:
                app.logger.error("File update failed: {}".format(e))
            app.logger.debug("File {} updated with deleted=yes".format(file_doc["filename"]))
        else:
            # delete right away
            res = swarm_client.delete("",queryArgs=admin_args, metaData=admin_headers, path=customer_bucket_name + "/" + file_doc["filename"])
            if 200 == res.httpStatusCode:
                app.logger.debug("File {}/{} deleted".format(
                    customer_bucket_name, file_doc["filename"]))
            else:
                app.logger.error("File {}/{} delete failed: {}".format(
                    customer_bucket_name, file_doc["filename"], res ))
            # delete file doc
            try:
                arch_db.files.delete_one({"_id": file_doc["_id"]})
            except mongoerrors, e:
                app.logger.error("File {} deleted".format(file_doc["filename"]))
                abort(500)
    else:
        app.logger.error("file {}/{} not found".format(customer_bucket_name, file_doc["filename"]))
    return json.dumps({"file": "deleted"}, default=json_util.default)   
    
##########################################
###  HOOKS
##########################################
@app.errorhandler(400)
def bad_request(error):
    return make_response(json.dumps({"error":"bad request"}),400)

@app.errorhandler(401)
def unauthorized(error):
    res = make_response(json.dumps({"error":"unauthorized"}), 401)
    res.headers["WWW-Authenticate"] = "Basic realm='Login required'"
    return res
    
@app.errorhandler(403)
def forbidden(error):
    return make_response(json.dumps({"error":"forbidden"}),403)

@app.errorhandler(404)
def not_found(error):
    return make_response(json.dumps({"error":"not found"}),404)

@app.errorhandler(500)
def internal_server_error(error):
    return make_response(json.dumps({"error":"internal server error"}),500)

@app.before_request
def before_request():
    # log the incoming request
    try:
        source_ip = request.remote_addr
    except:
        source_ip = "unknown"
    try:
        user_name = request.authorization.username
    except:
        user_name = "unknown"
    try:
        js = request.json
    except:
        js = ""
    app.logger.info("IN {} {} {} {} {} {}".format(
        source_ip, user_name,
        request.method, request.scheme, request.full_path, js
        ))
    
@app.after_request
def after_request(response):
    # log the outgoing response 
    try:
        source_ip = request.remote_addr
    except:
        source_ip = "unknown"
    try:
        user_name = request.authorization.username
    except:
        user_name = "unknown"
    app.logger.info("OUT {} {} {} {} {} {}".format(
        source_ip, user_name,
        request.method, request.scheme, request.full_path, response.status
        ))
    return response
    
##########################################
###  MAIN
##########################################
if __name__ == "__main__":
    
    swarm_client.start()
    
    formatter = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
    logger = RotatingFileHandler("gdprarch.log", maxBytes=100000000,backupCount=5)
    logger.setLevel(logging.DEBUG)
    logger.setFormatter(formatter)
    app.logger.addHandler(logger)
    app.run(debug=True)
    
    swarm_client.stop()
