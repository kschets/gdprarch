#!/usr/bin/python
import os
import json
import logging
import time
import re
import bcrypt
import hashlib
import cStringIO
from bson import json_util
from bson.objectid import ObjectId
from functools import wraps
from pymongo import MongoClient
from flask import Flask, abort, make_response, request, Response, send_file
from logging.handlers import RotatingFileHandler
from castorsdk.scspHeaders import ScspHeaders, ScspAuthentication, ScspAuthorization
from castorsdk.scspClient import ScspClient
from castorsdk.scspQueryArgs import ScspQueryArgs
from castorsdk.realm.scspBucket import ScspBucket
from castorsdk.realm.scspDomain import ScspDomain
from werkzeug.routing import BaseConverter

clusterHosts = ["10.50.1.84", "10.50.1.85", "10.50.1.86"]
scspPort = "80"
swarm_adm = "admin"
swarm_pass = "caringo"
swarm_client = ScspClient(clusterHosts,scspPort, 8, 8, 8)

mongo_client = MongoClient()
arch_db = mongo_client.gdprarch
app = Flask(__name__)

class RegexConverter(BaseConverter):
    def __init__(self, url_map, *items):
        super(RegexConverter, self).__init__(url_map)
        self.regex = items[0]
        
app.url_map.converters['regex'] = RegexConverter
    
def check_auth(username, password):
    if username == "admin":
        return password == "passw0rd"
    else:
        # search an account with username
        account = arch_db.accounts.find_one({"username": username})
        app.logger.debug("account authentication check for ={}=/={}=".format(username,password))
        app.logger.debug("account from db : {}".format(account))
        return account and bcrypt.hashpw(password.encode("utf-8"), account["password"].encode("utf-8")) == account["password"]
    
def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        "Could not verify your access for the URL\n",
        401,
        {"WWW-Authenticate": "Basic realm='Login required'"}
    )

def requires_auth(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args,**kwargs)
    return decorated

##########################################
###  TENANTS
##########################################
@app.route("/api/tenant",methods=["POST"])
@requires_auth
def tenant_post():
    if not request.json or not "name" in request.json:
        abort(400)
    app.logger.info("POST /api/tenant {}".format(request.json))
    tenant = request.json
    res = arch_db.tenants.insert_one(tenant)
    app.logger.debug("tenant inserted")
    
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
        app.logger.error("domain check error")
        abort(500)
    if 200 == res.httpStatusCode:
        app.logger.info("Tenant domain exists already: {}".format(tenant_domain_name))
    else:
        app.logger.info("Tenant domain about to be created: {}".format(tenant_domain_name))
        open_access_meta = ScspHeaders()
        open_access_meta.addValue(ScspAuthorization.AUTHORIZATION_HEADER_NAME, ScspAuthorization().getAuthSpec())
        try:
            res = tenant_domain.create(open_access_meta,swarm_auth,None)
        except Exception, e:
            app.logger.error("Failed to create tenant domain {}".format(tenant_domain_name))
            abort(500)
        if 201 == res.httpStatusCode:
            app.logger.info("Tenant domain {} created".format(tenant_domain_name))
            time.sleep(2)
        else:
            app.logger.error("Tenant domain {} not created".format(tenant_domain_name))
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
        app.logger.info("Tenant domain updated with domain user")
        time.sleep(3)
    else:
        app.logger.error("Tenant domain update with domain user failed: {}".format(res))
        abort(500)
    
    # check the domain
    domain_headers = ScspHeaders()
    domain_headers.authentication = domain_auth
    res = swarm_client.info("", queryArgs=domain_args, metaData=domain_headers)
    if 200 == res.httpStatusCode:
        app.logger.info("Tenant domain check OK")
    else:
        app.logger.error("Tenant domain check failed")
    return json.dumps({"tenant":"{}".format(tenant)}, default=json_util.default)
    
@app.route('/api/tenant',methods=["GET"])
@app.route('/api/tenant/<lookup>',methods=["GET"])
@requires_auth
def tenant_get(lookup=None):
    if lookup is not None:
        try:
            obj_id = ObjectId(lookup)
        except:
            # by lookup
            app.logger.info("GET /api/tenant/{} ( by lookup )".format(lookup))
            regx = re.compile(lookup, re.IGNORECASE)
            res = arch_db.tenants.find({"name": regx})
        else:
            # by object_id
            app.logger.info("GET /api/tenant/{} (by object_id)".format(lookup))
            res = arch_db.tenants.find({"_id": obj_id})
    else:
        app.logger.info("GET /api/tenant")
        res = arch_db.tenants.find()
    res_list = [x for x in res]
    if len(res_list) == 0:
        abort(404)
    return json.dumps({"tenant":res_list}, default=json_util.default)

##########################################
###  ACCOUNTS
##########################################
@app.route("/api/account", methods=["POST"])
@requires_auth
def account_post():
    app.logger.info("POST /api/account {}".format(request.json))
    if not request.json or not "tenant" in request.json or not "username" in request.json or not "password" in request.json:
        abort(400)
    # try to find the tenant
    try:
        tenant_obj_id = ObjectId(request.json["tenant"])
    except:
        abort(400)
    res = arch_db.tenants.find({"_id": tenant_obj_id})
    if len([x for x in res]) == 0:
        return json.dumps({"error":"tenant not found"})
    account = {
        "username": request.json["username"],
        "password": bcrypt.hashpw(request.json["password"].encode("utf-8"), bcrypt.gensalt().encode("utf-8")),
        "tenant": tenant_obj_id
    }
    res = arch_db.accounts.insert_one(account)
    return json.dumps({"result":"account created"})

@app.route("/api/account", methods=["GET"])
@app.route("/api/account/<lookup>", methods=["GET"])
@requires_auth
def account_get(lookup=None):
    app.logger.info("GET /api/account/{}".format(lookup))
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
                res = arch_db.accounts.find({"tenant": tenant_obj_id})
        else:
            res = arch_db.accounts.find()
        res_list = [x for x in res]
    else:
        # get this tenants accounts
        account = arch_db.accounts.find_one({"username": auth.username})
        if account:
            tenant_obj_id = account["tenant"]
            if lookup is not None:
                regx = re.compile(lookup, re.IGNORECASE)
                res = arch_db.accounts.find({"$and":{[{"tenant": tenant_obj_id},{"username": regx} ]}})
            else:
                res = arch_db.accounts.find({"tenant": tenant_obj_id})
            res_list = [x for x in res]
    if len(res_list) == 0:
        abort(404)
    else:
        return json.dumps({"account": res_list}, default=json_util.default)
    
##########################################
###  CUSTOMERS 
##########################################
@app.route("/api/customer", methods=["POST"])
@requires_auth
def customer_post():
    app.logger.info("POST /api/customer")
    if not request.json:
        abort(400)
    # tenant id is found by matching the account tenant_id
    auth = request.authorization
    account = arch_db.accounts.find_one({"username": auth.username})
    if account:
        tenant_obj_id = account["tenant"]
        customer = request.json
        customer["tenant"] = tenant_obj_id
        res = arch_db.customers.insert_one(customer)
        app.logger.debug("customer created: {}".format(customer))
        return json.dumps({"customer":"{}".format(customer)})
    else:
        return json.dumps({"error":"account not found"})
    
@app.route("/api/customer", methods=["GET"])
@app.route("/api/customer/<lookup>", methods=["GET"])
@requires_auth
def customer_get(lookup=None):
    tenant_obj_id = None
    res_list = []
    auth = request.authorization
    account = arch_db.accounts.find_one({"username": auth.username})
    app.logger.debug("GET /api/customer/{}, requesting account:{}".format(lookup,account))
    if account:
        tenant_obj_id = account["tenant"]
        if lookup is not None:
            regx = re.compile(lookup, re.IGNORECASE)
            res = arch_db.customers.find({"$and":[{"name":regx},{"tenant":tenant_obj_id}]})
        else:
            res = arch_db.customers.find({"tenant": tenant_obj_id})
        res_list = [x for x in res]
    if len(res_list) == 0:
        abort(404)
    return json.dumps({"customer": res_list}, default=json_util.default)

##########################################
###  FILES
##########################################
@app.route("/api/file/<customer_id>",methods=["POST"])
@requires_auth
def post_file(customer_id=None):
    app.logger.info("POST /api/files/{}".format(customer_id))
    try:
        customer_obj_id = ObjectId(customer_id)
    except:
        abort(400)
    customer_obj = arch_db.customers.find_one({"_id": customer_obj_id})
    if not customer_obj:
        abort(400)
    auth = request.authorization
    account_obj = arch_db.accounts.find_one({"username":auth.username})
    if not account_obj or account_obj["tenant"] != customer_obj["tenant"]:
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
    if 200 == res.httpStatusCode:
        app.logger.info("customer bucket {} found".format(customer_bucket_name))
    else:
        app.logger.info("customer bucket {} needs be created first".format(customer_bucket_name))
        fwrite = cStringIO.StringIO("")
        fwrite.seek(0,2)
        size = fwrite.tell()
        fwrite.seek(0,0)
        # authz, admin_headers and admin_args unaltered
        res = swarm_client.write(fwrite, size, queryArgs=admin_args, metaData=admin_headers, path=customer_bucket_name)
        if 201 == res.httpStatusCode:
            app.logger.info("customer bucket {} created".format(customer_bucket_name))
            time.sleep(3)
        else:
            app.logger.error("customer bucket {} creation failed: {}".format(customer_bucket_name,res))
            abort(500)
        
    # finally write the files 
    if len(request.files) > 0:
        for fn in request.files:
            f = request.files[fn]
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
                res = arch_db.files.insert_one(file_doc)
                app.logger.info("file_doc {} inserted".format(file_doc))
            else:
                app.logger.error("file stream {}/{} not created : {}".format(customer_bucket_name, f.filename, write_response))
    return json.dumps({"result": "upload complete"})

@app.route("/api/file/<customer_id>", methods=["GET"])
@requires_auth
def file_list(customer_id=None):
    app.logger.info("GET /api/file/{}".format(customer_id))
    try:
        customer_obj_id = ObjectId(customer_id)
    except:
        abort(400)
    customer_obj = arch_db.customers.find_one({"_id": customer_obj_id})
    if not customer_obj:
        abort(400)
    auth = request.authorization
    account_obj = arch_db.accounts.find_one({"username": auth.username})
    if not account_obj or account_obj["tenant"] != customer_obj["tenant"]:
        abort(403)
    # list the files for this customer
    res = arch_db.files.find({"customer": customer_obj_id})
    res_list = [x for x in res]
    if len(res_list) == 0:
        abort(404)
    return json.dumps({"file": res_list}, default=json_util.default)
    
@app.route("/api/file/<customer_id>/<file_id>", methods=["GET"])
@requires_auth
def file_get(customer_id=None, file_id=None):
    app.logger.info("/api/file/{}/{}".format(customer_id, file_id ))
    try:
        customer_obj_id = ObjectId(customer_id)
    except:
        abort(400)
    customer_obj = arch_db.customers.find_one({"_id": customer_obj_id})
    if not customer_obj:
        abort(400)
    auth = request.authorization
    account_obj = arch_db.accounts.find_one({"username": auth.username})
    if not account_obj or account_obj["tenant"] != customer_obj["tenant"]:
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
        app.logger.info("tenant domain {} found".format(tenant_domain_name))
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
        app.logger.info("customer bucket {} found".format(customer_bucket_name))
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
                    
@app.errorhandler(404)
def not_found(error):
    return make_response(json.dumps({"error":"not found"}),404)

if __name__ == "__main__":
    
    swarm_client.start()
    
    formatter = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
    logger = RotatingFileHandler("gdprarch.log", maxBytes=1000000,backupCount=5)
    logger.setLevel(logging.DEBUG)
    logger.setFormatter(formatter)
    app.logger.addHandler(logger)
    app.run(debug=True)
    
    swarm_client.stop()
