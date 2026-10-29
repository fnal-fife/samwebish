#!/usr/bin/env python
import base64
import json
from fastapi import (
    FastAPI,
    Request,
    Response,
    APIRouter,
    responses,
    HTTPException,
    Body,
    Form,
    status,
)
from fastapi.utils import is_body_allowed_for_status_code
from fastapi_utils.cbv import cbv
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi

import os
import os.path
import re
import time
import threading
import traceback
from typing import Annotated, Any, Dict


from version import samwebish_version
from data_dispatcher.api import DataDispatcherClient
from metacat.webapi import MetaCatClient
from metacat.webapi.webapi import (
    AlreadyExistsError,
    InvalidMetadataError,
    BadRequestError,
)
from rucio.client import Client as RClient
from rucio.client.replicaclient import ReplicaClient
from query_converter.parse_tree import SAM_query_to_MetaCat
from metadata_converter import MetadataConverter

import logging

logger = logging.getLogger(__name__)
logging.basicConfig(filename="logs/samwebish.log", level=logging.DEBUG)


app = FastAPI()

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Samwebish",
        version="0.0.4",
        description="SAM API for Metacat/Rucio\n\nTo authorize, paste encoded token in Authorize popup",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }
    openapi_schema["security"] = [{"BearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi


# override RequestValidationError to log the validation message
# and also add "message" and "error" tags to response for Samweb client
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logging.error(f"{request}: {exc_str}")
    exc_str = f"{exc}".replace("\n", " ").replace("   ", " ")
    content = {
        "status_code": 10422,
        "message": exc_str,
        "error": "validation",
        "data": None,
    }
    return responses.JSONResponse(
        content=content, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY
    )


# override exception handlers to include "message" as well as "detail"
# in JSON error responses, to make samweb client happy
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> Response:
    headers = getattr(exc, "headers", None)
    if not is_body_allowed_for_status_code(exc.status_code):
        return Response(status_code=exc.status_code, headers=headers)
    return responses.JSONResponse(
        {
            "detail": exc.detail,
            "message": exc.detail,
            "error": "exception",
        },
        status_code=exc.status_code,
        headers=headers,
    )


router = APIRouter()

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# classes for authentication, client connection caching


class ClientCache:

    # Note: there are now 4 caches in here that work almost the same
    #     except for the object called to create the connection.
    #     Better might be to have one cache class that you pass the
    #     connection creator into, and make 4 instances of that class...

    def __init__(self):
        self.mcccache = {}
        self.mccexp = {}
        self.ddccache = {}
        self.ddcexp = {}
        self.rccache = {}
        self.rcexp = {}
        self.rrpccache = {}
        self.rrpcexp = {}
        # for get_username, below
        self.subj_user_re = re.compile("(.*)@fnal.gov")
        self.scope_user_re = re.compile("storage[^ ]*/users/([^ ]*)")
        self.token_offset = len("Bearer ")
        self.rucio_env_lock = threading.Lock()

    # needs to be get_scitoken(self, request:Request):
    # and all the methods that call it (which is most of them) need a request:Request param
    # which they pass here, until then stubbing out for basic testgin
    def get_scitoken(
        self,
        request: Request,
    ):
        """extract scitoken from Authorization: header"""
        logger.debug(f"headers: {dict(request.headers)}")
        authheader = request.headers.get("Authorization", "")
        if not authheader:
            raise HTTPException(401, "SciToken athentication required")
        return authheader[self.token_offset :]

    def cheap_decode_token(self, scitok):
        """extract json data from jwt token without validating, etc."""

        if scitok:
            tp = scitok.split(".")
            return json.loads(base64.b64decode(tp[1] + "==", altchars="_-"))
        else:
            return {"sub": "", "scope": ""}

    def get_username(self, scitok):
        """get username from scitoken"""
        # Scitoken purists will tell us *not* to do this, nor to map
        # tokens to users at all, but SAMweb and MetaCat do, via db tables
        # so we can either setup one of these tables, or cheat.
        # Currently we cheat:
        # our subjects are often not usernames, (except production accounts)
        # if our subject is username@fnal.gov, take that
        # otherwise look for a username in the scope
        # i.e. "storage.write:.../users/username"
        #
        # note that this username guess isn't actually used except to log
        # into backend services...

        logger.info(f"get_username: {scitok=}")
        decoded = self.cheap_decode_token(scitok)
        logger.info(f'checking subject: {decoded["sub"]}')
        m = self.subj_user_re.match(decoded["sub"])
        if m:
            logger.info(f"Returning: {m.group(1)}")
            return m.group(1)
        logger.info(f'checking scope: {decoded["scope"]}')
        m = self.scope_user_re.search(decoded["scope"])
        if m:
            logger.info(f"Returning: {m.group(1)}")
            return m.group(1)
        logger.info(f"Returning: None!")
        return None

    def getdd_client(self, request: Request):
        """get DataDispatcherClient for this client"""
        scitok = self.get_scitoken(request)
        if not scitok in self.ddccache or self.ddcexp[scitok] < time.time():
            username = self.get_username(scitok)
            # set token_file on client to /dev/null so we don't have to
            # track/clean up token_library files.
            self.ddccache[scitok] = DataDispatcherClient()
            try:
                self.ddccache[scitok].login_token(username, scitok)
            except:
                raise HTTPException(401, "SciToken athentication failed")
            self.ddcexp[scitok] = time.time() + 300
        return self.ddccache[scitok]

    def getmc_client(self, request: Request):
        """get MetaCatClient for this client"""
        scitok = self.get_scitoken(request)
        if not scitok in self.mcccache or self.mccexp[scitok] < time.time():
            username = self.get_username(scitok)
            # set token_file on client to /dev/null so we don't have to
            # track/clean up token_library files.
            # self.mcccache[scitok] = MetaCatClient(token_file="/tmp/tok")
            self.mcccache[scitok] = MetaCatClient()
            try:
                self.mcccache[scitok].login_token(username, scitok)
            except:
                raise HTTPException(401, "SciToken athentication failed")
            # cache for 5 minutes
            self.mccexp[scitok] = time.time() + 300
        return self.mcccache[scitok]

    def getr_client(self, request: Request):
        """get rucio Client for this client"""
        scitok = self.get_scitoken(request)
        if not scitok in self.rccache or self.mccexp[scitok] < time.time():
            username = self.get_username(scitok)
            # set token_file on client to /dev/null so we don't have to
            # track/clean up token_library files.
            try:
                # can't pass token into rucio client, so briefly set
                # BEARER_TOKEN, thread lock it so we don't get misplaced
                # authentication if we have multiple threads running...
                with self.rucio_env_lock:
                    os.environ["BEARER_TOKEN"] = scitok
                    self.rccache[scitok] = RClient(
                        auth_type="oidc", creds={"user": username}
                    )
                    self.rccache[scitok].whoami()
                    del os.environ["BEARER_TOKEN"]
                logger.info(f"getr_client: {self.rccache[scitok]=}")
            except:
                if "BEARER_TOKEN" in os.environ:
                    del os.environ["BEARER_TOKEN"]
                logger.info(f"Exception: {traceback.format_exc()}")
                raise HTTPException(401, "SciToken athentication failed")
            # cache for 5 minutes
            self.rcexp[scitok] = time.time() + 300
        return self.rccache[scitok]

    def getrrp_client(self, request: Request):
        """get rucio Client for this client"""
        scitok = self.get_scitoken(request)
        if not scitok in self.rrpccache or self.rrpcexp[scitok] < time.time():
            username = self.get_username(scitok)
            # set token_file on client to /dev/null so we don't have to
            # track/clean up token_library files.
            try:
                # can't pass token into rucio client, so briefly set
                # BEARER_TOKEN (?)
                os.environ["BEARER_TOKEN"] = scitok
                self.rrpccache[scitok] = ReplicaClient(
                    auth_type="oidc", creds={"user": username}
                )
                del os.environ["BEARER_TOKEN"]
                logger.info(f"getrrp_client: {self.rrpccache[scitok]=}")
            except:
                if "BEARER_TOKEN" in os.environ:
                    del os.environ["BEARER_TOKEN"]
                logger.info(f"Exception: {traceback.format_exc()}")
                raise HTTPException(401, "SciToken athentication failed")
            # cache for 5 minutes
            self.rrpcexp[scitok] = time.time() + 300
        return self.rrpccache[scitok]

    def clean_expired(self):
        # needs rucio caches!
        now = time.time()
        for tok in self.mccexp:
            if self.mccexp < now:
                del self.mccexp[tok]
                del self.mcccache[tok]
        for tok in self.ddcexp:
            if self.ddcexp < now:
                del self.ddcexp[tok]
                del self.ddccache[tok]


client_cache = ClientCache()


class ClientCacheMixin:
    def __init__(self, *args, **kwargs):
        self.client_cache = client_cache
        # self.namespace = "sam"
        # for testing:
        self.namespace = "mengel"
        self.default_dataset = "mengel:all"
        self.mcc = MetadataConverter(experiment=os.environ.get("SAM_EXPERIMENT", ""))
        # XXX needs to come from config...
        self.base = f"https://{os.uname().nodename}:9443"


# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# classes for dispatching/handling web calls via CherryPy


@cbv(router)
class Definitions(ClientCacheMixin):
    """dispatcher and methods for /api/definitions paths"""

    @router.get(
        "/sam/{experiment}/api/definitions/list",
        response_class=responses.PlainTextResponse,
    )
    def list(
        self,
        request: Request,
        experiment,
        defname="",
        user="",
        group="",
        after="",
        before="",
        format="",
    ):
        client = self.client_cache.getmc_client(request)
        if not defname:
            defname = "*"
        query = f"queries matching {self.namespace}:{defname}"
        sep = "where"
        if user:
            query = f"{query} {sep} creator={user}"
            sep = "and"
        if after:
            query = f"{query} {sep} created_timestamp>'{after}'"
            sep = "and"
        if before:
            query = f"{query} {sep} created_timestamp<'{before}'"
            sep = "and"

        logger.info(f"searching with {query=}")
        dlist = list(client.search_named_queries(query))
        logger.info(f"got back {dlist=}")
        return "\n".join([x["name"] for x in dlist])

    @router.post(
        "/sam/{experiment}/api/definitions/create",
        response_class=responses.PlainTextResponse,
    )
    def create(self, request: Request, experiment, defname, dims, user, group=None):
        client = self.client_cache.getmc_client(request)
        mq = SAM_query_to_MetaCat(dims)
        client.create_named_query(self.namespace, defname, mq)

    @router.delete(
        "/sam/{experiment}/api/definitions/name/{defname}",
        response_class=responses.PlainTextResponse,
    )
    def delete(self, experiment, defname, request: Request):
        raise NotImplementedError()

    @router.get(
        "/sam/{experiment}/api/definitions/name/{defname}",
        response_class=responses.PlainTextResponse,
    )
    def get(self, request: Request, experiment, defname, format="json"):
        client = self.client_cache.getmc_client(request)
        res = client.get_named_query(self.namespace, defname)
        logger.info(f"got {res=} for {defname=}")
        if format == "plain":
            res = f"""
Definition Name: {defname}
  Definition Id: {res['created_timestamp']}
  Creation Date: {time.strftime("%Y-%M-%D %h:%m:%s", time.gmtime(res['created_timestamp']))}
       Username: {res['creator']}
          Group: None
     Dimensions: {res['source']}"""

        return res

    @router.get(
        "/sam/{experiment}/api/definitions/name/{defname}/files/count",
        response_class=responses.PlainTextResponse,
    )
    def files_count(self, experiment, defname, request: Request):
        sdict = self.summary(defname, request)
        logger.info(f"got {sdict=} {sdict['count']}")
        return str(sdict["count"])

    def summary(self, defname, request: Request):
        client = self.client_cache.getmc_client(request)
        res = list(
            client.query(f"files selected by {self.namespace}:{defname}", summary="count")
        )[0]
        return res

    @router.get(
        "/sam/{experiment}/api/definitions/name/{defname}/files/summary",
        response_class=responses.PlainTextResponse,
    )
    def files_summary(self, experiment, defname, request: Request):
        sdict = self.summary(defname, request)
        sdict["file_count"] = sdict["count"]
        sdict["total_file_size"] = sdict["total_size"]
        sdict["total_event_count"] = 0
        logger.info(f"{sdict=}")
        return json.dumps(sdict)

    @router.get(
        "/sam/{experiment}/api/definitions/name/{defname}/files/list",
        response_class=responses.PlainTextResponse,
    )
    def files_list(self, request: Request, experiment, defname="", format=""):
        client = self.client_cache.getmc_client(request)
        res = list(client.query(f"files selected by {self.namespace}:{defname}"))
        logger.info(f"{res=}")
        if format == "json":
            return json.dumps(res)
        else:
            return "\n".join([e["name"] for e in res])


@cbv(router)
class Files(ClientCacheMixin):
    """dispatcher and methods for /api/files paths"""

    def convert_sam_query(self, dims):
        return SAM_query_to_MetaCat(dims)

    @router.get(
        "/sam/{experiment}/api/files/list", response_class=responses.PlainTextResponse
    )
    def list(self, request: Request, experiment, dims="", fileinfo=""):
        mquery = self.convert_sam_query(dims)
        logger.info(f"list: converted {dims=} to {mquery=}")
        client = self.client_cache.getmc_client(request)
        res = client.query(mquery)
        return "\n".join([x["name"] for x in res])

    @router.get(
        "/sam/{experiment}/api/files/count", response_class=responses.PlainTextResponse
    )
    def count(self, experiment, dims, request: Request):
        return self._summary(dims, request)["count"]

    def _summary(self, dims, request: Request):
        mquery = self.convert_sam_query(dims)
        client = self.client_cache.getmc_client(request)
        res = list(client.query(mquery, summary="count"))[0]
        return res

    @router.get(
        "/sam/{experiment}/api/files/summary", response_class=responses.PlainTextResponse
    )
    def summary(self, experiment, dims, request: Request):
        sdict = self._summary(dims, request)
        sdict["file_count"] = sdict["count"]
        sdict["total_file_size"] = sdict["total_size"]
        sdict["total_event_count"] = 0
        logger.info(f"{sdict=}")
        return json.dumps(sdict)

    @router.get(
        "/sam/{experiment}/api/files/name/{name}/locations",
        response_class=responses.PlainTextResponse,
    )
    def get_name_locations(
        self, request: Request, experiment: str, name: str = "", format: str = ""
    ):
        logger.info(f"get_name_locations {name=}")
        rpclient = self.client_cache.getrrp_client(request)
        data = list(rpclient.list_replicas([{"scope": self.namespace, "name": name}]))
        logger.info(f"get_name_locations: {data=}")
        if not data:
            return "[]"
            # raise HTTPException(404, 'Location not found')
        pfns = data[0]["pfns"]
        res = []
        for pfn, dat in pfns.items():
            rse = dat["rse"]
            ploc = pfn.find("/", 9)
            res.append({"location": f"{rse}:{pfn[ploc:]}"})
        if format and format == "plain":
            res = "\n".join(res)
        else:
            res = json.dumps(res)

        logger.info(f"get_name_locations: {res=}")
        return res

    @router.put(
        "/sam/{experiment}/api/files/name/{name}/locations",
        response_class=responses.PlainTextResponse,
    )
    def put_name_locations(self, request: Request, experiment, file, add="", remove=""):
        rpclient = self.client_cache.getrrp_client(request)
        mcclient = self.client_cache.getmc_client(request)

        if add:
            samloc = add
            rse, path = samloc.split(":", 1)
            metadata = mcclient.get_file(
                name=file, namespace=self.namespace, with_metadata=True
            )
            rclient.add_replica(
                rse,
                self.namespace,
                file,
                metadata["size"],
                metadata["checksums"]["adler32"],
            )
        if remove:
            samloc = remove
            rse, path = samloc.split(":", 1)
            # not sure we should do this... I think for now this is a noop
            # also not an api call to remove just one replica on an rse...
        return "ok"

    @router.get(
        "/sam/{experiment}/api/files/name/{name}/metadata",
        response_class=responses.PlainTextResponse,
    )
    def get_name_metadata(self, request: Request, experiment, name=None, format="plain"):
        mcclient = self.client_cache.getmc_client(request)
        metadata = mcclient.get_file(
            name=name, namespace=self.namespace, with_metadata=True
        )
        converted_metadata = self.mcc.convert_all_mc_sam(metadata)
        if format == "json":
            return json.dumps(converted_metadata)
        else:
            return "\n".join([f"{k:>20}:\t{v}" for k, v in converted_metadata.items()])

    def traverse_linage(self, request: Request, mcclient, name, ltype, raw=False):
        data = mcclient.get_file(
            name=name, namespace=self.namespace, with_provenance=True
        )
        res1 = data[ltype]
        res = []
        if raw:
            if len(res1) == 0:
                res.append(f"{self.namespace}:{name}")
        else:
            res.extend(res1)
        for fid in res1:
            cname = res1.split(":")[1]
            nextgen = self.traverse_lineage(mcclient, cname, ltype, raw)
            if raw and len(nextgen == 0):
                res.append(f"{self.namespace}:{cname}")
            else:
                res.extend(nextgen)
        return res

    @router.get(
        "/sam/{experiment}/api/files/name/{name}/lineage/{ltype}",
        response_class=responses.PlainTextResponse,
    )
    def lineage(self, request: Request, name, ltype, format="plain"):
        # ltype is: parents, children, rawancestors
        mcclient = self.client_cache.getmc_client(request)
        data = mcclient.get_file(
            name=file, namespace=self.namespace, with_provenance=True
        )
        if ltype in {"parents", "children"}:
            res = data[ltype]
        if ltype == "ancestors":
            res = self.traverse_lineage(mcclient, name, "parents")
        if ltype == "descendants":
            res = self.traverse_lineage(mcclient, name, "children")
        if ltype == "rawancestors":
            res = self.traverse_lineage(mcclient, name, "parents", raw=True)

        if format == "json":
            return json.dumps(res)
        else:
            return "\n".join(res)

    @router.post(
        "/sam/{experiment}/api/files", response_class=responses.PlainTextResponse
    )
    def post(self, experiment: str, metadata: Dict[str, Any], request: Request):
        """declare a file..."""
        mcclient = self.client_cache.getmc_client(request)
        try:
            mc_metadata = self.mcc.convert_all_sam_mc(metadata, namespace=self.namespace)
            mcclient.declare_files(self.default_dataset, [mc_metadata], self.namespace)
        except AlreadyExistsError as e:
            raise HTTPException(409, detail="File already exists")
        except InvalidMetadataError as e:
            raise HTTPException(400, detail=f"Invalid metadata: {e}")

        return ""

    @router.post(
        "/sam/{experiment}/api/files/validate_metadata",
        response_class=responses.PlainTextResponse,
    )
    def validate_metadata(self, experiment, metadata: Dict[str, Any], request: Request):
        mcclient = self.client_cache.getmc_client(request)
        mc_metadata = self.mcc.convert_all_sam_mc(metadata)
        try:
            resp = mcclient.declare_files(files=[mc_metadata], dry_run=True)
            return ""
        except:
            raise HTTPException(400, f"Invalid metadata: {e}")

    @router.put(
        "/sam/{experiment}/api/files/name/{name}/metadata",
        response_class=responses.PlainTextResponse,
    )
    def put_name_metadata(
        self, experiment, name, metadata: Dict[str, Any], request: Request
    ):
        mcclient = self.client_cache.getmc_client(request)
        mc_metadata = self.mcc.convert_all_sam_mc(metadata)
        did = f"{self.default_dataset}:{name}"
        mcclient.update_file_metadata(mc_metadata["metadata"], dids=[did])
        return ""

    @router.put(
        "/sam/{experiment}/api/files/id/{file_id}/metadata",
        response_class=responses.PlainTextResponse,
    )
    def put_id_metadata(
        self, experiment, file_id, metadata: Dict[str, Any], request: Request
    ):
        mcclient = self.client_cache.getmc_client(request)
        mc_metadata = self.mcc.convert_all_sam_mc(metadata)
        mcclient.update_file_metadata(mc_metadata["metadata"], fids=[file_id])
        return ""

    @router.put(
        "/sam/{experiment}/api/files/name/{name}/content_status",
        response_class=responses.PlainTextResponse,
    )
    def put_name_content_status(self, experiment, name, status: str, request: Request):
        mcclient = self.client_cache.getmc_client(request)
        mcclient.update_file_metadata({"core.content_status": status}, fids=[file_id])
        return ""

    @router.put(
        "/sam/{experiment}/api/files/id/{file_id}/content_status",
        response_class=responses.PlainTextResponse,
    )
    def put_id_content_status(self, experiment, file_id, status: str, request: Request):
        mc_metadata = self.mcc.convert_all_sam_mc(metadata)
        did = f"{self.default_dataset}:{name}"
        mcclient.update_file_metadata({"core.content_status": status}, dids=[did])
        return ""


@cbv(router)
class Users(ClientCacheMixin):
    """dispatcher and methods for /api/users paths"""

    @router.get(
        "/sam/{experiment}/api/users/", response_class=responses.PlainTextResponse
    )
    def get(self, experiment, username=None, format="plain", status=None):
        raise NotImplementedError()

    @router.post(
        "/sam/{experiment}/api/users/", response_class=responses.PlainTextResponse
    )
    def post(self, experiment, jsondata):
        raise NotImplementedError()

    @router.get(
        "/sam/{experiment}/api/users/name/{name}",
        response_class=responses.PlainTextResponse,
    )
    def get_by_name(self, experiment, name):
        raise NotImplementedError()

    @router.get(
        "/sam/{experiment}/api/users/id/{uid}", response_class=responses.PlainTextResponse
    )
    def get_by_id(self, experiement, uid):
        raise NotImplementedError()

    @router.put(
        "/sam/{experiment}/api/users/name/{name}",
        response_class=responses.PlainTextResponse,
    )
    def put_by_name(self, experiment, name, jsondata):
        raise NotImplementedError()

    @router.put(
        "/sam/{experiment}/api/users/id/{uid}", response_class=responses.PlainTextResponse
    )
    def put_by_id(self, experiment, uid, jsondata):
        raise NotImplementedError()


@cbv(router)
class Values(ClientCacheMixin):
    """dispatcher and methods for /api/values paths"""

    @router.get(
        "/sam/{experiment}/api/values/parameters",
        response_class=responses.PlainTextResponse,
    )
    def get_parameters(self, experiment, request: Request):
        mcclient = self.client_cache.getmc_client(request)
        keylist = list(mcclient.report_metadata_keys())
        return "\n".join(keylist)

    @router.post(
        "/sam/{experiment}/api/values/parameters",
        response_class=responses.PlainTextResponse,
    )
    def post_parameters(self, experimient, name, category, data_type, request: Request):
        # don't need to pre-post parameters in MetaCat, so
        return ""

    @router.get(
        "/sam/{experiment}/api/values/applications",
        response_class=responses.PlainTextResponse,
    )
    def get_applications(self, experiment, request: Request):
        mcclient = self.client_cache.getmc_client(request)
        vlist = mcclient.report_metadata_values("app.version")
        flist = mcclient.report_metadata_values("app.family")
        nlist = mcclient.report_metadata_values("app.name")
        # well, we don't actually easily get the correlations, so...
        # just permute the families, names and verions.
        res = []
        for f in flist:
            for n in nlist:
                for v in vlist:
                    res.append(f"{f}   {n}    {v}")
        return "\n".join(res)

    @router.post(
        "/sam/{experiment}/api/values/applications",
        response_class=responses.PlainTextResponse,
    )
    def post_applications(self, experiment, family, name, version, request: Request):
        # don't need to pre-post applications in MetaCat, so
        # just say its "ok"...
        return ""


@cbv(router)
class Projects(ClientCacheMixin):
    """dispatcher and methods for /api/project paths"""

    last_process_file = {}
    last_project_finished = {}

    def __init__(self, request: Request):
        ClientCacheMixin.__init__(self)
        self.last_process_file = Projects.last_process_file
        self.project_finished = Projects.last_project_finished

    @router.post(
        "/sam/{experiment}/api/project/id/{project_id}/establishProcess",
        response_class=responses.PlainTextResponse,
    )
    def establishProcess(
        self,
        request: Request,
        experiment,
        project_id,
        appname: Annotated[str, Form()],
        appversion: Annotated[str, Form()],
        node: Annotated[str, Form()],
        deliverylocation: Annotated[str, Form()] = None,
        username: Annotated[str, Form()] = None,
        subject: Annotated[str, Form()] = None,
        appfamily: Annotated[str, Form()] = None,
        description: Annotated[str, Form()] = None,
        filelimit: Annotated[str, Form()] = None,
        schemas: Annotated[str, Form()] = None,
    ):
        ddclient = self.client_cache.getdd_client(request)
        logger.info("establishProcess...")
        return ddclient.new_worker_id()

    @router.post(
        "/sam/{experiment}/api/project/id/{project_id}/process/{process_id}/getNextFile",
        response_class=responses.PlainTextResponse,
    )
    def getNextFile(
        self, experiment, project_id, process_id, request: Request, response: Response
    ):
        ddclient = self.client_cache.getdd_client(request)
        res = ddclient.next_file(project_id=project_id, worker_id=process_id)
        # just return the url from the first replica
        logger.info(f"next_file gives: {res=}")
        if res:
            rname, rdict = list(res["replicas"].items())[0]
            name = res["name"]
            namespace = res["namespace"]
            self.last_process_file[process_id] = name
            logger.info(f"getNextFile: set last_process_file {name}")
            return rdict["url"]
        else:
            self.project_finished[project_id] = True
            return responses.PlainTextResponse(status_code=204, content="")

    @router.post(
        "/sam/{experiment}/api/project/id/{project_id}/process/{process_id}/updateFileStatus",
        response_class=responses.PlainTextResponse,
    )
    def updateFileStatus(
        self,
        request: Request,
        experiment,
        process_id,
        project_id,
        status="consumed",
        filename=None,
    ):
        logger.info(
            f"updateFileStatus: {process_id=} {status=} {filename=} {project_id=}"
        )
        if status == "consumed":
            return self.releaseFile(
                process_id,
                "ok",
                project_id,
                filename,
                request,
            )
        if status == "skipped":
            return self.releaseFile(
                process_id,
                "bad",
                project_id,
                filename,
                request,
            )
        return ""

    @router.post(
        "/sam/{experiment}/api/project/id/{project_id}/process/{process_id}/releaseFile",
        response_class=responses.PlainTextResponse,
    )
    def releaseFile(self, process_id, status, project_id, filename, request: Request):
        logger.info(f"releaseFile: {process_id=} {status=} {filename=} {project_id=}")
        if not filename and self.last_process_file.get(process_id, ""):
            filename = self.last_process_file[process_id]
            logger.info(f"releaseFile: got last_process_file {filename}")
            del self.last_process_file[process_id]
        if not filename:
            return ""
        ddclient = self.client_cache.getdd_client(request)
        filename = os.path.basename(filename)
        did = f"{self.namespace}:{filename}"
        if status == "ok":
            ddclient.file_done(project_id, did, process_id)
        else:
            ddclient.file_failed(project_id, did, process_id)
        return ""

    @router.post(
        "/sam/{experiment}/api/project/id/{project_id}/process/{process_id}/endProcess",
        response_class=responses.PlainTextResponse,
    )
    def endProcess(self, experiment, project_id, process_id, request: Request):
        # don't need to do this...
        return ""

    @router.post(
        "/sam/{experiment}/api/project/id/{project_id}/endProject",
        response_class=responses.PlainTextResponse,
    )
    def endProject(self, experiment, project_id, request: Request):
        """if we haven't seen a getNextFile return nothing, cancel it"""
        if project_id not in self.project_finished:
            ddclient = self.client_cache.getdd_client(request)
            ddclient.cancel_project(project_id)
        return ""

    # same function for project or process status, which is a put
    # we ignore..
    @router.put(
        "/sam/{experiment}/api/project/id/{project_id}/process/{process_id}/status",
        response_class=responses.PlainTextResponse,
    )
    def ppstatus(
        self,
        request: Request,
        experiment,
        process_id=None,
        project_id=None,
        status: Annotated[str, Form] = None,
    ):
        pass

    @router.put(
        "/sam/{experiment}/api/project/id/{project_id}/status",
        response_class=responses.PlainTextResponse,
    )
    def pstatus(
        self, experiment, process_id, status: Annotated[str, Form()], request: Request
    ):
        pass

    @router.get(
        "/sam/{experiment}/api/project/id/{project_id}/status",
        response_class=responses.PlainTextResponse,
    )
    def get(self, experiment, project_id, request: Request):
        ddclient = self.client_cache.getdd_client(request)
        return json.dumps(ddclient.get_project(project_id))

    @router.get(
        "/sam/{experiment}/api/project/id/{project_id}/dumpProject",
        response_class=responses.PlainTextResponse,
    )
    def dumpProject(self, experiment, project_id, request: Request):
        ddclient = self.client_cache.getmc_client(request)
        return json.dumps(ddclient.get_project(project_id))

    @router.get(
        "/sam/{experiment}/api/projects/name/{name}/summary",
        response_class=responses.PlainTextResponse,
    )
    def summary(self, experiment, name, request: Request):
        ddclient = self.client_cache.getmc_client(request)
        #  xxx mimic sam Project summary?
        return json.dumps(ddclient.list_projects(attributes={"name": name})[0])

    @router.get(
        "/sam/{experiment}/api/project/name/{name}/recovery_dimensions",
        response_class=responses.PlainTextResponse,
    )
    def recovery_dimensions(
        self, request: Request, experiment, name, useFile=0, useProcess=0
    ):
        # wimpy non process version
        return "project name minus project_status like 'com%'"


@cbv(router)
class Api(ClientCacheMixin):
    """dispatcher and methods for /api/ paths"""

    @router.get("/sam/{experiment}/api", response_class=responses.PlainTextResponse)
    def index(self, request: Request):
        logger.info("test message")
        return '{"app":"samwebish", "version": samwebish_version}'

    @router.get(
        "/sam/{experiment}/api/createDefinition",
        response_class=responses.PlainTextResponse,
    )
    def createDefinition(self, request: Request, experiment, name, dims, user=""):
        return Definitions.create(self, experiment, name, dims, user, request)

    @router.get(
        "/sam/{experiment}/api/deleteDefinition",
        response_class=responses.PlainTextResponse,
    )
    def deleteDefinition(self, experiment, name, request: Request):
        return Definitions.delete(self, experiment, name, request)

    @router.get(
        "/sam/{experiment}/api/describeDefinition",
        response_class=responses.PlainTextResponse,
    )
    def describeDefinition(self, experiment, name, request: Request):
        return Definitions.get(self, experiment, name, request)

    @router.get(
        "/sam/{experiment}/api/translateConstraints",
        response_class=responses.PlainTextResponse,
    )
    def translateConstraints(self, request: Request, experiment, dims, format="plain"):

        return Files.list(experiment, dims, format, request)

    @router.get(
        "/sam/{experiment}/api/locateFile", response_class=responses.PlainTextResponse
    )
    def locateFile(self, experiment, file, request: Request):
        return Files.get_name_locations(self, experiment, file, request)

    @router.get(
        "/sam/{experiment}/api/getMetadata", response_class=responses.PlainTextResponse
    )
    def getMetadata(self, experiment, name, request: Request):
        return Files.get_name_metadata(self, experiment, name, request)

    @router.get(
        "/sam/{experiment}/api/dumpStation", response_class=responses.PlainTextResponse
    )
    def dumpStation(self, request: Request, experiment, station, dump="all"):
        ddclient = self.client_cache.getdd_client(request)
        rlst = list(ddclient.list_projects())
        logger.info(f"dumpStation: got {rlst=}")
        res = f"samwebish version {samwebish_version}\n{len(rlst)} active projects:\n"
        res += "\n".join(
            [
                f"project {x['attributes'].get('name','')} id {x['project_id']} owner: {x['owner']} state: {x['state']} files: {len(x['file_handles'])} "
                for x in rlst
            ]
        )
        return res

    @router.post(
        "/sam/{experiment}/api/startProject", response_class=responses.PlainTextResponse
    )
    def startProject(
        self,
        request: Request,
        experiment: str,
        name: Annotated[str, Form()],
        station: Annotated[str, Form()],
        username: Annotated[str, Form()] = None,
        subject: Annotated[str, Form()] = None,
        defname: Annotated[str, Form()] = None,
        def_id: Annotated[str, Form()] = None,
        snapshot_id: Annotated[str, Form()] = None,
        group: Annotated[str, Form()] = None,
    ):
        ddclient = self.client_cache.getdd_client(request)
        mcclient = self.client_cache.getmc_client(request)
        q = None
        if defname:
            q = f"files selected by {self.namespace}:{defname}"
        if def_id:
            q = f"files selected by {self.namespace}:{def_id}"
        if snapshot_id:
            q = f"files from {self.namespace}:snapshot_{snapshot_id}"
        if not q:
            raise HTTPException(400, detail=f"One of defname, def_id, snapshot_id requiered")
        try:
            files = list(mcclient.query(q))
        except BadRequestError:
            raise HTTPException(404, f"Defname {defname} not found")
        sid = f"{self.namespace}:snapshot_for_project_{name}"
        logger.info(f"startProject: {q=} {sid=} {files=}") # drop for production
        ds = mcclient.create_dataset(sid)
        mcclient.add_files(sid, files)
        p = ddclient.create_project(files, project_attributes={"name": name}, query=q)
        return f"{self.base}/sam/{experiment}/api/project/id/{p['project_id']}"

    @router.get(
        "/sam/{experiment}/api/findProject", response_class=responses.PlainTextResponse
    )
    def findProject(self, experiment, name, request: Request):
        ddclient = self.client_cache.getdd_client(request)
        pl = list(ddclient.list_projects(attributes={"name": name}))
        if not pl:
            raise HTTPException(404, "Project not found")
        p = pl[0]
        b = request.base_url
        return f"{self.base}/sam/{experiment}/api/project/id/{p['project_id']}"

app.include_router(router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
