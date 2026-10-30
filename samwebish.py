#!/usr/bin/env python
# pylint: disable=too-many-lines,logging-fstring-interpolation,too-many-positional-arguments,too-many-arguments,unused-argument

""" Samwebish: API converter, lets SAM clients use MetaCat+DataDispatcher+Rucio """

import base64
import json

from typing import Annotated, Any, Dict
import logging
import os
import os.path
import re
import threading
import time
import traceback

from fastapi.utils import is_body_allowed_for_status_code
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
import fastapi
from fastapi_utils.cbv import cbv

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
from version import samwebish_version

logger = logging.getLogger(__name__)
logging.basicConfig(filename="logs/samwebish.log", level=logging.DEBUG)


app = fastapi.FastAPI()

MWordP = Annotated[str, fastapi.Path(title="Metacat Word or FID", pattern="^[-/.a-zA-Z0-9_]*$")]
MWordQ = Annotated[str, fastapi.Query(title="Metacat Word or FID", pattern="^[-/.a-zA-Z0-9_]*$")]


def custom_openapi():
    """customizes OpenAPI interface"""
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Samwebish",
        version="0.0.4",
        description=(
            "SAM API for Metacat/Rucio\n\n"
            "To authorize, paste encoded token in Authorize popup"
        ),
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
    }
    openapi_schema["security"] = [{"BearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# override RequestValidationError to log the validation message
# and also add "message" and "error" tags to response for Samweb client
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: fastapi.Request, exc: RequestValidationError):
    """customize validation exceptions -- log them"""
    # pylint: disable=logging-fstring-interpolation
    logging.error(f"{request}: {exc}")
    exc_str = f"{exc}".replace("\n", " ").replace("   ", " ")
    content = {
        "status_code": 10422,
        "message": exc_str,
        "error": "validation",
        "data": None,
    }
    return fastapi.responses.JSONResponse(
        content=content, status_code=fastapi.status.HTTP_422_UNPROCESSABLE_ENTITY
    )


# override exception handlers to include "message" as well as "detail"
# in JSON error fastapi.responses, to make samweb client happy
@app.exception_handler(fastapi.HTTPException)
async def http_exception_handler(
    request: fastapi.Request, exc: fastapi.HTTPException
) -> fastapi.Response:  # pylint: disable=unused-argument
    """
    custom exception handler to make SAM clients happy
    with "message" and "error" keys in response
    """
    headers = getattr(exc, "headers", None)
    if not is_body_allowed_for_status_code(exc.status_code):
        return fastapi.Response(status_code=exc.status_code, headers=headers)
    return fastapi.responses.JSONResponse(
        {
            "detail": exc.detail,
            "message": exc.detail,
            "error": "exception",
        },
        status_code=exc.status_code,
        headers=headers,
    )


router = fastapi.APIRouter()

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# classes for authentication, client connection caching


# pylint: disable=too-many-instance-attributes, consider-using-dict-items
class ClientCache:

    """
    Client connection cache -- cache open connections per client
    also handles forwarding SciToken credentials on opening said
    connections
    """

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
        self.nthcall = 0

    def get_scitoken(
        self,
        request: fastapi.Request,
    ):
        """extract scitoken from Authorization: header"""
        # ------------
        # all the get methods call here, so clean expired entries every so often
        self.nthcall += 1
        if self.nthcall > 10:
            self.clean_expired()
        # ------------
        logger.debug(f"headers: {dict(request.headers)}")
        authheader = request.headers.get("Authorization", "")
        if not authheader:
            raise fastapi.HTTPException(401, "SciToken athentication required")
        return authheader[self.token_offset :]

    def cheap_decode_token(self, scitok):
        """extract json data from jwt token without validating, etc."""

        if scitok:
            tp = scitok.split(".")
            return json.loads(base64.b64decode(tp[1] + "==", altchars="_-"))
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

        # pylint: disable=logging-fstring-interpolation
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
        logger.info("Returning: None!")
        return None

    def getdd_client(self, request: fastapi.Request):
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
                # pylint: disable = raise-missing-from
                raise fastapi.HTTPException(401, "SciToken athentication failed")
            self.ddcexp[scitok] = time.time() + 300
        return self.ddccache[scitok]

    def getmc_client(self, request: fastapi.Request):
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
                # pylint: disable=raise-missing-from
                raise fastapi.HTTPException(401, "SciToken athentication failed")
            # cache for 5 minutes
            self.mccexp[scitok] = time.time() + 300
        return self.mcccache[scitok]

    def getr_client(self, request: fastapi.Request):
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
                # pylint: disable=logging-fstring-interpolation
                logger.info(f"getr_client: {self.rccache[scitok]=}")
            except:
                if "BEARER_TOKEN" in os.environ:
                    del os.environ["BEARER_TOKEN"]
                # pylint: disable=logging-fstring-interpolation, raise-missing-from
                logger.info(f"Exception: {traceback.format_exc()}")
                raise fastapi.HTTPException(401, "SciToken athentication failed")
            # cache for 5 minutes
            self.rcexp[scitok] = time.time() + 300
        return self.rccache[scitok]

    def getrrp_client(self, request: fastapi.Request):
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
                # pylint: disable=raise-missing-from
                raise fastapi.HTTPException(401, "SciToken athentication failed")
            # cache for 5 minutes
            self.rrpcexp[scitok] = time.time() + 300
        return self.rrpccache[scitok]

    def clean_expired(self):
        """clean expired items from cache"""
        now = time.time()
        for tok in self.mccexp:
            if self.mccexp[tok] < now:
                del self.mccexp[tok]
                del self.mcccache[tok]
        for tok in self.ddcexp:
            if self.ddcexp[tok] < now:
                del self.ddcexp[tok]
                del self.ddccache[tok]
        for tok in self.rcexp:
            if self.rcexp[tok] < now:
                del self.rcexp[tok]
                del self.rccache[tok]
        for tok in self.rrpcexp:
            if self.rrpcexp[tok] < now:
                del self.rrpcexp[tok]
                del self.rrpccache[tok]


client_cache = ClientCache()


# pylint: disable = too-few-public-methods
class ClientCacheMixin:
    """mixin to share a client cache"""

    def __init__(self):
        """initialize"""
        self.client_cache = client_cache
        # self.namespace = "sam"
        # for testing:
        self.namespace = "mengel"
        self.default_dataset = "mengel:all"
        self.mcc = MetadataConverter(experiment=os.environ.get("SAM_EXPERIMENT", ""))
        # pylint: disable = fixme
        # XXX needs to come from config...
        self.base = f"https://{os.uname().nodename}:8483"


# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# classes for dispatching/handling web calls via CherryPy


@cbv(router)
class Definitions(ClientCacheMixin):
    """dispatcher and methods for /api/definitions paths"""

    @router.get(
        "/sam/{experiment}/api/definitions/list",
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=redefined-builtin
    def list(
        self,
        request: fastapi.Request,
        experiment: MWordP,
        defname: MWordQ = "",
        user: MWordQ = "",
        group="",
        after="",
        before="",
        format="",
    ):  # pylint: disable=unused-argument
        """list definitions"""
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
        response_class=fastapi.responses.PlainTextResponse,
    )
    def create(
        self,
        request: fastapi.Request,
        experiment: MWordP,
        defname,
        dims,
        user: MWordQ,
        group=None,
    ):
        """Create a SAM Definition == MetaCat named_query"""
        client = self.client_cache.getmc_client(request)
        mq = SAM_query_to_MetaCat(dims)
        client.create_named_query(self.namespace, defname, mq)

    @router.delete(
        "/sam/{experiment}/api/definitions/name/{defname}",
        response_class=fastapi.responses.PlainTextResponse,
    )
    def delete(self, experiment: MWordP, defname, request: fastapi.Request):
        """Delete definition (not implemented)"""
        raise fastapi.HTTPException(501, detail="Not Implemented")

    @router.get(
        "/sam/{experiment}/api/definitions/name/{defname}",
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=redefined-builtin
    def get(self, request: fastapi.Request, experiment: MWordP, defname, format="json"):
        """Get information on definition"""
        client = self.client_cache.getmc_client(request)
        res = client.get_named_query(self.namespace, defname)
        logger.info(f"got {res=} for {defname=}")
        if format == "plain":
            res = f"""
Definition Name: {defname}
  Definition Id: {res['created_timestamp']}
  Creation Date: {time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(res['created_timestamp']))}
       Username: {res['creator']}
          Group: None
     Dimensions: {res['source']}"""
        else:
            res = json.dumps(res)

        return res

    @router.get(
        "/sam/{experiment}/api/definitions/name/{defname}/files/count",
        response_class=fastapi.responses.PlainTextResponse,
    )
    def files_count(self, experiment: MWordP, defname, request: fastapi.Request):
        """count files currently matched by definition"""
        sdict = self.summary(defname, request)
        logger.info(f"got {sdict=} {sdict['count']}")
        return str(sdict["count"])

    def summary(self, defname, request: fastapi.Request):
        """give summary of files matched by defininition"""
        client = self.client_cache.getmc_client(request)
        res = list(
            client.query(f"files selected by {self.namespace}:{defname}", summary="count")
        )[0]
        return res

    @router.get(
        "/sam/{experiment}/api/definitions/name/{defname}/files/summary",
        response_class=fastapi.responses.PlainTextResponse,
    )
    def files_summary(self, experiment: MWordP, defname, request: fastapi.Request):
        """give summary of files matched by defininition"""
        sdict = self.summary(defname, request)
        sdict["file_count"] = sdict["count"]
        sdict["total_file_size"] = sdict["total_size"]
        sdict["total_event_count"] = 0
        logger.info(f"{sdict=}")
        return json.dumps(sdict)

    @router.get(
        "/sam/{experiment}/api/definitions/name/{defname}/files/list",
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=redefined-builtin
    def files_list(self, request: fastapi.Request, experiment: MWordP, defname="", format=""):
        """list files matched by defininition"""
        client = self.client_cache.getmc_client(request)
        res = list(client.query(f"files selected by {self.namespace}:{defname}"))
        logger.info(f"{res=}")
        if format == "json":
            return json.dumps(res)
        return "\n".join([e["name"] for e in res])


@cbv(router)
class Files(ClientCacheMixin):
    """dispatcher and methods for /api/files paths"""

    def convert_sam_query(self, dims):
        """convert a sam query to metacat"""
        return SAM_query_to_MetaCat(dims)

    @router.get(
        "/sam/{experiment}/api/files/list", response_class=fastapi.responses.PlainTextResponse
    )
    def list(self, request: fastapi.Request, experiment: MWordP, dims="", fileinfo=""):
        """list files matched by dimension query"""
        mquery = self.convert_sam_query(dims)
        logger.info(f"list: converted {dims=} to {mquery=}")
        client = self.client_cache.getmc_client(request)
        res = client.query(mquery)
        return "\n".join([x["name"] for x in res])

    @router.get(
        "/sam/{experiment}/api/files/count", response_class=fastapi.responses.PlainTextResponse
    )
    def count(self, experiment: MWordP, dims, request: fastapi.Request):
        """count files matched by dimension query"""
        return self._summary(dims, request)["count"]

    def _summary(self, dims, request: fastapi.Request):
        """summarize files matched by dimension query"""
        mquery = self.convert_sam_query(dims)
        client = self.client_cache.getmc_client(request)
        res = list(client.query(mquery, summary="count"))[0]
        return res

    @router.get(
        "/sam/{experiment}/api/files/summary", response_class=fastapi.responses.PlainTextResponse
    )
    def summary(self, experiment: MWordP, dims, request: fastapi.Request):
        """summarize files matched by dimension query"""
        sdict = self._summary(dims, request)
        sdict["file_count"] = sdict["count"]
        sdict["total_file_size"] = sdict["total_size"]
        sdict["total_event_count"] = 0
        logger.info(f"{sdict=}")
        return json.dumps(sdict)

    @router.get(
        "/sam/{experiment}/api/files/name/{name}/locations",
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=redefined-builtin
    def get_name_locations(
        self, request: fastapi.Request, experiment: str, name: MWordP, format: str = ""
    ):
        """get locations for file by name"""
        logger.info(f"get_name_locations {name=}")
        rpclient = self.client_cache.getrrp_client(request)
        data = list(rpclient.list_replicas([{"scope": self.namespace, "name": name}]))
        logger.info(f"get_name_locations: {data=}")
        if not data:
            return "[]"
            # raise fastapi.HTTPException(404, 'Location not found')
        pfns = data[0]["pfns"]
        res = []
        for pfn, dat in pfns.items():
            rse = dat["rse"]
            ploc = pfn.find("/", 9)
            res.append({"location": f"{rse}:{pfn[ploc:]}"})
        if format and format == "plain":
            res = "\n".join([x["location"] for x in res])
        else:
            res = json.dumps(res)

        logger.info(f"get_name_locations: {res=}")
        return res

    @router.put(
        "/sam/{experiment}/api/files/name/{file}/locations",
        response_class=fastapi.responses.PlainTextResponse,
    )
    def put_name_locations(
        self, request: fastapi.Request, experiment: MWordP, file: MWordP, add="", remove=""
    ):
        """add locations for file by name"""
        rpclient = self.client_cache.getrrp_client(request)
        mcclient = self.client_cache.getmc_client(request)

        if add:
            samloc = add
            rse, path = samloc.split(":", 1)
            metadata = mcclient.get_file(
                name=file, namespace=self.namespace, with_metadata=True
            )
            rpclient.add_replica(
                rse,
                self.namespace,
                file,
                metadata["size"],
                metadata["checksums"]["adler32"],
                path=path,
            )
        # pylint: disable = fixme
        # xxx add to some dataset for rules?
        if remove:
            samloc = remove
            rse, path = samloc.split(":", 1)
            # not sure we should do this... I think for now this is a noop
            # also not an api call to remove just one replica on an rse...
        return "ok"

    @router.get(
        "/sam/{experiment}/api/files/name/{name}/metadata",
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=redefined-builtin
    def get_name_metadata(
        self, request: fastapi.Request, experiment: MWordP, name: MWordP, format="plain"
    ):
        """get metadata for file by name"""
        mcclient = self.client_cache.getmc_client(request)
        metadata = mcclient.get_file(
            name=name, namespace=self.namespace, with_metadata=True
        )
        logger.debug(f"From metacat: {metadata=}")
        converted_metadata = self.mcc.convert_all_mc_sam(metadata)
        logger.debug(f"From converter: {converted_metadata=}")
        if format == "json":
            return json.dumps(converted_metadata)
        return "\n".join([f"{k:>20}:\t{v}" for k, v in converted_metadata.items()])

    def traverse_lineage(self, request: fastapi.Request, mcclient, name, ltype, raw=False):
        """get file lineage"""
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
            cname = fid.split(":")[1]
            nextgen = self.traverse_lineage(request, mcclient, cname, ltype, raw)
            if raw and len(nextgen == 0):
                res.append(f"{self.namespace}:{cname}")
            else:
                res.extend(nextgen)
        return res

    @router.get(
        "/sam/{experiment}/api/files/name/{name}/lineage/{ltype}",
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=redefined-builtin
    def lineage(self, request: fastapi.Request, name: MWordP, ltype: MWordP, format="plain"):
        """get file lineage"""
        # ltype is: parents, children, rawancestors
        mcclient = self.client_cache.getmc_client(request)
        data = mcclient.get_file(
            name=name, namespace=self.namespace, with_provenance=True
        )
        res = []
        if ltype in {"parents", "children"}:
            res = data[ltype]
        if ltype == "ancestors":
            res = self.traverse_lineage(request, mcclient, name, "parents")
        if ltype == "descendants":
            res = self.traverse_lineage(request, mcclient, name, "children")
        if ltype == "rawancestors":
            res = self.traverse_lineage(request, mcclient, name, "parents", raw=True)

        if format == "json":
            return json.dumps(res)
        return "\n".join(res)

    @router.post(
        "/sam/{experiment}/api/files", response_class=fastapi.responses.PlainTextResponse
    )
    def post(self, experiment: str, metadata: Dict[str, Any], request: fastapi.Request):
        """declare a file..."""
        mcclient = self.client_cache.getmc_client(request)
        try:
            mc_metadata = self.mcc.convert_all_sam_mc(metadata, namespace=self.namespace)
            mcclient.declare_files(self.default_dataset, [mc_metadata], self.namespace)
        except AlreadyExistsError as e:
            raise fastapi.HTTPException(409, detail="File already exists:") from e
        except InvalidMetadataError as e:
            raise fastapi.HTTPException(400, detail=f"Invalid metadata: {e}") from e

        return ""

    @router.post(
        "/sam/{experiment}/api/files/validate_metadata",
        response_class=fastapi.responses.PlainTextResponse,
    )
    def validate_metadata(
        self, experiment: MWordP, metadata: Dict[str, Any], request: fastapi.Request
    ):
        """verify metadata is valid"""
        mcclient = self.client_cache.getmc_client(request)
        mc_metadata = self.mcc.convert_all_sam_mc(metadata, namespace=self.namespace)
        try:
            mcclient.declare_files(files=[mc_metadata], dry_run=True)
            return ""
        except Exception as e:
            raise fastapi.HTTPException(400, detail=f"Invalid metadata: {e}") from e

    @router.put(
        "/sam/{experiment}/api/files/name/{name}/metadata",
        response_class=fastapi.responses.PlainTextResponse,
    )
    def put_name_metadata(
        self, experiment: MWordP, name: MWordP, metadata: Dict[str, Any], request: fastapi.Request
    ):
        """set metadata for file by name"""
        mcclient = self.client_cache.getmc_client(request)
        mc_metadata = self.mcc.convert_all_sam_mc(metadata, namespace=self.namespace)
        did = f"{self.default_dataset}:{name}"
        mcclient.update_file_metadata(mc_metadata["metadata"], dids=[did])
        return ""

    @router.put(
        "/sam/{experiment}/api/files/id/{file_id}/metadata",
        response_class=fastapi.responses.PlainTextResponse,
    )
    def put_id_metadata(
        self, experiment: MWordP, file_id, metadata: Dict[str, Any], request: fastapi.Request
    ):
        """set metadata for file by id"""
        mcclient = self.client_cache.getmc_client(request)
        mc_metadata = self.mcc.convert_all_sam_mc(metadata, namespace=self.namespace)
        mcclient.update_file_metadata(mc_metadata["metadata"], fids=[file_id])
        return ""

    @router.put(
        "/sam/{experiment}/api/files/name/{name}/content_status",
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=redefined-outer-name
    def put_name_content_status(
        self, experiment: MWordP, name: MWordP, status: str, request: fastapi.Request
    ):
        """set content status of file by name"""
        mcclient = self.client_cache.getmc_client(request)
        mcclient.update_file_metadata(
            {"core.content_status": status},
            name=name,
            namespace=self.namespace,
        )
        return ""

    @router.put(
        "/sam/{experiment}/api/files/id/{file_id}/content_status",
        response_class=fastapi.responses.PlainTextResponse,
    )
    def put_id_content_status(
        self, experiment: MWordP, file_id, status: str, request: fastapi.Request
    ):
        """set content status of file by id"""
        mcclient = self.client_cache.getmc_client(request)
        mcclient.update_file_metadata({"core.content_status": status}, file_ids=[file_id])
        return ""


@cbv(router)
class Users(ClientCacheMixin):
    """dispatcher and methods for /api/users paths"""

    @router.get(
        "/sam/{experiment}/api/users/", response_class=fastapi.responses.PlainTextResponse
    )
    # pylint: disable=redefined-builtin
    def get(self, experiment: MWordP, username=None, format="plain", status=None):
        """get user info (not implemented)"""
        raise fastapi.HTTPException(501, detail="Not Implemented")

    @router.post(
        "/sam/{experiment}/api/users/", response_class=fastapi.responses.PlainTextResponse
    )
    def post(self, experiment: MWordP, jsondata):
        """add user info (not implemented)"""
        raise fastapi.HTTPException(501, detail="Not Implemented")

    @router.get(
        "/sam/{experiment}/api/users/name/{name}",
        response_class=fastapi.responses.PlainTextResponse,
    )
    def get_by_name(self, experiment: MWordP, name):
        """get user info by name (not implemented)"""
        raise fastapi.HTTPException(501, detail="Not Implemented")

    @router.get(
        "/sam/{experiment}/api/users/id/{uid}", response_class=fastapi.responses.PlainTextResponse
    )
    def get_by_id(self, experiement, uid):
        """get user info by id (not implemented)"""
        raise fastapi.HTTPException(501, detail="Not Implemented")

    @router.put(
        "/sam/{experiment}/api/users/name/{name}",
        response_class=fastapi.responses.PlainTextResponse,
    )
    def put_by_name(self, experiment: MWordP, name: MWordP, jsondata):
        """set user info by name (not implemented)"""
        raise fastapi.HTTPException(501, detail="Not Implemented")

    @router.put(
        "/sam/{experiment}/api/users/id/{uid}", response_class=fastapi.responses.PlainTextResponse
    )
    def put_by_id(self, experiment: MWordP, uid, jsondata):
        """set user info by id (not implemented)"""
        raise fastapi.HTTPException(501, detail="Not Implemented")


@cbv(router)
class Values(ClientCacheMixin):
    """dispatcher and methods for /api/values paths"""

    @router.get(
        "/sam/{experiment}/api/values/parameters",
        response_class=fastapi.responses.PlainTextResponse,
    )
    def get_parameters(self, experiment: MWordP, request: fastapi.Request):
        """get list of metadata parameters"""
        mcclient = self.client_cache.getmc_client(request)
        keylist = list(mcclient.report_metadata_keys())
        return "\n".join(keylist)

    @router.post(
        "/sam/{experiment}/api/values/parameters",
        response_class=fastapi.responses.PlainTextResponse,
    )
    def post_parameters(
        self, experimient, name: MWordQ, category, data_type, request: fastapi.Request
    ):
        """add to list of metadata parameters (ignored, just add metadata with it)"""
        # don't need to pre-post parameters in MetaCat, so
        return ""

    @router.get(
        "/sam/{experiment}/api/values/applications",
        response_class=fastapi.responses.PlainTextResponse,
    )
    def get_applications(self, experiment: MWordP, request: fastapi.Request):
        """get list of applications"""
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
        response_class=fastapi.responses.PlainTextResponse,
    )
    def post_applications(
        self, experiment: MWordP, family, name: MWordQ, version, request: fastapi.Request
    ):
        """extend list of applications (ignored -- just add metadata)"""
        # don't need to pre-post applications in MetaCat, so
        # just say its "ok"...
        return ""


@cbv(router)
class Projects(ClientCacheMixin):
    """dispatcher and methods for /api/project paths"""

    last_process_file = {}
    last_project_finished = {}

    def __init__(self, request: fastapi.Request):
        """initialize"""
        ClientCacheMixin.__init__(self)
        self.last_process_file = Projects.last_process_file
        self.project_finished = Projects.last_project_finished

    @router.post(
        "/sam/{experiment}/api/project/id/{project_id}/establishProcess",
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=invalid-name
    def establishProcess(
        self,
        request: fastapi.Request,
        experiment: MWordP,
        project_id,
        appname: Annotated[str, fastapi.Form()],
        appversion: Annotated[str, fastapi.Form()],
        node: Annotated[str, fastapi.Form()],
        deliverylocation: Annotated[str, fastapi.Form()] = None,
        username: Annotated[str, fastapi.Form()] = None,
        subject: Annotated[str, fastapi.Form()] = None,
        appfamily: Annotated[str, fastapi.Form()] = None,
        description: Annotated[str, fastapi.Form()] = None,
        filelimit: Annotated[str, fastapi.Form()] = None,
        schemas: Annotated[str, fastapi.Form()] = None,
    ):
        """establish a SAM project consumer (DataDispatcher worker)"""
        ddclient = self.client_cache.getdd_client(request)
        logger.info("establishProcess...")
        return ddclient.new_worker_id()

    @router.post(
        "/sam/{experiment}/api/project/id/{project_id}/process/{process_id}/getNextFile",
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=invalid-name
    def getNextFile(
        self,
        experiment: MWordP,
        project_id,
        process_id,
        request: fastapi.Request,
        response: fastapi.Response,
    ):
        """get a file from a project"""
        ddclient = self.client_cache.getdd_client(request)
        res = ddclient.next_file(project_id=project_id, worker_id=process_id)
        # just return the url from the first replica
        logger.info(f"next_file gives: {res=}")
        if res:
            # pylint: disable=unused-variable
            rname, rdict = list(res["replicas"].items())[0]
            name = res["name"]
            # namespace = res["namespace"]
            self.last_process_file[process_id] = name
            logger.info(f"getNextFile: set last_process_file {name}")
            return rdict["url"]
        self.project_finished[project_id] = True
        return fastapi.responses.PlainTextResponse(status_code=204, content="")

    @router.post(
        "/sam/{experiment}/api/project/id/{project_id}/process/{process_id}/updateFileStatus",
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=invalid-name
    def updateFileStatus(
        self,
        request: fastapi.Request,
        experiment: MWordP,
        process_id,
        project_id,
        status="consumed",
        filename=None,
    ):
        """update file status in a project"""
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
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=invalid-name
    def releaseFile(self, process_id, status, project_id, filename, request: fastapi.Request):
        """release / declare finished with a file in a project"""
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
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=invalid-name
    def endProcess(self, experiment: MWordP, project_id, process_id, request: fastapi.Request):
        """end a consumer / worker in a project"""
        # don't need to do this...
        return ""

    @router.post(
        "/sam/{experiment}/api/project/id/{project_id}/endProject",
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=invalid-name
    def endProject(self, experiment: MWordP, project_id, request: fastapi.Request):
        """if we haven't seen a getNextFile return nothing, cancel it"""
        if project_id not in self.project_finished:
            ddclient = self.client_cache.getdd_client(request)
            ddclient.cancel_project(project_id)
        return ""

    # same function for project or process status, which is a put
    # we ignore..
    @router.put(
        "/sam/{experiment}/api/project/id/{project_id}/process/{process_id}/status",
        response_class=fastapi.responses.PlainTextResponse,
    )
    def ppstatus(
        self,
        request: fastapi.Request,
        experiment: MWordP,
        process_id=None,
        project_id=None,
        status: Annotated[str, fastapi.Form] = None,
    ):
        """set project status (ignored)"""

    @router.put(
        "/sam/{experiment}/api/project/id/{project_id}/status",
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=redefined-outer-name
    def pstatus(
        self,
        experiment: MWordP,
        process_id,
        status: Annotated[str, fastapi.Form()],
        request: fastapi.Request,
    ):
        """set project status (ignored)"""

    @router.get(
        "/sam/{experiment}/api/project/id/{project_id}/status",
        response_class=fastapi.responses.PlainTextResponse,
    )
    def get(self, experiment: MWordP, project_id, request: fastapi.Request):
        """get project status"""
        ddclient = self.client_cache.getdd_client(request)
        return json.dumps(ddclient.get_project(project_id))

    @router.get(
        "/sam/{experiment}/api/project/id/{project_id}/dumpProject",
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=invalid-name
    def dumpProject(self, experiment: MWordP, project_id, request: fastapi.Request):
        """dump project status"""
        ddclient = self.client_cache.getdd_client(request)
        return json.dumps(ddclient.get_project(project_id))

    @router.get(
        "/sam/{experiment}/api/projects/name/{name}/summary",
        response_class=fastapi.responses.PlainTextResponse,
    )
    def summary(self, experiment: MWordP, name: MWordP, request: fastapi.Request):
        """get project summary"""
        ddclient = self.client_cache.getdd_client(request)
        # pylint: disable = fixme
        #  xxx mimic sam Project summary?
        return json.dumps(ddclient.list_projects(attributes={"name": name})[0])

    @router.get(
        "/sam/{experiment}/api/project/name/{name}/recovery_dimensions",
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=invalid-name
    def recovery_dimensions(
        self, request: fastapi.Request, experiment: MWordP, name: MWordP, useFile=0, useProcess=0
    ):
        """get project recovery query"""
        # wimpy non process version
        return "project name minus project_status like 'com%'"


@cbv(router)
class Api(ClientCacheMixin):
    """dispatcher and methods for /api/ paths"""

    @router.get("/sam/{experiment}/api", response_class=fastapi.responses.PlainTextResponse)
    def index(self, request: fastapi.Request):
        """announce version etc."""
        logger.info("test message")
        return f'{{"app":"samwebish", "version": {samwebish_version} }}'

    @router.get(
        "/sam/{experiment}/api/createDefinition",
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=redefined-outer-name,invalid-name
    def createDefinition(
        self, request: fastapi.Request, experiment: MWordP, name: MWordQ, dims, user: MWordQ = ""
    ):
        """create / define a definition"""
        return Definitions.create(self, experiment, name, dims, user, request)

    @router.get(
        "/sam/{experiment}/api/deleteDefinition",
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=invalid-name
    def deleteDefinition(self, experiment: MWordP, name: MWordQ, request: fastapi.Request):
        """delete a definition"""
        return Definitions.delete(self, experiment, name, request)

    @router.get(
        "/sam/{experiment}/api/describeDefinition",
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=redefined-outer-name,invalid-name
    def describeDefinition(self, experiment: MWordP, name: MWordQ, request: fastapi.Request):
        """describe a definition"""
        return Definitions.get(self, experiment, name, request)

    @router.get(
        "/sam/{experiment}/api/translateConstraints",
        response_class=fastapi.responses.PlainTextResponse,
    )
    # pylint: disable=redefined-outer-name,redefined-builtin,invalid-name
    def translateConstraints(
        self, request: fastapi.Request, experiment: MWordP, dims, format="plain"
    ):
        """list files returned by a query"""
        return Files.list(experiment, dims, format, request)

    @router.get(
        "/sam/{experiment}/api/locateFile", response_class=fastapi.responses.PlainTextResponse
    )
    # pylint: disable=invalid-name
    def locateFile(self, experiment: MWordP, file, request: fastapi.Request):
        """get a file's list of locations"""
        return Files.get_name_locations(self, experiment, file, request)

    @router.get(
        "/sam/{experiment}/api/getMetadata", response_class=fastapi.responses.PlainTextResponse
    )
    # pylint: disable=invalid-name
    def getMetadata(self, experiment: MWordP, name: MWordQ, request: fastapi.Request):
        """get a file's metadata"""
        return Files.get_name_metadata(self, experiment, name, request)

    # pylint: disable=invalid-name
    @router.get(
        "/sam/{experiment}/api/dumpStation", response_class=fastapi.responses.PlainTextResponse
    )
    def dumpStation(self, request: fastapi.Request, experiment: MWordP, station, dump="all"):
        """show station information"""
        ddclient = self.client_cache.getdd_client(request)
        rlst = list(ddclient.list_projects())
        logger.info(f"dumpStation: got {rlst=}")
        res = f"samwebish version {samwebish_version}\n{len(rlst)} active projects:\n"
        res += "\n".join(
            [
                # pylint: disable=line-too-long
                f"project {x['attributes'].get('name','')} id {x['project_id']} owner: {x['owner']} state: {x['state']} files: {len(x['file_handles'])} "
                for x in rlst
            ]
        )
        return res

    @router.post(
        "/sam/{experiment}/api/startProject", response_class=fastapi.responses.PlainTextResponse
    )
    # pylint: disable=invalid-name,too-many-locals
    def startProject(
        self,
        request: fastapi.Request,
        experiment: str,
        name: Annotated[str, fastapi.Form()],
        station: Annotated[str, fastapi.Form()],
        username: Annotated[str, fastapi.Form()] = None,
        subject: Annotated[str, fastapi.Form()] = None,
        defname: Annotated[str, fastapi.Form()] = None,
        def_id: Annotated[str, fastapi.Form()] = None,
        snapshot_id: Annotated[str, fastapi.Form()] = None,
        group: Annotated[str, fastapi.Form()] = None,
    ):
        """start a file delivery project"""
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
            raise fastapi.HTTPException(
                400, detail="One of defname, def_id, snapshot_id requiered"
            )
        try:
            files = list(mcclient.query(q))
        except BadRequestError:
            # pylint: disable=raise-missing-from
            raise fastapi.HTTPException(404, f"Defname {defname} not found")
        sid = f"{self.namespace}:snapshot_for_project_{name}"
        logger.info(f"startProject: {q=} {sid=} {files=}")  # drop for production
        mcclient.create_dataset(sid)
        mcclient.add_files(sid, files)
        # pylint: disable=line-too-long
        p = ddclient.create_project(files, project_attributes={"name": name}, query=q)
        return f"{self.base}/sam/{experiment}/api/project/id/{p['project_id']}"

    @router.get(
        "/sam/{experiment}/api/findProject", response_class=fastapi.responses.PlainTextResponse
    )
    # pylint: disable=invalid-name
    def findProject(self, experiment: MWordP, name: MWordQ, request: fastapi.Request):
        """find a file delivery project by name"""
        ddclient = self.client_cache.getdd_client(request)
        pl = list(ddclient.list_projects(attributes={"name": name}))
        if not pl:
            raise fastapi.HTTPException(404, "Project not found")
        p = pl[0]
        return f"{self.base}/sam/{experiment}/api/project/id/{p['project_id']}"


app.include_router(router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
