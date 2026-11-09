#!/usr/bin/env python3
"""Bounded public API discovery for Winnow. Source-pure, zero credentials.

One GET per published public endpoint. No login, scraping or CAPTCHA handling,
no Instagram page/media fetch, no cookie handling, no retries. Redact all source
data and media URLs from stdout. Public Github Actions standard CPU only.
"""
from __future__ import annotations
import json
import time
from urllib.parse import urlencode, urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
import socket

LIMIT = 200_000
TIMEOUT = 8
QUERY = "site:instagram.com/p/ NASA"
INSTAGRAM_POST = "https://www.instagram.com/p/DaEDJ4KGJp3/"
TESTS = [
    ("mwmbl", "search", "https://api.mwmbl.org/api/v2/search/", {"q": QUERY}),
    ("freeserp_web", "search", "https://freeserp.ai/api.php", {"index":"web","q": QUERY,"size":"5"}),
    ("purili", "search", "https://puri.li/api/search", {"q": QUERY}),
    ("anonsearch", "searxng", "https://anonsearch.win/search", {"q": QUERY,"format":"json"}),
    ("baresearch", "searxng", "https://baresearch.org/search", {"q": QUERY,"format":"json"}),
    ("etsi", "searxng", "https://etsi.me/search", {"q": QUERY,"format":"json"}),
    ("searx_be", "searxng", "https://searx.be/search", {"q": QUERY,"format":"json"}),
    ("instagram_oembed", "oembed", "https://graph.facebook.com/v26.0/instagram_oembed", {"url":INSTAGRAM_POST}),
    ("commons_reference", "commons", "https://commons.wikimedia.org/w/api.php", {
        "action":"query","format":"json","prop":"imageinfo","iiprop":"url|extmetadata",
        "titles":"File:Artemis 2 - Earth - Reid Wiseman iPhone (2).jpg"
    }),
]

class StopRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(req.full_url, code, "REDIRECT_NOT_FOLLOWED", headers, fp)

OPENER=build_opener(StopRedirect)
def probe(name,kind,url,params):
    host=urlparse(url).hostname
    assert host and url.startswith("https://") and not any(x in url for x in ("@", "#"))
    request=Request(url+"?"+urlencode(params),headers={
        "User-Agent":"Winnow-public-RDTE/0.1 (no-credential endpoint discovery)",
        "Accept":"application/json"
    })
    result={"name":name,"category":kind,"host":host,"status":None,
            "json":False,"schema":[],"hits":None,"instagram_hits":None,"error":None}
    t=time.monotonic()
    try:
        with OPENER.open(request,timeout=TIMEOUT) as response:
            result["status"]=response.status
            ctype=response.headers.get("Content-Type","").lower()
            result["content_type"]=ctype.split(";")[0]
            raw=response.read(LIMIT+1)
            if len(raw)>LIMIT:raise ValueError("RESPONSE_TOO_LARGE")
            if "json" not in ctype:raise ValueError("NOT_JSON_CONTENT_TYPE")
        parsed=json.loads(raw)
        if not isinstance(parsed,dict):raise ValueError("JSON_NOT_OBJECT")
        result["json"]=True
        result["schema"]=sorted(parsed)[:12]
        array=None
        for key in ("results","data","items","hits"):
            if isinstance(parsed.get(key),list):
                array=parsed[key];break
        if isinstance(array,list):
            result["hits"]=len(array)
            result["instagram_hits"]=sum(
              1 for v in array if isinstance(v,dict) and
              ("instagram.com/p/" in str(v.get("url","")) or
               "instagram.com/p/" in str(v.get("link","")))
            )
        if kind=="oembed":
            result["embed_html_present"]=isinstance(parsed.get("html"),str) and bool(parsed["html"])
            result["media_urls_returned"]=any(k in parsed for k in ("media_url","thumbnail_url","carousel_children"))
        if kind=="commons":
            pages=parsed.get("query",{}).get("pages",{}) if isinstance(parsed.get("query"),dict) else {}
            result["imageinfo_present"]=any(isinstance(page,dict) and bool(page.get("imageinfo")) for page in pages.values())
        result["error"]=None
    except HTTPError as e:
        result["status"]=e.code
        result["error"]="HTTP_STATUS"
    except (TimeoutError,socket.timeout):
        result["error"]="TIMEOUT"
    except (URLError,OSError):
        result["error"]="NETWORK_FAILURE"
    except (ValueError,json.JSONDecodeError) as e:
        result["error"]=str(e).split(":")[0][:48]
    result["elapsed_ms"]=round((time.monotonic()-t)*1000)
    return result

def main():
    reports=[]
    for spec in TESTS:
        rep=probe(*spec)
        reports.append(rep)
        print("PUBLIC_ENDPOINT_PROBE="+json.dumps(rep,sort_keys=True),flush=True)
    print("PUBLIC_ENDPOINT_DISCOVERY_SUMMARY="+json.dumps({
        "tested":len(reports),
        "json200":[r["name"] for r in reports if r["status"]==200 and r["json"]],
        "unavailable":[r["name"] for r in reports if r["status"]!=200 or not r["json"]],
        "media_acquisition":"NOT_RUN",
        "instagram_post_page_access":"NOT_RUN",
        "insta_rights":"NOT_GRANTED_BY_PUBLIC_ENDPOINT",
        "credentials":"NONE"
    },sort_keys=True))
if __name__=="__main__": main()
