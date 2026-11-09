#!/usr/bin/env python3
"""One additional public API search-yield check and independently licensed image fixture.

No Instagram page or CDN request. All source requests public and bounded.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from urllib.parse import urlencode, urlparse
from urllib.request import Request
from urllib.error import HTTPError,URLError
import public_endpoint_discovery as d

QUERY="NASA Instagram"
PROBES=[
 ("mwmbl_broad","search","https://api.mwmbl.org/api/v2/search/",{"q":QUERY}),
 ("freeserp_broad","search","https://freeserp.ai/api.php",{"index":"web","q":QUERY,"size":"8"}),
 ("purili_broad","search","https://puri.li/api/search",{"q":QUERY}),
 ("instagram_oembed_carousel","oembed","https://graph.facebook.com/v26.0/instagram_oembed",
   {"url":"https://www.instagram.com/p/DW6mSqqgcpn/"}),
 ("nasa_image_library","nasa","https://images-api.nasa.gov/search",
   {"q":"Artemis II Earth","media_type":"image","page_size":2}),
]

def commons_bytes():
    result={"name":"commons_download","status":None,"verified":False,"license":None,"bytes":0,"sha256":None,"error":None}
    try:
        url="https://commons.wikimedia.org/w/api.php?"+urlencode({
            "action":"query","format":"json","prop":"imageinfo",
            "iiprop":"url|extmetadata",
            "titles":"File:Artemis 2 - Earth - Reid Wiseman iPhone (2).jpg"})
        req=Request(url,headers={"User-Agent":"Winnow-public-RDTE/0.1 public-media-provenance","Accept":"application/json"})
        with d.OPENER.open(req,timeout=d.TIMEOUT) as response:
            raw=response.read(d.LIMIT+1)
            if len(raw)>d.LIMIT:raise ValueError("SOURCE_METADATA_TOO_LARGE")
        obj=json.loads(raw)
        pages=obj.get("query",{}).get("pages",{})
        info=[p["imageinfo"][0] for p in pages.values()
              if isinstance(p,dict) and p.get("imageinfo")]
        if len(info)!=1:raise ValueError("FILE_METADATA_NOT_FOUND")
        item=info[0]
        license_name=item.get("extmetadata",{}).get("LicenseShortName",{}).get("value","")
        result["license"]=license_name[:64]
        if "public domain" not in license_name.lower():
            raise ValueError("LICENSE_NOT_AUTO_PUBLIC_DOMAIN")
        image_url=item["url"]
        u=urlparse(image_url)
        if u.scheme!="https" or u.hostname!="upload.wikimedia.org" or u.username is not None:
            raise ValueError("MEDIA_ORIGIN_NOT_ALLOWED")
        media=Request(image_url,headers={"User-Agent":"Winnow-public-RDTE/0.1 public-media-provenance"})
        with d.OPENER.open(media,timeout=d.TIMEOUT) as response:
            result["status"]=response.status
            data=response.read(1_000_001)
            if len(data)>1_000_000:raise ValueError("MEDIA_TOO_LARGE")
            if "image/jpeg" not in response.headers.get("Content-Type","").lower():
                raise ValueError("MIME_NOT_JPEG")
        if not data.startswith(b"\xff\xd8\xff") or not data.endswith(b"\xff\xd9"):
            raise ValueError("IMAGE_STRUCTURE_INVALID")
        result["sha256"]=hashlib.sha256(data).hexdigest()
        result["bytes"]=len(data)
        result["verified"]=True
    except (HTTPError,URLError,OSError,ValueError,KeyError,TypeError) as e:
        result["error"]=type(e).__name__ if not isinstance(e,ValueError) else str(e)[:70]
    return result

def main():
    for item in PROBES:
        r=d.probe(*item)
        print("PUBLIC_ENDPOINT_FOLLOWUP="+json.dumps(r,sort_keys=True),flush=True)
    r=commons_bytes()
    print("PUBLIC_COMMONS_REAL_BYTES="+json.dumps(r,sort_keys=True),flush=True)
    print("INSTAGRAM_MEDIA_BYTES=NOT_RUN",flush=True)
if __name__=="__main__":main()
