from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import json
from concurrent.futures import ThreadPoolExecutor
import mimetypes
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree as ET

import requests
import urllib3
from flask import Flask, Response, jsonify, render_template, request
from werkzeug.utils import secure_filename

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import whois as whois_lib
except ImportError:
    whois_lib = None

try:
    from ipwhois import IPWhois
except ImportError:
    IPWhois = None


def load_env(path: Path) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip("'\"").strip())


load_env(Path(__file__).with_name(".env"))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

VT_API_KEY = os.environ.get("VT_API_KEY", "")
URLSCAN_KEY = os.environ.get("URLSCAN_KEY", "")
GROQ_KEY = os.environ.get("GROQ_KEY", "")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.1-8b-instant"

CACHE_TTL = 300
MAX_HOPS = 10
LOOKUP_CACHE: dict[str, dict] = {}
RESULT_CACHE: dict[str, tuple[float, dict]] = {}
REDIRECTS = {301, 302, 303, 307, 308}

ALLOWED_EXTENSIONS = set(
    "jpg jpeg png gif tiff tif bmp webp pdf doc docx xls xlsx ppt pptx "
    "mp3 mp4 mov avi wav heic heif raw cr2 nef arw".split()
)
TRUSTED_DOMAINS = set(
    "google.com googleapis.com gstatic.com youtube.com facebook.com instagram.com "
    "twitter.com x.com github.com github.io githubusercontent.com vercel.com "
    "vercel.app netlify.com netlify.app cloudflare.com workers.dev aws.amazon.com "
    "amazonaws.com amazon.com microsoft.com azure.com azurewebsites.net apple.com "
    "icloud.com fastly.net fastly.com akamaiedge.net akamai.com shopify.com "
    "myshopify.com stripe.com twilio.com sendgrid.com reddit.com wikipedia.org "
    "medium.com substack.com ghost.io wordpress.com nytimes.com bbc.com reuters.com "
    "theguardian.com".split()
)
SHORTENERS = set("bit.ly tinyurl.com t.co ow.ly buff.ly goo.gl is.gd rebrand.ly cutt.ly shorturl.at tiny.cc lnkd.in dlvr.it ift.tt adf.ly bl.ink rb.gy clck.ru u.to qr.ae x.co v.gd s.id ouo.io".split())
SUSPICIOUS_TLDS = set(".tk .ml .ga .cf .gq .xyz .top .click .link .online .site .store .icu .pw .cc .su .ws".split())
SUSPICIOUS_ASNS = set("AS197695 AS9123 AS8075 AS16276 AS20473 AS14061 AS46606 AS53667 AS209103 AS206728 AS48666 AS35913".split())
SUSPICIOUS_REGISTRARS = ("namecheap", "reg.ru", "beget", "timeweb", "nic.ru", "regway", "pananames", "bizcn", "west.cn")
TRUSTED_CAS = ("let's encrypt", "digicert", "sectigo", "comodo", "globalsign", "entrust", "geotrust", "amazon", "google trust services", "zerossl", "cloudflare", "godaddy")

PAGE_PATTERNS = {
    "trackers": [("google-analytics", r"google-analytics\.com"), ("googletagmanager", r"googletagmanager\.com"), ("facebook pixel", r"facebook\.net/en_US/fbevents|connect\.facebook\.net"), ("hotjar", r"hotjar\.com"), ("mouseflow", r"mouseflow\.com"), ("fullstory", r"fullstory\.com"), ("segment", r"segment\.com"), ("mixpanel", r"mixpanel\.com"), ("amplitude", r"amplitude\.com"), ("clarity", r"clarity\.ms"), ("matomo", r"matomo\."), ("plausible", r"plausible\.io"), ("doubleclick", r"doubleclick\.net"), ("googlesyndication", r"googlesyndication\.com"), ("ad network", r"adnxs\.com|rubiconproject\.com")],
    "fingerprints": [("fingerprintjs", r"fingerprintjs|fp\.js"), ("clientjs", r"clientjs"), ("canvas fingerprint", r"canvas.*fingerprint|CanvasRenderingContext2D"), ("webgl fingerprint", r"webgl.*fingerprint"), ("browser fingerprinting", r"navigator\.plugins|screen\.colorDepth|AudioContext")],
    "miners": [("coinhive", r"coinhive"), ("cryptonight", r"cryptonight"), ("minero", r"minero\.cc"), ("web miner", r"webmr\.js|coin-hive|jsecoin|cryptoloot|deepminer|ppoi\.org")],
}

SENSITIVE_FIELDS = {
    "gps": "GPSLatitude GPSLongitude GPSAltitude GPSPosition GPSLatitudeRef GPSLongitudeRef GPSMapDatum".split(),
    "device": "Make Model LensModel LensMake Software HostComputer CameraID DeviceSerialNumber".split(),
    "author": "Author Creator Artist Copyright XPAuthor LastModifiedBy Manager Company dc:creator CreatorTool Producer".split(),
    "identity": "UserComment ImageDescription DocumentID InstanceID OriginalDocumentID".split(),
    "timestamps": "DateTimeOriginal CreateDate ModifyDate MetadataDate ContentCreateDate DateCreated".split(),
    "location_text": "City State Country CountryCode Location Sub-location Province-State".split(),
    "network": "IPTCDigest ExifIFD MakerNote".split(),
}
IGNORED_METADATA = set("SourceFile ExifToolVersion FileSize FileType FileTypeExtension MIMEType ImageWidth ImageHeight FilePermissions FileModifyDate FileAccessDate FileInodeChangeDate".split())
OOXML_NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
}


def cached(key: str, fn):
    if key not in LOOKUP_CACHE:
        LOOKUP_CACHE[key] = fn()
    return LOOKUP_CACHE[key]


def bool_value(value, default=True) -> bool:
    return default if value is None else str(value).lower() not in {"0", "false", "off", "no"}


def domain_in(hostname: str, domains: set[str]) -> bool:
    host = hostname.lower().strip(".")
    return any(host == domain or host.endswith("." + domain) for domain in domains)


def risk_level(score: int) -> str:
    return "clean" if score == 0 else "low" if score < 25 else "medium" if score < 55 else "high"


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def safe_ip(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return "unresolvable"


def get_asn(ip: str) -> dict:
    default = {"asn": "unknown", "org": "unknown", "country": "??"}
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return {"asn": "private", "org": "private", "country": "??"}
    except ValueError:
        return default

    def lookup():
        if IPWhois is None:
            return default
        try:
            data = IPWhois(ip, timeout=6).lookup_rdap(depth=1, retry_count=1)
            return {"asn": f"AS{data.get('asn', 'unknown')}", "org": (data.get("asn_description") or "unknown")[:60], "country": data.get("asn_country_code") or "??"}
        except Exception:
            return default

    return cached(f"asn:{ip}", lookup)


def get_tls_info(hostname: str) -> dict:
    def lookup():
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=6) as raw, ctx.wrap_socket(raw, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
            issuer_fields = dict(item for group in cert.get("issuer", []) for item in group)
            before = ssl.cert_time_to_seconds(cert.get("notBefore"))
            after = ssl.cert_time_to_seconds(cert.get("notAfter"))
            now = time.time()
            return {
                "issuer": issuer_fields.get("organizationName") or issuer_fields.get("commonName") or "unknown",
                "age_days": int((now - before) / 86400),
                "expires_in_days": int((after - now) / 86400),
                "valid": True,
            }
        except ssl.SSLCertVerificationError:
            return {"issuer": "invalid/self-signed", "age_days": -1, "expires_in_days": -1, "valid": False}
        except Exception:
            return {"issuer": "unknown", "age_days": -1, "expires_in_days": -1, "valid": False}

    return cached(f"tls:{hostname}", lookup)


def get_domain_age(hostname: str) -> dict:
    default = {"age_days": -1, "registrar": "unknown"}
    parts = hostname.rstrip(".").split(".")
    if len(parts) < 2 or whois_lib is None:
        return default
    apex = ".".join(parts[-2:])

    def lookup():
        try:
            data = whois_lib.whois(apex)
            created = data.creation_date[0] if isinstance(data.creation_date, list) else data.creation_date
            if isinstance(created, dt.date) and not isinstance(created, dt.datetime):
                created = dt.datetime.combine(created, dt.time.min)
            if not isinstance(created, dt.datetime):
                return default
            return {"age_days": (dt.datetime.utcnow() - created.replace(tzinfo=None)).days, "registrar": (data.registrar or "unknown").lower()}
        except Exception:
            return default

    return cached(f"domain:{apex}", lookup)


def score_hop(hop: dict) -> dict:
    flags, score = [], 0
    host = (hop.get("hostname") or "").lower()
    headers = hop.get("headers") or {}
    trusted = domain_in(host, TRUSTED_DOMAINS)

    def add(label: str, points=0):
        nonlocal score
        flags.append(label)
        score += points

    if domain_in(host, SHORTENERS):
        add("url shortener", 15)
    if any(ord(ch) > 127 for ch in host):
        add("non-ASCII characters in domain", 40)
    if any(part.startswith("xn--") for part in host.split(".")):
        add("punycode IDN domain (possible spoofing)", 20)
    if not trusted and any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        add(f"high-abuse TLD ({next(tld for tld in SUSPICIOUS_TLDS if host.endswith(tld))})", 15)
    try:
        ipaddress.ip_address(host)
        add("URL points directly to IP address", 25)
    except ValueError:
        pass
    if not trusted and len(host.rstrip(".").split(".")) > 4:
        add(f"deep subdomain ({len(host.rstrip('.').split('.'))} labels)", 10)

    tls = hop.get("tls") or {}
    if hop.get("scheme") == "https":
        if not tls.get("valid"):
            add("invalid / self-signed certificate", 30)
        elif not trusted:
            issuer = (tls.get("issuer") or "").lower()
            if 0 <= tls.get("age_days", 999) < 30 and not any(ca in issuer for ca in TRUSTED_CAS):
                add(f"cert only {tls['age_days']}d old (unknown CA)", 25)
            if 0 <= tls.get("expires_in_days", 999) < 7:
                add(f"cert expires in {tls['expires_in_days']}d", 10)
    else:
        add("plain HTTP, no encryption", 20)

    if not trusted:
        age = (hop.get("domain_age") or {}).get("age_days", -1)
        registrar = (hop.get("domain_age") or {}).get("registrar", "")
        if 0 <= age < 30:
            add(f"domain only {age}d old", 40)
        elif 0 <= age < 90:
            add(f"domain {age}d old", 20)
        if any(name in registrar for name in SUSPICIOUS_REGISTRARS):
            add(f"registrar: {registrar[:30]}", 20)
        if (hop.get("asn") or {}).get("asn") in SUSPICIOUS_ASNS:
            add(f"suspicious hosting ASN ({hop['asn']['asn']})", 25)
        if headers.get("server") and not any(name in headers["server"].lower() for name in ("nginx", "apache", "cloudflare", "iis", "litespeed", "openresty", "caddy", "gunicorn", "vercel", "netlify", "fastly", "akamai", "envoy", "traefik")):
            add(f"unusual server: {headers['server'][:30]}", 10)
        missing = [name for name, key in (("CSP", "content-security-policy"), ("HSTS", "strict-transport-security")) if not headers.get(key)]
        if not headers.get("x-frame-options") and not headers.get("content-security-policy"):
            missing.append("X-Frame-Options")
        if missing:
            add(f"missing headers: {', '.join(missing)}", 5)
        if headers.get("x-powered-by"):
            add(f"X-Powered-By: {headers['x-powered-by'][:30]}")
        cookie = headers.get("set-cookie", "").lower()
        issues = [label for token, label in (("secure", "no Secure flag"), ("httponly", "no HttpOnly flag"), ("samesite", "no SameSite flag")) if cookie and token not in cookie]
        if issues:
            add(f"cookie: {', '.join(issues)}", 5)

    content_type = headers.get("content-type", "")
    if hop.get("status_code") == 200 and content_type and not trusted:
        if "application/octet-stream" in content_type or "application/x-msdownload" in content_type:
            add("response is a file download", 30)
        elif "application/zip" in content_type or "application/x-zip" in content_type:
            add("response is a ZIP archive", 25)

    score = min(score, 100)
    hop.update({"flags": flags, "risk_score": score, "risk_level": risk_level(score), "trusted": trusted})
    return hop


def analyze_page_content(html: str) -> dict:
    found = {group: sorted({name for name, pattern in patterns if re.search(pattern, html, re.I)}) for group, patterns in PAGE_PATTERNS.items()}
    scripts = list(dict.fromkeys(re.findall(r"""src=["']https?://([^/"']+)""", html, re.I)))[:20]
    return {**found, "script_domains": scripts, "has_threats": bool(found["fingerprints"] or found["miners"])}


def run_exiftool(filepath: str) -> dict:
    exe = shutil.which("exiftool")
    if not exe:
        return {"error": "ExifTool is not installed"}
    try:
        result = subprocess.run([exe, "-json", "-a", "-u", "-g1", filepath], capture_output=True, text=True, timeout=15)
        if result.returncode:
            return {"error": result.stderr.strip() or "ExifTool failed"}
        data = json.loads(result.stdout)
        return data[0] if data else {}
    except subprocess.TimeoutExpired:
        return {"error": "ExifTool timed out"}
    except Exception as exc:
        return {"error": str(exc)}


def _ooxml_text(root: ET.Element, tag: str) -> str | None:
    el = root.find(tag, OOXML_NS)
    if el is not None and el.text:
        return el.text.strip()
    return None


def extract_ooxml_metadata(filepath: str) -> dict:
    flat = {}
    try:
        with zipfile.ZipFile(filepath) as archive:
            if "docProps/core.xml" in archive.namelist():
                root = ET.fromstring(archive.read("docProps/core.xml"))
                for key, tag in (
                    ("Creator", "dc:creator"),
                    ("LastModifiedBy", "cp:lastModifiedBy"),
                    ("CreateDate", "dcterms:created"),
                    ("ModifyDate", "dcterms:modified"),
                    ("Title", "dc:title"),
                    ("Subject", "dc:subject"),
                ):
                    value = _ooxml_text(root, tag)
                    if value and key not in flat:
                        flat[key] = value
            if "docProps/app.xml" in archive.namelist():
                root = ET.fromstring(archive.read("docProps/app.xml"))
                for key, tag in (
                    ("Software", "ep:Application"),
                    ("Company", "ep:Company"),
                    ("Manager", "ep:Manager"),
                ):
                    value = _ooxml_text(root, tag)
                    if value:
                        flat[key] = value
    except Exception:
        return {}
    return flat


def extract_pdf_metadata(filepath: str) -> dict:
    flat = {}
    try:
        text = Path(filepath).read_bytes()[:500000].decode("latin-1", errors="ignore")
        for src, dst in (
            ("Author", "Author"),
            ("Creator", "Creator"),
            ("Producer", "Producer"),
            ("Title", "Title"),
            ("Subject", "Subject"),
            ("CreationDate", "CreateDate"),
            ("ModDate", "ModifyDate"),
            ("Company", "Company"),
        ):
            match = re.search(rf"/{src}\s*\(([^)]*)\)", text)
            if match and match.group(1).strip():
                flat[dst] = match.group(1).strip()
    except Exception:
        return {}
    return flat


def extract_metadata_fallback(filepath: str, filename: str) -> dict:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in {"docx", "xlsx", "pptx"}:
        flat = extract_ooxml_metadata(filepath)
    elif ext == "pdf":
        flat = extract_pdf_metadata(filepath)
    else:
        return {}
    if not flat:
        return {}
    flat["FileType"] = ext.upper()
    flat["MIMEType"] = mimetypes.guess_type(filename)[0] or "unknown"
    return flat


def flatten_metadata(raw: dict) -> dict:
    flat = {}
    for key, value in raw.items():
        if isinstance(value, dict):
            flat.update(value)
        else:
            flat[key] = value
    return flat


def basic_file_info(filepath: str, filename: str, flat: dict | None = None) -> dict:
    flat = flat or {}
    size = os.path.getsize(filepath)
    mime = flat.get("MIMEType") or mimetypes.guess_type(filename)[0] or "unknown"
    filetype = flat.get("FileType") or (filename.rsplit(".", 1)[-1].upper() if "." in filename else "unknown")
    dimensions = f"{flat.get('ImageWidth')}x{flat.get('ImageHeight')}" if flat.get("ImageWidth") else None
    return {"filename": flat.get("FileName", filename), "filetype": filetype, "mime": mime, "size": flat.get("FileSize", f"{size:,} bytes"), "dimensions": dimensions}


def metadata_from_raw(raw: dict, filepath: str, filename: str) -> dict:
    flat = flatten_metadata(raw)
    findings = {cat: {} for cat in SENSITIVE_FIELDS}
    all_fields = {}
    for field, value in flat.items():
        if field in IGNORED_METADATA:
            continue
        all_fields[field] = str(value)
        for category, fields in SENSITIVE_FIELDS.items():
            if field in fields:
                findings[category][field] = str(value)

    gps = f"{flat['GPSLatitude']}, {flat['GPSLongitude']}" if flat.get("GPSLatitude") and flat.get("GPSLongitude") else None
    checks = (
        (findings["gps"] or gps, 40, "GPS location embedded"),
        (findings["device"], 15, f"Device: {next(iter(findings['device'].values()), '')[:40]}"),
        (findings["author"], 20, "Author/identity info present"),
        (findings["location_text"], 15, "Location text embedded"),
        (findings["identity"], 10, "Document identity info present"),
    )
    score = sum(points for present, points, _ in checks if present)
    flags = [label for present, _, label in checks if present]
    return {
        "available": True,
        "file_info": basic_file_info(filepath, filename, flat),
        "findings": {k: v for k, v in findings.items() if v},
        "gps_summary": gps,
        "risk_score": min(score, 100),
        "risk_flags": flags,
        "total_fields": len(all_fields),
        "all_fields": dict(list(all_fields.items())[:60]),
    }


def extract_metadata(filepath: str, filename: str) -> dict:
    raw = run_exiftool(filepath)
    if "error" in raw:
        fallback = extract_metadata_fallback(filepath, filename)
        if fallback:
            return metadata_from_raw(fallback, filepath, filename)
        return {
            "available": True,
            "extraction_error": raw["error"],
            "file_info": basic_file_info(filepath, filename),
            "findings": {},
            "gps_summary": None,
            "risk_score": 0,
            "risk_flags": [],
            "total_fields": 0,
            "all_fields": {"Metadata scanner": raw["error"], "Fallback scan": "Basic file details only"},
        }
    return metadata_from_raw(raw, filepath, filename)


def vt_lookup(url: str) -> dict:
    if not VT_API_KEY:
        return {"available": False}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": VT_API_KEY}, timeout=10)
        if res.status_code != 200:
            return {"available": False, "error": f"HTTP {res.status_code}"}
        stats = res.json()["data"]["attributes"]["last_analysis_stats"]
        return {"available": True, **{key: stats.get(key, 0) for key in ("malicious", "suspicious", "harmless", "undetected")}}
    except Exception as exc:
        return {"available": False, "error": str(exc)}


def urlscan_with_proxy(scan_id: str, **extra) -> dict:
    return {
        "available": True,
        "uuid": scan_id,
        "report_url": f"https://urlscan.io/result/{scan_id}/",
        "screenshot_url": f"https://urlscan.io/screenshots/{scan_id}.png",
        "screenshot_proxy": f"/urlscan-screenshot/{scan_id}",
        "ready": False,
        **extra,
    }


def urlscan_screenshot_ready(scan_id: str, shot_url: str | None = None) -> bool:
    headers = {"API-Key": URLSCAN_KEY}
    shot_url = shot_url or f"https://urlscan.io/screenshots/{scan_id}.png"
    try:
        probe = requests.head(shot_url, headers=headers, timeout=10, allow_redirects=True)
        return probe.status_code == 200
    except Exception:
        return False


def urlscan_fetch_png(scan_id: str) -> tuple[bytes | None, str]:
    """Return PNG bytes and the URL that worked, or (None, '')."""
    headers = {"API-Key": URLSCAN_KEY}
    candidates: list[str] = []
    try:
        result = requests.get(
            f"https://urlscan.io/api/v1/result/{scan_id}/",
            headers=headers,
            timeout=10,
        )
        if result.status_code == 200:
            task = result.json().get("task") or {}
            for key in ("screenshotURL", "screenshotURLFullPage"):
                url = task.get(key)
                if url:
                    candidates.append(url)
    except Exception:
        pass
    candidates.append(f"https://urlscan.io/screenshots/{scan_id}.png")
    seen: set[str] = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        try:
            res = requests.get(url, headers=headers, timeout=20, allow_redirects=True)
        except Exception:
            continue
        if res.status_code != 200 or not res.content:
            continue
        content_type = (res.headers.get("Content-Type") or "").lower()
        if content_type.startswith("image/") or res.content[:8].startswith(b"\x89PNG\r\n\x1a\n"):
            return res.content, url
    return None, ""


def urlscan_apply_result(base: dict, data: dict) -> dict:
    task = data.get("task") or {}
    shot = task.get("screenshotURL") or task.get("screenshotURLFullPage")
    out = {
        **base,
        "verdicts": data.get("verdicts", {}),
        "stats": data.get("stats", {}),
        "ready": True,
    }
    if shot:
        out["screenshot_url"] = shot
    scan_id = base.get("uuid") or ""
    out["screenshot_ready"] = bool(scan_id) and urlscan_screenshot_ready(scan_id, out.get("screenshot_url"))
    return out


def urlscan_submit(url: str) -> dict:
    if not URLSCAN_KEY:
        return {"available": False}
    try:
        res = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers={"API-Key": URLSCAN_KEY, "Content-Type": "application/json"},
            json={"url": url, "visibility": "unlisted"},
            timeout=10,
        )
        if res.status_code not in (200, 201):
            return {"available": False, "error": f"Submit HTTP {res.status_code}"}
        scan_id = res.json().get("uuid")
        if not scan_id:
            return {"available": False, "error": "No scan uuid returned"}
        return urlscan_with_proxy(scan_id)
    except Exception as exc:
        return {"available": False, "error": str(exc)}


def urlscan_lookup(url: str) -> dict:
    base = urlscan_submit(url)
    if not base.get("available") or not base.get("uuid"):
        return base
    scan_id = base["uuid"]
    headers = {"API-Key": URLSCAN_KEY}
    for _ in range(5):
        time.sleep(5)
        poll = requests.get(f"https://urlscan.io/api/v1/result/{scan_id}/", headers=headers, timeout=8)
        if poll.status_code == 200:
            return urlscan_apply_result(base, poll.json())
    return base


def urlscan_result(scan_id: str) -> dict:
    base = urlscan_with_proxy(scan_id)
    if not URLSCAN_KEY:
        return {**base, "available": False, "error": "No urlscan API key"}
    try:
        res = requests.get(
            f"https://urlscan.io/api/v1/result/{scan_id}/",
            headers={"API-Key": URLSCAN_KEY},
            timeout=8,
        )
        if res.status_code == 200:
            return urlscan_apply_result(base, res.json())
        if res.status_code in (404, 410):
            return base
        return {**base, "error": f"HTTP {res.status_code}"}
    except Exception as exc:
        return {**base, "error": str(exc)}


def groq_json(prompt: str, max_tokens: int) -> dict:
    if not GROQ_KEY:
        return {"available": False}
    try:
        res = requests.post(GROQ_URL, headers={"Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json"}, json={"model": GROQ_MODEL, "messages": [{"role": "user", "content": prompt}], "max_tokens": max_tokens, "temperature": 0.2}, timeout=25)
        if res.status_code != 200:
            return {"available": False, "error": f"Groq HTTP {res.status_code}"}
        text = res.json()["choices"][0]["message"]["content"].strip()
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
        start, end = text.find("{"), text.rfind("}")
        return {"available": True, **json.loads(text[start : end + 1] if start != -1 and end != -1 else text)}
    except Exception as exc:
        return {"available": False, "error": str(exc)}


def ai_site(url: str, summary: str, html: str) -> dict:
    prompt = f"""You are a cybersecurity analyst helping journalists safely investigate websites.

URL: {url}
Redirect chain:
{summary}

Page content snippet:
{html[:3000]}

Return only JSON with "purpose", "vibe_score", "vibe_reason", "ai_content_detected", "threat_assessment", "threat_reason", "journalist_advice", and "tags"."""
    return groq_json(prompt, 600)


def ai_file(filename: str, metadata: dict) -> dict:
    prompt = f"""You are a digital forensics expert helping journalists understand metadata risks.

Filename: {filename}
Metadata findings:
{json.dumps(metadata.get("findings", {}), indent=2)}
GPS summary: {metadata.get("gps_summary", "none")}
Risk flags: {", ".join(metadata.get("risk_flags", [])) or "none"}

Return only JSON with "summary", "privacy_risks", "journalist_advice", "threat_level", and "strip_metadata"."""
    return groq_json(prompt, 500)


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise ValueError("No URL provided.")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if not urlparse(url).hostname:
        raise ValueError("Could not parse a hostname from that URL.")
    return url


def follow_chain(url: str) -> tuple[list[dict], str]:
    LOOKUP_CACHE.clear()
    session = requests.Session()
    headers = {"User-Agent": "Mozilla/5.0 Safehouse/1.0", "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5"}
    hops, seen, final_html = [], set(), ""
    current = url

    for _ in range(MAX_HOPS):
        if current in seen:
            hops.append({"url": current, "error": "redirect loop", "flags": ["redirect loop"], "risk_level": "high", "risk_score": 50})
            break
        seen.add(current)
        parsed = urlparse(current)
        host, scheme = parsed.hostname or "", parsed.scheme
        ip = safe_ip(host)
        if ip == "unresolvable":
            hops.append({"url": current, "hostname": host, "ip": ip, "error": f"DNS failed for {host!r}", "flags": ["DNS resolution failed"], "risk_level": "unknown", "risk_score": 0})
            break
        try:
            res = session.get(current, headers=headers, timeout=8, allow_redirects=False, verify=False)
        except requests.exceptions.Timeout:
            hops.append({"url": current, "hostname": host, "ip": ip, "error": "Request timed out", "flags": ["timeout"], "risk_level": "unknown", "risk_score": 0})
            break
        except Exception as exc:
            hops.append({"url": current, "hostname": host, "ip": ip, "error": str(exc), "flags": [], "risk_level": "unknown", "risk_score": 0})
            break

        if res.status_code not in REDIRECTS and "html" in res.headers.get("content-type", ""):
            final_html = res.text[:80000]
        hops.append(score_hop({"url": current, "hostname": host, "scheme": scheme, "ip": ip, "status_code": res.status_code, "headers": {k.lower(): v for k, v in res.headers.items()}, "tls": get_tls_info(host) if scheme == "https" else {"valid": False, "issuer": "http only", "age_days": -1, "expires_in_days": -1}, "domain_age": get_domain_age(host), "asn": get_asn(ip)}))
        if res.status_code not in REDIRECTS:
            break
        location = res.headers.get("Location", "").strip()
        if not location:
            break
        current = urljoin(current, location)

    return hops, final_html


def chain_summary(chain: list[dict]) -> str:
    return "\n".join(
        f"  {hop.get('url', '')} -> {hop.get('risk_level', '?')} (score {hop.get('risk_score', 0)})"
        for hop in chain
    )


def parse_analyze_url() -> str:
    try:
        return normalize_url((request.get_json(silent=True) or {}).get("url") or "")
    except ValueError as exc:
        raise ValueError(str(exc)) from exc


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze/chain", methods=["POST"])
def analyze_chain():
    try:
        url = parse_analyze_url()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    now = time.time()
    cached_result = RESULT_CACHE.get(url)
    if cached_result and now - cached_result[0] < CACHE_TTL:
        cached = cached_result[1]
        return jsonify(
            {
                "chain": cached.get("chain", []),
                "overall_risk": cached.get("overall_risk", 0),
                "page_analysis": cached.get("page_analysis", {}),
                "elapsed": cached.get("elapsed", 0),
                "html_excerpt": "",
                "cached": True,
            }
        )

    try:
        start = time.time()
        chain, html = follow_chain(url)
        elapsed = round(time.time() - start, 2)
    except Exception as exc:
        return jsonify({"error": f"Analysis failed: {exc}"}), 500

    return jsonify(
        {
            "chain": chain,
            "overall_risk": max((hop.get("risk_score", 0) for hop in chain), default=0),
            "page_analysis": analyze_page_content(html) if html else {},
            "html_excerpt": html[:3000] if html else "",
            "elapsed": elapsed,
            "cached": False,
        }
    )


@app.route("/analyze/intel", methods=["POST"])
def analyze_intel():
    try:
        url = parse_analyze_url()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    if not bool_value((request.get_json(silent=True) or {}).get("external_intel"), True):
        return jsonify({"virustotal": {"available": False}, "urlscan": {"available": False}})

    with ThreadPoolExecutor(max_workers=2) as pool:
        vt_future = pool.submit(vt_lookup, url)
        us_future = pool.submit(urlscan_lookup, url)
        vt = vt_future.result()
        urlscan = us_future.result()
    return jsonify({"virustotal": vt, "urlscan": urlscan})


@app.route("/analyze/ai", methods=["POST"])
def analyze_ai():
    try:
        url = parse_analyze_url()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    body = request.get_json(silent=True) or {}
    if not bool_value(body.get("external_intel"), True):
        return jsonify({"ai_analysis": {"available": False}})

    chain = body.get("chain") or []
    html_excerpt = body.get("html_excerpt") or ""
    summary = chain_summary(chain)
    return jsonify({"ai_analysis": ai_site(url, summary, html_excerpt)})


@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        url = parse_analyze_url()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    now = time.time()
    cached_result = RESULT_CACHE.get(url)
    if cached_result and now - cached_result[0] < CACHE_TTL:
        return jsonify({**cached_result[1], "cached": True, "cached_age": int(now - cached_result[0])})

    try:
        start = time.time()
        chain, html = follow_chain(url)
        elapsed = round(time.time() - start, 2)
    except Exception as exc:
        return jsonify({"error": f"Analysis failed: {exc}"}), 500

    external = bool_value((request.get_json(silent=True) or {}).get("external_intel"), True)
    summary = chain_summary(chain)
    html_excerpt = html[:3000] if html else ""
    result = {
        "chain": chain,
        "overall_risk": max((hop.get("risk_score", 0) for hop in chain), default=0),
        "page_analysis": analyze_page_content(html) if html else {},
        "virustotal": vt_lookup(url) if external else {"available": False},
        "urlscan": urlscan_lookup(url) if external else {"available": False},
        "ai_analysis": ai_site(url, summary, html_excerpt) if external else {"available": False},
        "elapsed": elapsed,
        "cached": False,
    }
    RESULT_CACHE[url] = (now, result)
    return jsonify(result)


@app.route("/urlscan-result/<scan_id>")
def urlscan_result_route(scan_id):
    if not re.fullmatch(r"[0-9a-fA-F-]{32,40}", scan_id):
        return jsonify({"error": "Invalid urlscan id"}), 400
    return jsonify(urlscan_result(scan_id))


@app.route("/urlscan-screenshot/<scan_id>")
def urlscan_screenshot_route(scan_id):
    if not re.fullmatch(r"[0-9a-fA-F-]{32,40}", scan_id):
        return jsonify({"error": "Invalid urlscan id"}), 400
    if not URLSCAN_KEY:
        return jsonify({"error": "No urlscan API key configured"}), 503
    try:
        png_bytes, _source_url = urlscan_fetch_png(scan_id)
        if not png_bytes:
            return "", 404
        return Response(png_bytes, mimetype="image/png")
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502


@app.route("/analyze-file", methods=["POST"])
def analyze_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    upload = request.files["file"]
    filename = secure_filename(upload.filename or "")
    if not filename:
        return jsonify({"error": "No file selected"}), 400
    if not allowed_file(filename):
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "unknown"
        return jsonify({"error": f"File type '.{ext}' not supported. Supported: images, PDFs, Office docs, media files."}), 400

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=f"_{filename}", delete=False) as tmp:
            upload.save(tmp.name)
            tmp_path = tmp.name
        metadata = extract_metadata(tmp_path, filename)
        metadata["ai_analysis"] = ai_file(filename, metadata) if bool_value(request.form.get("external_intel"), True) else {"available": False}
        return jsonify(metadata)
    except Exception as exc:
        return jsonify({"error": f"File analysis failed: {exc}"}), 500
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", port=5000, use_reloader=False)
