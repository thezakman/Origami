"""Origin-IP discovery & IP-based WAF bypass — a discovery dimension the path
scan can't reach.

Behind a CDN/WAF (Cloudflare, Akamai, AWS) the public DNS points at the *edge*,
which filters and blocks. If the real **origin** IP is reachable, requesting it
directly with the target's `Host` header bypasses the edge entirely — reaching
content the WAF hides. This module gathers candidate origin IPs and the scanner's
`_origin_fold` probes each one.

Layered by what's configured (the user picked "keyed, else crt.sh fallback"):

  1. **Always (keyless):** resolve the host's own A/AAAA records — a misconfigured
     A record often points straight at the origin, not the CDN.
  2. **crt.sh (keyless):** Certificate-Transparency SANs/subdomains → resolve them;
     a sibling sub-host frequently resolves to the origin the apex hides.
  3. **Keyed OSINT (opt-in via env keys):** Shodan / SecurityTrails / Censys search
     by hostname/cert for associated & *historical* IPs (the strongest origin leads).
     When no key is set, this layer is skipped and crt.sh (2) is the fallback.

Pure URL-builders + parsers here (unit-tested, offline); the thin async fetchers
each own a short-lived httpx client, mirroring modules/discovery/wayback.py.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket

import httpx

from origami.core import credentials

_TIMEOUT = 12.0
_MAX_CANDIDATES = 40          # cap resolved candidate IPs we hand back to the fold


# ── layer 1: direct DNS ────────────────────────────────────────────────────────
async def resolve_ips(host: str, *, port: int = 443) -> list[str]:
    """All A/AAAA addresses for `host` (deduped, order-preserving). Runs the
    blocking getaddrinfo in a thread so the event loop isn't stalled. [] on failure."""
    host = host.split(":")[0].strip(".")
    if not host:
        return []
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for info in infos:
        ip = info[4][0]
        if ip and ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


# ── layer 2: crt.sh (keyless Certificate Transparency) ──────────────────────────
def crtsh_url(domain: str) -> str:
    """crt.sh JSON search for every certificate naming `domain` (and subdomains)."""
    return f"https://crt.sh/?q=%25.{domain}&output=json"


def parse_crtsh(text: str, domain: str) -> set[str]:
    """Hostnames under `domain` from a crt.sh JSON response. Wildcards (`*.x`) are
    stripped to the bare label; only names within `domain` are kept."""
    domain = domain.lower().strip(".")
    try:
        rows = json.loads(text)
    except (ValueError, TypeError):
        return set()
    out: set[str] = set()
    for row in rows if isinstance(rows, list) else ():
        nv = row.get("name_value") if isinstance(row, dict) else None
        if not isinstance(nv, str):
            continue
        for name in nv.splitlines():
            name = name.strip().lstrip("*.").lower().strip(".")
            if name and (name == domain or name.endswith("." + domain)):
                out.add(name)
    return out


# ── layer 3: keyed OSINT (Shodan / SecurityTrails / Censys) ─────────────────────
def shodan_search_url(host: str, key: str) -> str:
    return f"https://api.shodan.io/shodan/host/search?key={key}&query=hostname:{host}"


def parse_shodan(text: str) -> set[str]:
    """IPs from a Shodan host/search response (`matches[].ip_str`)."""
    try:
        d = json.loads(text)
    except (ValueError, TypeError):
        return set()
    out: set[str] = set()
    for m in (d.get("matches") or []) if isinstance(d, dict) else ():
        ip = m.get("ip_str") if isinstance(m, dict) else None
        if isinstance(ip, str) and ip:
            out.add(ip)
    return out


def securitytrails_url(domain: str) -> str:
    """SecurityTrails **historical** A records — the classic origin-behind-CDN leak."""
    return f"https://api.securitytrails.com/v1/history/{domain}/dns/a"


def parse_securitytrails(text: str) -> set[str]:
    """IPs from a SecurityTrails history/dns/a response (`records[].values[].ip`)."""
    try:
        d = json.loads(text)
    except (ValueError, TypeError):
        return set()
    out: set[str] = set()
    for rec in (d.get("records") or []) if isinstance(d, dict) else ():
        for v in (rec.get("values") or []) if isinstance(rec, dict) else ():
            ip = v.get("ip") if isinstance(v, dict) else None
            if isinstance(ip, str) and ip:
                out.add(ip)
    return out


def censys_search_url() -> str:
    return "https://search.censys.io/api/v2/hosts/search"


def censys_query(domain: str) -> dict:
    """Censys hosts search body — servers whose TLS cert names `domain`."""
    return {"q": f"services.tls.certificates.leaf_data.names: {domain}", "per_page": 50}


def parse_censys(text: str) -> set[str]:
    """IPs from a Censys hosts/search response (`result.hits[].ip`)."""
    try:
        d = json.loads(text)
    except (ValueError, TypeError):
        return set()
    hits = (((d.get("result") or {}).get("hits")) or []) if isinstance(d, dict) else []
    return {h["ip"] for h in hits if isinstance(h, dict) and isinstance(h.get("ip"), str)}


# env var → (present?) so the fold can announce which keyed sources are active.
def configured_sources() -> list[str]:
    """Keyed OSINT sources whose credentials are available (env var or config file)."""
    out = []
    if credentials.get("SHODAN_API_KEY"):
        out.append("shodan")
    if credentials.get("SECURITYTRAILS_API_KEY"):
        out.append("securitytrails")
    if credentials.get("CENSYS_API_ID") and credentials.get("CENSYS_API_SECRET"):
        out.append("censys")
    return out


async def _get(client: httpx.AsyncClient, url: str, **kw) -> str:
    r = await client.get(url, **kw)
    r.raise_for_status()
    return r.text


async def keyed_ips(domain: str) -> set[str]:
    """Query every configured keyed source for candidate origin IPs. Best-effort:
    a source that errors/times-out contributes nothing (never raises)."""
    ips: set[str] = set()
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True,
                                 headers={"User-Agent": "origami"}) as c:
        if key := credentials.get("SHODAN_API_KEY"):
            try:
                ips |= parse_shodan(await _get(c, shodan_search_url(domain, key)))
            except Exception:
                pass
        if key := credentials.get("SECURITYTRAILS_API_KEY"):
            try:
                ips |= parse_securitytrails(await _get(
                    c, securitytrails_url(domain), headers={"APIKEY": key}))
            except Exception:
                pass
        cid, csec = credentials.get("CENSYS_API_ID"), credentials.get("CENSYS_API_SECRET")
        if cid and csec:
            try:
                r = await c.post(censys_search_url(), json=censys_query(domain),
                                 auth=(cid, csec))
                r.raise_for_status()
                ips |= parse_censys(r.text)
            except Exception:
                pass
    return ips


async def crtsh_ips(domain: str, *, cap: int = _MAX_CANDIDATES) -> set[str]:
    """crt.sh subdomains → resolve each (concurrently) → candidate IPs. Best-effort."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True,
                                     headers={"User-Agent": "origami"}) as c:
            names = parse_crtsh(await _get(c, crtsh_url(domain)), domain)
    except Exception:
        return set()
    resolved = await asyncio.gather(*(resolve_ips(n) for n in list(names)[:cap]),
                                    return_exceptions=True)
    ips: set[str] = set()
    for r in resolved:
        if isinstance(r, list):
            ips.update(r)
    return set(list(ips)[:cap])


def has_registrable_domain(host: str) -> bool:
    """False for IP literals and single-label/localhost hosts — targets with no
    domain to query in Certificate Transparency or OSINT (skip those layers)."""
    host = host.split(":")[0].strip(".")
    try:
        ipaddress.ip_address(host)
        return False                     # a bare IP has no CT/OSINT footprint
    except ValueError:
        pass
    return "." in host and host.lower() != "localhost"


async def candidate_origin_ips(host: str) -> tuple[list[str], str]:
    """Gather candidate origin IPs for `host` and say which layer produced them.

    Keyed sources win when configured (the strongest, incl. historical IPs);
    otherwise crt.sh is the fallback — exactly the user's "3, else 2" choice.
    Returns (ips, source_label). Always deduped and capped."""
    from origami.core.scope import reg_domain
    if not has_registrable_domain(host):
        return [], "n/a (IP/local target)"   # no domain → no CT/OSINT to query
    domain = reg_domain(host.split(":")[0])
    if configured_sources():
        ips = await keyed_ips(domain)
        label = "+".join(configured_sources())
        if ips:
            return sorted(ips)[:_MAX_CANDIDATES], label
        # keyed configured but returned nothing → still fall back to crt.sh
    ips = await crtsh_ips(domain)
    return sorted(ips)[:_MAX_CANDIDATES], "crt.sh"
