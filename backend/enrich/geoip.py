"""Offline GeoIP / ASN enrichment for IP addresses.

Uses MaxMind GeoLite2 databases when they're present, and degrades cleanly to
public/private classification when they aren't — so the feature is always
available in some form, and fully populated once an operator drops the .mmdb
files into ./data (see .env.example).
"""

import ipaddress
import logging

from backend.config import GEOIP_ASN_DB, GEOIP_CITY_DB

logger = logging.getLogger(__name__)

try:
    import geoip2.database  # type: ignore

    _HAVE_GEOIP2 = True
except ImportError:
    _HAVE_GEOIP2 = False

_city_reader = None
_asn_reader = None
_readers_loaded = False


def _load_readers() -> None:
    global _city_reader, _asn_reader, _readers_loaded
    if _readers_loaded:
        return
    _readers_loaded = True

    if not _HAVE_GEOIP2:
        logger.info("geoip2 not installed; GeoIP enrichment limited to public/private classification")
        return

    import os

    if os.path.exists(GEOIP_CITY_DB):
        try:
            _city_reader = geoip2.database.Reader(GEOIP_CITY_DB)
        except Exception:
            logger.exception("Failed to open GeoLite2 City DB at %s", GEOIP_CITY_DB)
    if os.path.exists(GEOIP_ASN_DB):
        try:
            _asn_reader = geoip2.database.Reader(GEOIP_ASN_DB)
        except Exception:
            logger.exception("Failed to open GeoLite2 ASN DB at %s", GEOIP_ASN_DB)

    if not _city_reader and not _asn_reader:
        logger.info("No GeoLite2 databases found; set GEOIP_CITY_DB / GEOIP_ASN_DB to enable")


def status() -> dict:
    _load_readers()
    return {
        "geoip2_installed": _HAVE_GEOIP2,
        "city_db": _city_reader is not None,
        "asn_db": _asn_reader is not None,
    }


def _scope(ip_obj) -> str:
    if ip_obj.is_private:
        return "private"
    if ip_obj.is_loopback:
        return "loopback"
    if ip_obj.is_multicast:
        return "multicast"
    if ip_obj.is_reserved or ip_obj.is_link_local:
        return "reserved"
    return "public"


def enrich_ip(ip: str) -> dict:
    """Return {ip, scope, country, city, asn, org} — geo fields None when
    unavailable (private IP, or DB not installed)."""
    _load_readers()
    result = {"ip": ip, "scope": "unknown", "country": None, "city": None, "asn": None, "org": None}

    # Tolerate INET text that carries a netmask (e.g. "192.168.1.70/32").
    bare_ip = ip.split("/")[0].strip()
    try:
        ip_obj = ipaddress.ip_address(bare_ip)
    except ValueError:
        return result

    ip = str(ip_obj)
    result["ip"] = ip
    result["scope"] = _scope(ip_obj)
    if result["scope"] != "public":
        return result

    if _city_reader is not None:
        try:
            city = _city_reader.city(ip)
            result["country"] = city.country.name
            result["city"] = city.city.name
        except Exception:
            pass

    if _asn_reader is not None:
        try:
            asn = _asn_reader.asn(ip)
            result["asn"] = asn.autonomous_system_number
            result["org"] = asn.autonomous_system_organization
        except Exception:
            pass

    return result


def enrich_ips(ips: list[str]) -> dict[str, dict]:
    return {ip: enrich_ip(ip) for ip in dict.fromkeys(ips)}
