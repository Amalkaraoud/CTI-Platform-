"""
Export dispatch: pushes the active indicators to the SIEM / TIP destinations configured by the operator.

Destinations come from environment variables ONLY. They are never read from a request, which keeps
the export path free of server-side request forgery: nobody who can call the API can choose where
data is sent.

    ONYX_EXPORT_TAXII_URL      TAXII 2.1 collection "objects" URL   (OpenCTI, Elastic, any TAXII server)
    ONYX_EXPORT_TAXII_TOKEN    bearer token (optional)
    ONYX_EXPORT_MISP_URL       MISP base URL
    ONYX_EXPORT_MISP_KEY       MISP automation key
    ONYX_EXPORT_SPLUNK_URL     Splunk HEC base URL
    ONYX_EXPORT_SPLUNK_TOKEN   Splunk HEC token
    ONYX_EXPORT_TLP            clear | green | amber | red   (default amber)
    ONYX_EXPORT_VERIFY_TLS     true | false                   (default true)
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

from onyx_connectors import export

EXPORTABLE_STATES = ("VALID", "DEGRADING")


def configured_destinations(env: Mapping[str, str]) -> list[str]:
    out = []
    if env.get("ONYX_EXPORT_TAXII_URL"):
        out.append("taxii")
    if env.get("ONYX_EXPORT_MISP_URL") and env.get("ONYX_EXPORT_MISP_KEY"):
        out.append("misp")
    if env.get("ONYX_EXPORT_SPLUNK_URL") and env.get("ONYX_EXPORT_SPLUNK_TOKEN"):
        out.append("splunk")
    return out


def dispatch(indicators: Iterable[dict[str, Any]], env: Mapping[str, str]) -> dict[str, Any]:
    items = [i for i in indicators if i.get("decay_state") in (None, *EXPORTABLE_STATES)]
    dests = configured_destinations(env)
    if not dests:
        return {"status": "skipped", "reason": "no export destination configured", "indicators": len(items)}
    tlp = env.get("ONYX_EXPORT_TLP", "amber")
    kw = {"verify_tls": env.get("ONYX_EXPORT_VERIFY_TLS", "true").lower() != "false"}
    results: dict[str, Any] = {}
    if "taxii" in dests:
        results["taxii"] = export.push_taxii(env["ONYX_EXPORT_TAXII_URL"], export.build_bundle(items, tlp=tlp),
                                             token=env.get("ONYX_EXPORT_TAXII_TOKEN") or None, **kw)
    if "misp" in dests:
        results["misp"] = export.push_misp(env["ONYX_EXPORT_MISP_URL"], env["ONYX_EXPORT_MISP_KEY"],
                                           export.build_misp_event("ONYX CTI export", items, tlp=tlp), **kw)
    if "splunk" in dests:
        results["splunk"] = export.push_splunk_hec(env["ONYX_EXPORT_SPLUNK_URL"], env["ONYX_EXPORT_SPLUNK_TOKEN"],
                                                   export.build_splunk_events(items), **kw)
    return {"status": "ok", "indicators": len(items), "destinations": results}
