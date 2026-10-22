"""HTTP probe module — authorized active testing of discovered endpoints."""
from vulnscanner.http_probe.scope import Scope
from vulnscanner.http_probe.prober import HttpProber, ProbeResult

__all__ = ["Scope", "HttpProber", "ProbeResult"]
