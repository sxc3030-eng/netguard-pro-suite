"""NetGuard AI — capture engines.

Three interchangeable sources feed the same detection pipeline
(``netguard.process_observation``):

==========  ==========================  =======  ===========================================
engine      needs                       payload  notes
==========  ==========================  =======  ===========================================
``etw``     Windows + administrator     no       built into Windows (no driver to install):
                                                 real-time flows, bytes, owning process, DNS
``poll``    nothing                     no       connection table polling; no per-flow bytes
``npcap``   Npcap driver + scapy        yes      "expert mode": DPI, IDS rules, JA3, pcap
==========  ==========================  =======  ===========================================
"""
from .base import FlowEvent, DnsEvent, CaptureEngine, ENGINE_CAPABILITIES, select_engine_name

__all__ = ["FlowEvent", "DnsEvent", "CaptureEngine", "ENGINE_CAPABILITIES", "select_engine_name"]
