"""ETW capture engine — real-time network flows without any driver to install.

Windows already traces its own TCP/IP stack through Event Tracing for Windows.
This module opens a private real-time ETW session (pure ctypes, no dependency)
and subscribes to two manifest providers:

* ``Microsoft-Windows-Kernel-Network`` — one event per TCP/UDP send, receive,
  connect, accept and disconnect, with addresses, ports, byte count and the
  owning process id.
* ``Microsoft-Windows-DNS-Client`` — one event per DNS query issued by any
  process (query name).

Requirements: Windows 10/11, administrator (creating an ETW session needs it).
No packet contents are available: DPI / IDS payload rules / JA3 / pcap recording
belong to the optional Npcap engine.

The event payload layouts below come from the providers' manifests
(``wevtutil gp Microsoft-Windows-Kernel-Network /ge /gm``). Ports use the
``win:Port`` out-type, i.e. network byte order.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import socket
import struct
import sys
import uuid
from typing import Optional, Set

from .base import (ACCEPT, CONNECT, DISCONNECT, RECV, SEND, CaptureEngine,
                   DnsEvent, FlowEvent)

SESSION_NAME = "NetGuardAI-Capture"

KERNEL_NETWORK_GUID = uuid.UUID("{7DD42A49-5329-4832-8DFD-43D979153A88}")
DNS_CLIENT_GUID = uuid.UUID("{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}")

# Microsoft-Windows-Kernel-Network event ids
TCP4 = {10: SEND, 11: RECV, 12: CONNECT, 13: DISCONNECT, 15: ACCEPT}
TCP6 = {26: SEND, 27: RECV, 28: CONNECT, 29: DISCONNECT, 31: ACCEPT}
UDP4 = {42: SEND, 43: RECV}
UDP6 = {58: SEND, 59: RECV}
KERNEL_NETWORK_KEYWORDS = 0x10 | 0x20          # IPv4 | IPv6
DNS_QUERY_EVENT_IDS = (3006,)                    # "DNS query is called for the name …"

# ── payload parsers (pure functions: unit-tested without a live session) ─────
_V4 = struct.Struct("<II4s4s")      # PID, size, daddr, saddr   (then >HH dport, sport)
_V6 = struct.Struct("<II16s16s")
_PORTS = struct.Struct(">HH")


def parse_network_event(event_id: int, data: bytes, local_ips: Optional[Set[str]] = None) -> Optional[FlowEvent]:
    """Decode one Kernel-Network event payload into a FlowEvent (None if unknown/short)."""
    if event_id in TCP4 or event_id in UDP4:
        if len(data) < _V4.size + _PORTS.size:
            return None
        pid, size, daddr, saddr = _V4.unpack_from(data, 0)
        dport, sport = _PORTS.unpack_from(data, _V4.size)
        d_ip, s_ip = socket.inet_ntoa(daddr), socket.inet_ntoa(saddr)
        kind = (TCP4.get(event_id) or UDP4.get(event_id))
        proto = "TCP" if event_id in TCP4 else "UDP"
    elif event_id in TCP6 or event_id in UDP6:
        if len(data) < _V6.size + _PORTS.size:
            return None
        pid, size, daddr, saddr = _V6.unpack_from(data, 0)
        dport, sport = _PORTS.unpack_from(data, _V6.size)
        d_ip, s_ip = socket.inet_ntop(socket.AF_INET6, daddr), socket.inet_ntop(socket.AF_INET6, saddr)
        kind = (TCP6.get(event_id) or UDP6.get(event_id))
        proto = "TCP" if event_id in TCP6 else "UDP"
    else:
        return None

    # The kernel logs each event from the local endpoint's perspective
    # (saddr = local). Receive events on some builds carry the wire order
    # instead, so trust the interface address list when it can decide.
    local_ip, local_port, remote_ip, remote_port = s_ip, sport, d_ip, dport
    if local_ips:
        if s_ip not in local_ips and d_ip in local_ips:
            local_ip, local_port, remote_ip, remote_port = d_ip, dport, s_ip, sport
    if kind in (CONNECT, ACCEPT, DISCONNECT):
        size = 0
    return FlowEvent(kind=kind, proto=proto, local_ip=local_ip, local_port=local_port,
                     remote_ip=remote_ip, remote_port=remote_port, size=int(size), pid=int(pid))


def parse_dns_event(data: bytes, pid: int = 0) -> Optional[DnsEvent]:
    """DNS-Client 3006: first field is the query name (null-terminated UTF-16LE), then QueryType (u32)."""
    end = -1
    for i in range(0, len(data) - 1, 2):
        if data[i] == 0 and data[i + 1] == 0:
            end = i
            break
    if end <= 0:
        return None
    try:
        name = data[:end].decode("utf-16-le", errors="replace").strip().rstrip(".")
    except Exception:
        return None
    if not name or len(name) > 253:
        return None
    qtype = 0
    if len(data) >= end + 2 + 4:
        qtype = struct.unpack_from("<I", data, end + 2)[0]
    return DnsEvent(name=name, pid=int(pid), qtype=int(qtype))


def local_ip_set() -> Set[str]:
    ips: Set[str] = {"127.0.0.1", "::1"}
    try:
        import psutil
        for infos in psutil.net_if_addrs().values():
            for info in infos:
                addr = (getattr(info, "address", "") or "").split("%")[0]
                if addr and ":" in addr or addr.count(".") == 3:
                    ips.add(addr)
    except Exception:
        try:
            for res in socket.getaddrinfo(socket.gethostname(), None):
                ips.add(res[4][0].split("%")[0])
        except Exception:
            pass
    return ips


# ── ctypes declarations (Windows only) ───────────────────────────────────────
class GUID(ctypes.Structure):
    _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD), ("Data4", ctypes.c_ubyte * 8)]

    @classmethod
    def from_uuid(cls, u: uuid.UUID) -> "GUID":
        g = cls()
        ctypes.memmove(ctypes.byref(g), u.bytes_le, 16)
        return g

    def to_uuid(self) -> uuid.UUID:
        return uuid.UUID(bytes_le=bytes(self))


class WNODE_HEADER(ctypes.Structure):
    _fields_ = [("BufferSize", wt.ULONG), ("ProviderId", wt.ULONG), ("HistoricalContext", ctypes.c_uint64),
                ("TimeStamp", ctypes.c_int64), ("Guid", GUID), ("ClientContext", wt.ULONG), ("Flags", wt.ULONG)]


class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [("Wnode", WNODE_HEADER), ("BufferSize", wt.ULONG), ("MinimumBuffers", wt.ULONG),
                ("MaximumBuffers", wt.ULONG), ("MaximumFileSize", wt.ULONG), ("LogFileMode", wt.ULONG),
                ("FlushTimer", wt.ULONG), ("EnableFlags", wt.ULONG), ("AgeLimit", wt.LONG),
                ("NumberOfBuffers", wt.ULONG), ("FreeBuffers", wt.ULONG), ("EventsLost", wt.ULONG),
                ("BuffersWritten", wt.ULONG), ("LogBuffersLost", wt.ULONG), ("RealTimeBuffersLost", wt.ULONG),
                ("LoggerThreadId", wt.HANDLE), ("LogFileNameOffset", wt.ULONG), ("LoggerNameOffset", wt.ULONG)]


class EVENT_DESCRIPTOR(ctypes.Structure):
    _fields_ = [("Id", wt.USHORT), ("Version", ctypes.c_ubyte), ("Channel", ctypes.c_ubyte),
                ("Level", ctypes.c_ubyte), ("Opcode", ctypes.c_ubyte), ("Task", wt.USHORT),
                ("Keyword", ctypes.c_uint64)]


class EVENT_HEADER(ctypes.Structure):
    _fields_ = [("Size", wt.USHORT), ("HeaderType", wt.USHORT), ("Flags", wt.USHORT), ("EventProperty", wt.USHORT),
                ("ThreadId", wt.ULONG), ("ProcessId", wt.ULONG), ("TimeStamp", ctypes.c_int64),
                ("ProviderId", GUID), ("EventDescriptor", EVENT_DESCRIPTOR), ("ProcessorTime", ctypes.c_uint64),
                ("ActivityId", GUID)]


class ETW_BUFFER_CONTEXT(ctypes.Structure):
    _fields_ = [("ProcessorNumber", ctypes.c_ubyte), ("Alignment", ctypes.c_ubyte), ("LoggerId", wt.USHORT)]


class EVENT_RECORD(ctypes.Structure):
    _fields_ = [("EventHeader", EVENT_HEADER), ("BufferContext", ETW_BUFFER_CONTEXT),
                ("ExtendedDataCount", wt.USHORT), ("UserDataLength", wt.USHORT),
                ("ExtendedData", ctypes.c_void_p), ("UserData", ctypes.c_void_p), ("UserContext", ctypes.c_void_p)]


class EVENT_TRACE_HEADER(ctypes.Structure):
    _fields_ = [("Size", wt.USHORT), ("FieldTypeFlags", wt.USHORT), ("Version", wt.ULONG),
                ("ThreadId", wt.ULONG), ("ProcessId", wt.ULONG), ("TimeStamp", ctypes.c_int64),
                ("Guid", GUID), ("ProcessorTime", ctypes.c_uint64)]


class EVENT_TRACE(ctypes.Structure):
    _fields_ = [("Header", EVENT_TRACE_HEADER), ("InstanceId", wt.ULONG), ("ParentInstanceId", wt.ULONG),
                ("ParentGuid", GUID), ("MofData", ctypes.c_void_p), ("MofLength", wt.ULONG),
                ("ClientContext", wt.ULONG)]


class TRACE_LOGFILE_HEADER(ctypes.Structure):
    _fields_ = [("BufferSize", wt.ULONG), ("Version", wt.ULONG), ("ProviderVersion", wt.ULONG),
                ("NumberOfProcessors", wt.ULONG), ("EndTime", ctypes.c_int64), ("TimerResolution", wt.ULONG),
                ("MaximumFileSize", wt.ULONG), ("LogFileMode", wt.ULONG), ("BuffersWritten", wt.ULONG),
                ("LogInstanceGuid", GUID), ("LoggerName", ctypes.c_void_p), ("LogFileName", ctypes.c_void_p),
                ("TimeZone", ctypes.c_byte * 172), ("BootTime", ctypes.c_int64), ("PerfFreq", ctypes.c_int64),
                ("StartTime", ctypes.c_int64), ("ReservedFlags", wt.ULONG), ("BuffersLost", wt.ULONG)]


EVENT_RECORD_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.POINTER(EVENT_RECORD)) if sys.platform == "win32" else None


class EVENT_TRACE_LOGFILEW(ctypes.Structure):
    _fields_ = [("LogFileName", wt.LPWSTR), ("LoggerName", wt.LPWSTR), ("CurrentTime", ctypes.c_int64),
                ("BuffersRead", wt.ULONG), ("ProcessTraceMode", wt.ULONG), ("CurrentEvent", EVENT_TRACE),
                ("LogfileHeader", TRACE_LOGFILE_HEADER), ("BufferCallback", ctypes.c_void_p),
                ("BufferSize", wt.ULONG), ("Filled", wt.ULONG), ("EventsLost", wt.ULONG),
                ("EventRecordCallback", ctypes.c_void_p), ("IsKernelTrace", wt.ULONG), ("Context", ctypes.c_void_p)]


WNODE_FLAG_TRACED_GUID = 0x00020000
EVENT_TRACE_REAL_TIME_MODE = 0x00000100
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
EVENT_TRACE_CONTROL_STOP = 1
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
TRACE_LEVEL_INFORMATION = 4
ERROR_SUCCESS, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS = 0, 5, 183
INVALID_PROCESSTRACE_HANDLE = 0xFFFFFFFFFFFFFFFF if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x00000000FFFFFFFF
_NAME_CHARS = 512


def struct_sizes() -> dict:
    """Sanity numbers checked by the unit tests (x64 values from the Windows SDK)."""
    return {"EVENT_TRACE_PROPERTIES": ctypes.sizeof(EVENT_TRACE_PROPERTIES),
            "EVENT_HEADER": ctypes.sizeof(EVENT_HEADER),
            "EVENT_RECORD": ctypes.sizeof(EVENT_RECORD),
            "EVENT_TRACE": ctypes.sizeof(EVENT_TRACE),
            "TRACE_LOGFILE_HEADER": ctypes.sizeof(TRACE_LOGFILE_HEADER),
            "EVENT_TRACE_LOGFILEW": ctypes.sizeof(EVENT_TRACE_LOGFILEW)}


def _new_properties():
    total = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + 2 * _NAME_CHARS * ctypes.sizeof(ctypes.c_wchar)
    buf = ctypes.create_string_buffer(total)
    props = ctypes.cast(buf, ctypes.POINTER(EVENT_TRACE_PROPERTIES)).contents
    props.Wnode.BufferSize = total
    props.Wnode.Flags = WNODE_FLAG_TRACED_GUID
    props.Wnode.ClientContext = 1                      # QPC timestamps
    props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
    props.BufferSize = 64                              # KB per buffer
    props.MinimumBuffers = 16
    props.MaximumBuffers = 128
    props.FlushTimer = 1                               # seconds
    props.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
    props.LogFileNameOffset = 0
    return buf, props


class EtwEngine(CaptureEngine):
    name = "etw"

    def __init__(self, *args, session_name: str = SESSION_NAME, **kwargs):
        super().__init__(*args, **kwargs)
        self.session_name = session_name
        self._session = ctypes.c_uint64(0)
        self._trace = None
        self._callback_ref = None
        self._local_ips: Set[str] = set()
        self._kn = KERNEL_NETWORK_GUID.bytes_le
        self._dns = DNS_CLIENT_GUID.bytes_le

    # -- session management --------------------------------------------------
    def _advapi(self):
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        advapi.StartTraceW.argtypes = [ctypes.POINTER(ctypes.c_uint64), wt.LPCWSTR, ctypes.c_void_p]
        advapi.StartTraceW.restype = wt.ULONG
        advapi.ControlTraceW.argtypes = [ctypes.c_uint64, wt.LPCWSTR, ctypes.c_void_p, wt.ULONG]
        advapi.ControlTraceW.restype = wt.ULONG
        advapi.EnableTraceEx2.argtypes = [ctypes.c_uint64, ctypes.POINTER(GUID), wt.ULONG, ctypes.c_ubyte,
                                          ctypes.c_uint64, ctypes.c_uint64, wt.ULONG, ctypes.c_void_p]
        advapi.EnableTraceEx2.restype = wt.ULONG
        advapi.OpenTraceW.argtypes = [ctypes.POINTER(EVENT_TRACE_LOGFILEW)]
        advapi.OpenTraceW.restype = ctypes.c_uint64
        advapi.ProcessTrace.argtypes = [ctypes.POINTER(ctypes.c_uint64), wt.ULONG, ctypes.c_void_p, ctypes.c_void_p]
        advapi.ProcessTrace.restype = wt.ULONG
        advapi.CloseTrace.argtypes = [ctypes.c_uint64]
        advapi.CloseTrace.restype = wt.ULONG
        return advapi

    def _stop_session(self, advapi) -> None:
        buf, _props = _new_properties()
        advapi.ControlTraceW(0, self.session_name, buf, EVENT_TRACE_CONTROL_STOP)

    def stop(self) -> None:
        super().stop()
        if sys.platform != "win32":
            return
        try:
            advapi = self._advapi()
            self._stop_session(advapi)          # makes ProcessTrace return
            if self._trace is not None:
                advapi.CloseTrace(self._trace)
        except Exception:
            pass

    # -- event callback ------------------------------------------------------
    def _on_event(self, record_ptr) -> None:
        try:
            rec = record_ptr.contents
            n = rec.UserDataLength
            if not n or not rec.UserData:
                return
            provider = bytes(rec.EventHeader.ProviderId)
            event_id = rec.EventHeader.EventDescriptor.Id
            if provider == self._kn:
                data = ctypes.string_at(rec.UserData, n)
                ev = parse_network_event(event_id, data, self._local_ips)
                if ev is not None:
                    self.events_seen += 1
                    self.on_flow(ev)
            elif provider == self._dns and event_id in DNS_QUERY_EVENT_IDS:
                data = ctypes.string_at(rec.UserData, n)
                dev = parse_dns_event(data, rec.EventHeader.ProcessId)
                if dev is not None:
                    self.on_dns(dev)
        except Exception:
            # Never let an exception cross the ctypes callback boundary
            self.events_lost += 1

    # -- main loop -----------------------------------------------------------
    def _run(self) -> None:
        if sys.platform != "win32":
            self.on_error("moteur ETW: Windows requis")
            return
        advapi = self._advapi()
        self._local_ips = local_ip_set()

        buf, _props = _new_properties()
        rc = advapi.StartTraceW(ctypes.byref(self._session), self.session_name, buf)
        if rc == ERROR_ALREADY_EXISTS:            # stale session from a previous crash
            self._stop_session(advapi)
            buf, _props = _new_properties()
            rc = advapi.StartTraceW(ctypes.byref(self._session), self.session_name, buf)
        if rc == ERROR_ACCESS_DENIED:
            self.on_error("moteur ETW: droits administrateur requis (relance NetGuard AI en tant qu'administrateur)")
            return
        if rc != ERROR_SUCCESS:
            self.on_error(f"moteur ETW: StartTrace a échoué (code {rc})")
            return

        try:
            for guid, keywords in ((KERNEL_NETWORK_GUID, KERNEL_NETWORK_KEYWORDS), (DNS_CLIENT_GUID, 0)):
                g = GUID.from_uuid(guid)
                rc = advapi.EnableTraceEx2(self._session.value, ctypes.byref(g), EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                           TRACE_LEVEL_INFORMATION, keywords, 0, 0, None)
                if rc != ERROR_SUCCESS and guid == KERNEL_NETWORK_GUID:
                    self.on_error(f"moteur ETW: EnableTraceEx2 Kernel-Network a échoué (code {rc})")
                    return

            self._callback_ref = EVENT_RECORD_CALLBACK(self._on_event)   # keep a reference alive
            logfile = EVENT_TRACE_LOGFILEW()
            logfile.LoggerName = self.session_name
            logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
            logfile.EventRecordCallback = ctypes.cast(self._callback_ref, ctypes.c_void_p)
            handle = advapi.OpenTraceW(ctypes.byref(logfile))
            if handle == INVALID_PROCESSTRACE_HANDLE:
                self.on_error(f"moteur ETW: OpenTrace a échoué (code {ctypes.get_last_error()})")
                return
            self._trace = handle
            handles = (ctypes.c_uint64 * 1)(handle)
            # Blocks until the session is stopped (stop() → ControlTrace STOP)
            rc = advapi.ProcessTrace(handles, 1, None, None)
            if rc != ERROR_SUCCESS and not self._stop.is_set():
                self.on_error(f"moteur ETW: ProcessTrace s'est arrêté (code {rc})")
        finally:
            try:
                if self._trace is not None:
                    advapi.CloseTrace(self._trace)
                self._stop_session(advapi)
            except Exception:
                pass
