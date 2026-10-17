"""FFI adapter for the consumer-owned held-child helper. No automatic library load.

The owner must authenticate/build/select its own helper before passing a CDLL.
No default library, executable, descriptor source or runtime authorization here.
"""
import ctypes as C
import os

from exec_channel import Channel
from child_process import Child
from two_guest import CreationResult, Observation


class Refusal(Exception):
    pass


class Plan(C.Structure):
    _fields_ = [("executable", C.c_int), ("streams", C.c_int * 4),
                ("argv", C.POINTER(C.c_char_p)), ("envp", C.POINTER(C.c_char_p)),
                ("launch_end_ns", C.c_int64), ("network_count", C.c_uint), ("network", C.c_int * 4)]


class Record(C.Structure):
    _fields_ = [(n, C.c_int) for n in ("pid", "pidfd", "gate", "exec_error", "started", "owned", "retired",
                "release_attempted", "release_possible", "primary", "secondary")] + [
                ("release_count", C.c_ssize_t), ("last_ns", C.c_int64), ("launch_end_ns", C.c_int64)]


def plan(executable, streams, argv, envp, launch_end_ns, *, network=()):
    if (type(executable) is not int or type(streams) not in (list, tuple) or len(streams) != 4
            or any(type(v) is not int or not 4 <= v <= 2147483647 for v in [executable, *streams])
            or len(set([executable, *streams])) != 5):
        raise Refusal("Five distinct retained descriptors required")
    if (type(network) not in (list, tuple) or len(network) not in (0, 4)
            or any(type(v) is not int or not 4+len(network) <= v <= 2147483647
                   for v in [executable, *streams, *network])
            or len(set([executable, *streams, *network])) != 5+len(network)):
        raise Refusal("Zero or two exact TAP/vhost pairs, disjoint from child destinations required")
    if type(launch_end_ns) is not int or not 0 < launch_end_ns < 2**63:
        raise Refusal("Original nanosecond launch bound required")
    arrays = []
    for items in (argv, envp):
        if (type(items) not in (list, tuple) or len(items) >= 64 or
                any(type(x) is not bytes or b"\0" in x or len(x) > 4096 for x in items)
                or sum(len(x)+1 for x in items) > 65536):
            raise Refusal("Bounded bytes-only argv/env required")
        arrays.append((C.c_char_p * (len(items)+1))(*items, None))
    if not argv or not argv[0]:
        raise Refusal("Nonempty argv required")
    result = Plan(executable, (C.c_int*4)(*streams), arrays[0], arrays[1], launch_end_ns, len(network), (C.c_int*4)(*network))
    result._retained_strings = arrays
    return result


class Capability:
    def __init__(self, owner, selected_plan):
        self.owner, self.plan = owner, selected_plan
        self.record = Record()
        self.child = None
        self.channel = None
        self.creation_error = None
        self.retirement_attempted = False


class Binding:
    def __init__(self, library, clock_ns, cleanup_end_ns, *, waitid=None, send=None):
        if type(cleanup_end_ns) is not int or not 0 < cleanup_end_ns < 2**63:
            raise Refusal("Original nanosecond cleanup bound required")
        self.lib, self.clock, self.end = library, clock_ns, cleanup_end_ns
        self.waitid, self.send = waitid, send
        self.records = {}
        self.configure()

    def configure(self):
        self.lib.hs_layout.argtypes = [C.c_uint, C.c_uint]
        self.lib.hs_layout.restype = C.c_size_t
        for kind, struct in enumerate((Plan, Record)):
            expected = [C.sizeof(struct)] + [getattr(struct, name).offset for name, _ in struct._fields_]
            for field, value in enumerate(expected):
                if self.lib.hs_layout(kind, field) != value:
                    raise Refusal("Held-helper ABI layout mismatch")
        signatures = {"hs_init": ([C.POINTER(Record)], None),
            "hs_create": ([C.POINTER(Record), C.POINTER(Plan)], C.c_int),
            "hs_release": ([C.POINTER(Record), C.c_int64], C.c_int),
            "hs_cancel_gate": ([C.POINTER(Record)], C.c_int),
            "hs_retire": ([C.POINTER(Record)], None)}
        for name, (args, result) in signatures.items():
            function = getattr(self.lib, name)
            function.argtypes, function.restype = args, result

    def create_held(self, role, selected_plan):
        if role not in ("endpoint", "dut") or role in self.records:
            raise Refusal("Unknown or repeated guest role")
        if type(selected_plan) is not Plan or not 0 < selected_plan.launch_end_ns < self.end:
            raise Refusal("Launch/cleanup bounds do not match the selected phases")
        cap = Capability(self, selected_plan)
        self.records[role] = cap  # retain storage before native call or any failure
        self.lib.hs_init(C.byref(cap.record))
        result = self.lib.hs_create(C.byref(cap.record), C.byref(selected_plan))
        if result not in (0, -1):
            raise Refusal("Unsupported create return; record retained for reconciliation")
        if cap.record.primary:
            cap.creation_error = OSError(cap.record.primary, os.strerror(cap.record.primary))
        elif result:
            cap.creation_error = Refusal("Creation failed without exact error")
        if cap.record.owned:
            options = {}
            if self.waitid is not None: options["waitid"] = self.waitid
            if self.send is not None: options["send"] = self.send
            cap.child = Child(cap.record.pid, cap.record.pidfd if cap.record.pidfd >= 0 else None,
                              self.clock, self.end, **options)
            return CreationResult(cap, cap.creation_error)
        return CreationResult(None, cap.creation_error or Refusal("No original child retained"))

    def exact(self, cap):
        if type(cap) is not Capability or cap.owner is not self or not any(cap is v for v in self.records.values()) or cap.child is None:
            raise Refusal("Foreign or unowned child capability")

    def release(self, cap):
        self.exact(cap)
        if cap.creation_error is not None:
            raise cap.creation_error
        if cap.child.authority_lost or cap.child.terminal is not None or cap.child.reaped:
            raise Refusal("Child lifetime retired or unknown")
        if self.lib.hs_release(C.byref(cap.record), cap.plan.launch_end_ns):
            raise OSError(cap.record.primary or 5, "Gate release refused/uncertain")

    def observe(self, cap, kind):
        self.exact(cap)
        try:
            cap.child.observation(kind)
        finally:
            # Genuine terminal return suppresses C release even if its clock was late.
            if (cap.child.terminal is not None or cap.child.authority_lost) and not cap.retirement_attempted:
                cap.retirement_attempted = True
                self.lib.hs_retire(C.byref(cap.record))
        return Observation(cap, kind)

    def terminate_exact(self, cap):
        self.exact(cap)
        return cap.child.terminate()

    def exec_channel(self, cap, *, read, close):
        """Bind explicit operations once; no implicit native channel activation."""
        self.exact(cap)
        if cap.channel is not None:
            raise Refusal("Diagnostic descriptor already bound")
        cap.channel = Channel(cap.record.exec_error,
                              cap.record.pidfd if cap.record.pidfd >= 0 else None,
                              self.clock, self.end, read=read, close=close)
        return cap.channel

    def close_descriptors(self, cap):
        self.exact(cap)
        if cap.channel is None:
            raise Refusal("Descriptor inventory not bound")
        return cap.channel.finish(reaped=cap.child.reaped)
