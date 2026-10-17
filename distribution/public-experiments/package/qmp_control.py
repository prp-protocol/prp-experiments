"""Small QMP client over an already owned connected channel; never opens sockets.

Only greeting, baseline capabilities and quit. QMP ACK is never process death.
Caller supplies admitted byte/call reservations, endpoint identity and deadline.
"""
import json
import math


class Refusal(Exception):
    pass


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Refusal("Duplicate QMP key")
        value[key] = item
    return value


class Client:
    def __init__(self, channel, identity, clock, end, *, rx_bytes, tx_bytes, calls, frame_bytes):
        if identity is None or type(end) not in (float, int) or not math.isfinite(end):
            raise Refusal("Independent endpoint identity and finite deadline required")
        if any(type(v) is not int or v <= 0 for v in (rx_bytes, tx_bytes, calls, frame_bytes)):
            raise Refusal("Explicit finite caller-owned reservations required")
        if frame_bytes > rx_bytes:
            raise Refusal("Frame capacity exceeds receive reservation")
        self.channel, self.identity, self.clock, self.end = channel, identity, clock, end
        self.rx_limit, self.tx_limit, self.call_limit, self.frame_limit = rx_bytes, tx_bytes, calls, frame_bytes
        self.rx = self.tx = self.calls = 0
        self.raw = []
        self.pending = b""
        self.state = "GREETING"
        self.primary = None
        self.busy = False
        self.last = None
        self.revision = 0
        self.possible = set()
        self.version = None
        self.events = 0
        self.phase_end = end

    def fail(self, error):
        self.revision += 1
        if self.primary is None:
            self.primary = error
        return self.primary

    def time(self, revision):
        value = self.clock()
        if (type(value) not in (int, float) or not math.isfinite(value)
                or (self.last is not None and value < self.last)):
            raise Refusal("QMP clock invalid or regressed")
        self.last = value
        if value >= min(self.end, self.phase_end):
            raise Refusal("QMP absolute deadline reached")
        if self.primary is not None or revision != self.revision:
            raise self.primary

    def begin(self, identity):
        if self.busy:
            raise self.fail(Refusal("QMP reentry"))
        self.busy = True
        try:
            if identity is not self.identity:
                raise Refusal("Foreign endpoint lifetime")
            self.time(self.revision)
        except Exception as error:
            self.busy = False
            raise self.fail(error)
        return self.revision

    def debit_call(self):
        if self.calls >= self.call_limit:
            raise Refusal("QMP call reservation exhausted")
        self.calls += 1

    def receive(self, identity):
        revision = self.begin(identity)
        try:
            if self.state == "QUIT_ACK":
                raise Refusal("Quit transaction already complete")
            n = min(self.rx_limit - self.rx, self.frame_limit - len(self.pending))
            if n <= 0:
                raise Refusal("QMP receive/frame reservation exhausted")
            self.debit_call()
            if hasattr(self.channel, "recv_until"):
                raw = self.channel.recv_until(n, int(min(self.end, self.phase_end)*1000000000))
            else:
                raw = self.channel.recv(n)
            if type(raw) is not bytes or len(raw) > n:
                raise Refusal("Unsupported receive result")
            self.rx += len(raw)
            self.raw.append(("rx", raw))
            self.time(revision)  # returned bytes survive clock/callback failure
            if hasattr(self.channel, "check_return"): self.channel.check_return()
            if not raw:
                raise Refusal("QMP EOF without required response")
            self.pending += raw
            while b"\r\n" in self.pending:
                frame, self.pending = self.pending.split(b"\r\n", 1)
                self.frame(frame)
            return self.state
        except Exception as error:
            raise self.fail(error)
        finally:
            self.busy = False

    def frame(self, raw):
        message = json.loads(raw.decode("ascii"), object_pairs_hook=unique,
                             parse_constant=lambda _: (_ for _ in ()).throw(Refusal("Non-JSON constant")))
        if type(message) is not dict:
            raise Refusal("QMP object required")
        if self.state == "GREETING":
            greeting = message.get("QMP")
            if set(message) != {"QMP"} or type(greeting) is not dict or type(greeting.get("version")) is not dict:
                raise Refusal("QMP greeting required")
            version = greeting["version"]
            triple = version.get("qemu")
            if (type(triple) is not dict or any(type(triple.get(k)) is not int or triple[k] < 0
                    for k in ("major", "minor", "micro")) or type(version.get("package")) is not str
                    or type(greeting.get("capabilities")) is not list
                    or any(type(v) is not str for v in greeting["capabilities"])):
                raise Refusal("Malformed greeting/version")
            self.version = version  # informative, not executable identity proof
            self.state = "HELLO"
            return
        if "event" in message:
            stamp = message.get("timestamp")
            if (self.state not in ("READY", "WAIT_QUIT") or type(message["event"]) is not str
                    or not {"event", "timestamp"} <= set(message) <= {"event", "timestamp", "data"}
                    or type(stamp) is not dict or set(stamp) != {"seconds", "microseconds"}
                    or any(type(v) is not int for v in stamp.values())
                    or ("data" in message and type(message["data"]) is not dict)):
                raise Refusal("Unexpected asynchronous event")
            self.events += 1  # full raw bytes are already retained; never terminal evidence
            return
        expected = {"WAIT_CAP": "capabilities", "WAIT_QUIT": "quit"}.get(self.state)
        if expected is None or message.get("id") != expected:
            raise Refusal("Unknown, stale or early QMP reply")
        if set(message) != {"return", "id"} or message["return"] != {}:
            raise Refusal("QMP command failed or unsupported reply shape")
        self.state = "READY" if expected == "capabilities" else "QUIT_ACK"

    def command(self, identity, operation):
        revision = self.begin(identity)
        try:
            expected = {"qmp_capabilities": ("HELLO", "WAIT_CAP", "capabilities"),
                        "quit": ("READY", "WAIT_QUIT", "quit")}.get(operation)
            if expected is None or self.state != expected[0] or self.pending:
                raise Refusal("Unsupported command/state or incomplete inbound frame")
            raw = (json.dumps({"execute": operation, "id": expected[2]}, separators=(",", ":")) + "\r\n").encode()
            if len(raw) > self.tx_limit - self.tx:
                raise Refusal("QMP transmit reservation exhausted")
            self.debit_call()
            self.tx += len(raw)
            self.raw.append(("tx", raw))
            self.state = expected[1]
            self.possible.add(operation)  # before send; partial/throw never retries
            if hasattr(self.channel, "send_until"):
                count = self.channel.send_until(raw, int(min(self.end, self.phase_end)*1000000000))
            else:
                count = self.channel.send(raw)
            self.raw.append(("send_result", count))
            self.time(revision)
            if hasattr(self.channel, "check_return"): self.channel.check_return()
            if type(count) is not int or count != len(raw):
                raise Refusal("Partial/unknown QMP send; no remainder retry")
        except Exception as error:
            raise self.fail(error)
        finally:
            self.busy = False

    def negotiate(self, identity, end=None):
        if self.state != "GREETING":
            raise self.fail(Refusal("Negotiation is one-shot"))
        if end is not None:
            if type(end) not in (int, float) or not math.isfinite(end) or end > self.end:
                raise self.fail(Refusal("Invalid negotiation phase bound"))
            self.phase_end = end
        while self.state == "GREETING":
            self.receive(identity)
        self.command(identity, "qmp_capabilities")
        while self.state == "WAIT_CAP":
            self.receive(identity)
        return self.state  # protocol readiness only, never guest readiness

    def quit(self, identity):
        self.phase_end = self.end  # original cleanup bound, never a new origin
        self.command(identity, "quit")
        while self.state == "WAIT_QUIT":
            self.receive(identity)
        return self.state  # ACK only; wait/reap remain separate
