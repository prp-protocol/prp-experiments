"""Serial two-guest lifecycle composition over explicit injected ports.

No native port is supplied. Capability objects are owned references, never PIDs.
Receipt/claim interpretation is the port's contract; fixtures are not native proof.
"""
from dataclasses import dataclass
import math


class Refusal(Exception):
    pass


@dataclass(frozen=True)
class Observation:
    capability: object
    kind: str  # READY, TERMINAL, REAPED, WRITERS_SETTLED; distinct joins


@dataclass(frozen=True)
class CreationResult:
    capability: object
    error: Exception = None


@dataclass
class Guest:
    role: str
    capability: object = None
    create_attempted: bool = False
    create_uncertain: bool = False
    ready: bool = False
    release_possible: bool = False
    stop_attempted: bool = False
    terminal: bool = False
    reaped: bool = False
    writers_settled: bool = False


class Controller:
    """One run, one origin, two exact capabilities, no native authority inferred.

    Ports: reserve(op, role), create_held(role), release(cap), quit(cap), observe(cap, kind),
    exercise(endpoint_cap, dut_cap), terminate_exact(cap), retain(op, role, raw).
    reserve must debit existing caller-owned quotas before effects. retain must
    be nonblocking bounded custody, not filesystem persistence. No dynamic ports
    are loaded by the CLI. The concrete native implementation remains absent.
    """
    def __init__(self, ports, clock, origin, evidence_validator=None):
        if type(origin) not in (int, float) or not math.isfinite(origin):
            raise Refusal("Finite original HOST monotonic origin required")
        self.ports = ports
        self.clock = clock
        self.origin = origin
        self.last = origin
        self.cleanup_end = origin + 590  # final HOST cleanup phase; export still separate
        self.normal_end = origin + 420  # 20 + 20 + 380, never refreshed
        self.launch_end = origin + 40
        if not (origin < self.launch_end < self.normal_end < self.cleanup_end
                and math.isfinite(self.cleanup_end)):
            raise Refusal("Absolute phase bounds cannot be represented")
        self.started = False
        self.cleanup_started = False
        self.busy = False
        self.revision = 0
        self.time_failed = False
        self.primary = None
        self.secondary = []
        self.secondary_overflow = False
        self.guests = [Guest("endpoint"), Guest("dut")]
        self.exercise_attempted = False
        self.exercise_returned = False
        self.result = None
        self.evidence_validator = evidence_validator
        self.evidence_result = None
        if hasattr(ports, "bind_phases"):
            ports.bind_phases(origin, self.launch_end, self.normal_end, self.cleanup_end)

    def fail(self, error):
        self.revision += 1
        if self.primary is None:
            self.primary = error
        elif error is not self.primary:
            if len(self.secondary) < 8:
                self.secondary.append(error)
            else:
                self.secondary_overflow = True
        return error

    def now(self, end, cleanup=False):
        revision = self.revision
        try:
            value = self.clock()
        except Exception as error:
            self.time_failed = True
            raise self.fail(error)
        # Clock facts are checked even if its callback changed revision.
        if (type(value) not in (int, float) or not math.isfinite(value)
                or value < self.last or self.time_failed):
            self.time_failed = True
            raise self.fail(Refusal("Clock invalid or regressed"))
        self.last = value
        if value >= end:
            raise self.fail(Refusal("Phase expired"))
        if revision != self.revision or (self.primary is not None and not cleanup):
            raise self.primary
        return value

    def call(self, op, guest, callback, end, cleanup=False, returned=None):
        self.now(end, cleanup)
        revision = self.revision
        try:
            self.ports.reserve(op, guest.role if guest else "pair")
            self.now(end, cleanup)
            if revision != self.revision:
                raise self.primary
            raw = callback()
            # Returned ownership/terminal facts precede fallible retention/clocks.
            if returned is not None:
                returned(raw)
            self.ports.retain(op, guest.role if guest else "pair", raw)
            self.now(end, cleanup)
            if revision != self.revision:
                raise self.primary
            return raw
        except Exception as error:
            self.fail(error)
            raise

    def join(self, guest, kind, raw):
        if (type(raw) is not Observation or raw.capability is not guest.capability
                or raw.kind != kind or guest.capability is None):
            raise Refusal("Foreign/malformed lifecycle observation")
        if kind == "READY":
            if guest.terminal or guest.reaped:
                raise Refusal("Cannot revive terminal guest")
            guest.ready = True
        elif kind == "TERMINAL":
            guest.terminal = True
        elif kind == "REAPED":
            if not guest.terminal:
                raise Refusal("Reap cannot substitute for terminal observation")
            guest.reaped = True
        elif kind == "WRITERS_SETTLED":
            if not guest.reaped:
                raise Refusal("Writer settlement requires completed reap join")
            guest.writers_settled = True

    def cleanup(self):
        if self.cleanup_started:
            raise self.fail(Refusal("Cleanup is one-shot; no repeated lifecycle operations"))
        self.cleanup_started = True
        for guest in reversed(self.guests):
            if guest.capability is None:
                continue
            # A terminal observation suppresses the one permitted stop request.
            # Observation failure never invents absence or a numeric target.
            if not guest.terminal:
                try:
                    self.call("terminal", guest,
                              lambda: self.ports.observe(guest.capability, "TERMINAL"),
                              self.cleanup_end, True,
                              lambda raw: self.join(guest, "TERMINAL", raw))
                except Exception:
                    if not guest.terminal and not guest.stop_attempted and not self.time_failed:
                        def stop():
                            if guest.terminal or guest.reaped:
                                raise Refusal("Terminal capability cannot be signaled")
                            guest.stop_attempted = True
                            return self.ports.terminate_exact(guest.capability)
                        try:
                            self.call("stop", guest, stop, self.cleanup_end, True)
                        except Exception:
                            pass
                        if guest.stop_attempted:
                            try:
                                self.call("terminal_after_stop", guest,
                                          lambda: self.ports.observe(guest.capability, "TERMINAL"),
                                          self.cleanup_end, True,
                                          lambda raw: self.join(guest, "TERMINAL", raw))
                            except Exception:
                                pass
                # One separately reserved post-action observation, not polling.
            if guest.terminal and not guest.reaped:
                try:
                    self.call("reap", guest,
                              lambda: self.ports.observe(guest.capability, "REAPED"),
                              self.cleanup_end, True, lambda raw: self.join(guest, "REAPED", raw))
                except Exception:
                    pass
            if guest.reaped and not guest.writers_settled:
                try:
                    self.call("writers", guest,
                              lambda: self.ports.observe(guest.capability, "WRITERS_SETTLED"),
                              self.cleanup_end, True,
                              lambda raw: self.join(guest, "WRITERS_SETTLED", raw))
                except Exception:
                    pass

    def run(self):
        if self.started:
            raise self.fail(Refusal("One-shot controller: repeated/reentrant run"))
        self.started = True  # before clock, reservation or callback
        self.busy = True
        try:
            for guest in self.guests:
                def create():
                    guest.create_attempted = True
                    guest.create_uncertain = True
                    return self.ports.create_held(guest.role)

                def own(raw):
                    if type(raw) is CreationResult:
                        result = raw
                        raw = result.capability
                        if raw is None:
                            if not isinstance(result.error, Exception):
                                raise Refusal("Missing creation failure evidence")
                            guest.create_uncertain = False
                            self.fail(result.error)
                            return
                        if result.error is not None:
                            if not isinstance(result.error, Exception):
                                raise Refusal("Invalid creation failure evidence")
                            self.fail(result.error)
                    if raw is None or any(raw is other.capability for other in self.guests):
                        raise Refusal("Missing or duplicate held capability")
                    guest.capability = raw
                    guest.create_uncertain = False

                self.call("create", guest, create, self.launch_end, returned=own)
                def release():
                    guest.release_possible = True
                    return self.ports.release(guest.capability)
                self.call("release", guest, release, self.launch_end)
                raw = self.call("ready", guest, lambda: self.ports.observe(guest.capability, "READY"), self.launch_end)
                self.join(guest, "READY", raw)
            def exercise():
                self.exercise_attempted = True
                return self.ports.exercise(self.guests[0].capability, self.guests[1].capability)
            self.result = self.call("exercise", None, exercise, self.normal_end)
            self.exercise_returned = True
            if self.evidence_validator is not None:
                self.evidence_result = self.call("verify", None,
                    lambda: self.evidence_validator(self.result), self.normal_end)
            for guest in reversed(self.guests):
                self.call("quit", guest, lambda: self.ports.quit(guest.capability), self.cleanup_end)
        except Exception as error:
            self.fail(error)
        finally:
            self.cleanup()
            self.busy = False
        return self.summary()

    def summary(self):
        settled = all(g.capability is not None and g.terminal and g.reaped and g.writers_settled
                      for g in self.guests)
        return {"state": "HOST_COMPOSITION_COMPLETE" if self.primary is None and settled
                and self.exercise_returned else "INCOMPLETE", "native_evidence": False,
                "experiment_pass": False, "cleanup_settled": settled,
                "evidence_validation_returned": self.evidence_result is not None,
                "exercise_attempted": self.exercise_attempted,
                "primary": type(self.primary).__name__ if self.primary else None,
                "guests": [{"role": g.role, "owned": g.capability is not None,
                            "create_uncertain": g.create_uncertain, "ready": g.ready,
                            "release_possible": g.release_possible,
                            "stop_attempted": g.stop_attempted, "terminal": g.terminal,
                            "reaped": g.reaped, "writers_settled": g.writers_settled}
                           for g in self.guests]}
