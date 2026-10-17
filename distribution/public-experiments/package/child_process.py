"""Exact retained-child wait/signal primitives. No spawn or PID discovery.

Only a future exclusive fork/reaper port can provide the original child relation.
Constructing this object from a number is NOT evidence of that relation. No CLI
exposes this API and experiment run remains refusing without the complete port.
"""
import math
import os
import signal


class Refusal(Exception):
    pass


class Child:
    def __init__(self, original_pid, retained_pidfd, clock, end, *, waitid=os.waitid,
                 send=signal.pidfd_send_signal):
        if type(original_pid) is not int or original_pid <= 0:
            raise Refusal("Original positive fork-return PID required")
        if retained_pidfd is not None and (type(retained_pidfd) is not int or retained_pidfd < 0):
            raise Refusal("Retained exact pidfd or explicit absence required")
        if type(end) not in (int, float) or not math.isfinite(end):
            raise Refusal("Original absolute deadline required")
        self.pid = original_pid
        self.pidfd = retained_pidfd
        self.clock, self.end = clock, end
        self.waitid, self.send = waitid, send
        self.last = None
        self.failed_clock = False
        self.primary = None
        self.secondary = []
        self.overflow = False
        self.busy = False
        self.revision = 0
        self.authority_lost = False
        self.signal_attempted = False
        self.signal_returned = False
        self.terminal = None
        self.reaped = False
        self.wait_attempts = 0
        self.raw_wait = []  # at most one observe, one post-action observe, one reap
        self.raw_signal = None

    def fail(self, error):
        self.revision += 1
        if self.primary is None:
            self.primary = error
        elif error is not self.primary:
            if len(self.secondary) < 8:
                self.secondary.append(error)
            else:
                self.overflow = True
        return error

    def time(self, revision):
        try:
            value = self.clock()
        except Exception as error:
            self.failed_clock = True
            raise self.fail(error)
        if (type(value) not in (int, float) or not math.isfinite(value)
                or self.failed_clock or (self.last is not None and value < self.last)):
            self.failed_clock = True
            raise self.fail(Refusal("Invalid/regressed clock"))
        self.last = value
        if value >= self.end:
            raise self.fail(Refusal("Absolute cleanup deadline reached"))
        if revision != self.revision:
            raise self.primary

    def begin(self):
        if self.busy:
            raise self.fail(Refusal("Reentrant child operation"))
        self.busy = True
        revision = self.revision
        try:
            self.time(revision)
            if self.authority_lost or self.reaped:
                raise Refusal("Child action authority retired or unknown")
        except Exception as error:
            self.busy = False
            raise self.fail(error)
        return revision

    def decode(self, raw):
        if raw is None:
            return None  # WNOHANG: no event, not proof of liveness
        fields = (raw.si_pid, raw.si_signo, raw.si_code, raw.si_status, raw.si_uid)
        if any(type(x) is not int for x in fields) or fields[0] != self.pid or fields[1] != signal.SIGCHLD:
            raise Refusal("Foreign/invalid wait observation")
        code, status = fields[2:4]
        if code == os.CLD_EXITED:
            if not 0 <= status <= 255:
                raise Refusal("Invalid exit status")
        elif code in (os.CLD_KILLED, os.CLD_DUMPED):
            if status not in signal.valid_signals() or status <= 0:
                raise Refusal("Invalid termination signal")
        else:
            raise Refusal("Stop/continue/unknown event is not terminal")
        return fields

    def wait(self, reap=False):
        revision = self.begin()
        try:
            if type(reap) is not bool or (reap and self.terminal is None):
                raise Refusal("Reap requires prior exact terminal evidence")
            if self.wait_attempts >= 3:
                raise Refusal("Finite wait allowance exhausted")
            options = os.WEXITED | os.WNOHANG | (0 if reap else os.WNOWAIT)
            self.wait_attempts += 1
            try:
                raw = self.waitid(os.P_PID, self.pid, options)
            except Exception as error:
                # An ambiguous consuming wait can have reaped. Never reconstruct.
                if reap or isinstance(error, ChildProcessError):
                    self.authority_lost = True
                raise
            self.raw_wait.append(raw)
            try:
                terminal = self.decode(raw)
                if terminal is not None:
                    if self.terminal is not None and terminal != self.terminal:
                        raise Refusal("Terminal identity/status changed")
                    self.terminal = terminal  # suppress signal even on late return
                    if reap:
                        self.reaped = True  # retire before clocks/persistence
            except Exception:
                self.authority_lost = True
                raise
            self.time(revision)
            return terminal
        except Exception as error:
            raise self.fail(error)
        finally:
            self.busy = False

    def terminate(self):
        revision = self.begin()
        try:
            if self.terminal is not None or self.signal_attempted:
                raise Refusal("Terminal child or already attempted exact signal")
            if self.pidfd is None:
                raise Refusal("No retained pidfd; original-child wait only, no numeric signal fallback")
            self.signal_attempted = True  # before potential side effect
            self.raw_signal = self.send(self.pidfd, signal.SIGKILL, None, 0)
            self.signal_returned = True
            self.time(revision)
            if self.raw_signal is not None:
                raise Refusal("Unexpected pidfd_send_signal return")
            # Request accepted, not terminal/reaped/writer settlement.
        except Exception as error:
            raise self.fail(error)
        finally:
            self.busy = False

    def observation(self, kind):
        """Bridge exact process facts to the existing controller capability join."""
        from two_guest import Observation
        if kind not in ("TERMINAL", "REAPED"):
            raise Refusal("Process wait cannot establish QMP readiness or writer settlement")
        result = self.wait(reap=kind == "REAPED")
        if result is None:
            raise Refusal("No terminal event observed")
        return Observation(self, kind)
