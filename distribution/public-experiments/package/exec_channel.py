"""Finite diagnostic channel for the held helper; EOF never proves exec success.

The child emits at most one native C int. Only the original error FD and pidfd
are owned here; gate closure belongs to C, plan descriptors to the caller.
No implicit reads, polls, retries, or closure before original-child reap.
"""
import ctypes
import os


class Refusal(Exception):
    pass


class Channel:
    def __init__(self, error_fd, pidfd, clock, end, *, read=os.read, close=os.close):
        fds = [x for x in (error_fd, pidfd) if x is not None]
        if (type(error_fd) is not int or any(type(x) is not int or x < 0 for x in fds)
                or len(set(fds)) != len(fds) or type(end) is not int or end <= 0):
            raise Refusal('Exact distinct descriptor ownership required')
        self.error_fd, self.pidfd = error_fd, pidfd
        self.clock, self.end, self.read, self.close = clock, end, read, close
        self.raw = b''; self.calls = 0; self.eof = False; self.errno = None
        self.primary = None; self.secondary = []; self.overflow = False
        self.last = None; self.clock_failed = False; self.busy = False; self.revision = 0
        self.close_attempted = set(); self.closed = set(); self.raw_times = []

    def fail(self, error):
        self.revision += 1
        if self.primary is None: self.primary = error
        elif len(self.secondary) < 8: self.secondary.append(error)
        else: self.overflow = True
        return error

    def tick(self, phase_end=None):
        try:
            value = self.clock()
        except Exception:
            self.clock_failed = True
            raise
        # Bounded latest clock pair, even if a callback records a new error.
        self.raw_times = (self.raw_times + [value])[-2:]
        if (type(value) is not int or value < 0 or value >= self.end
                or self.last is not None and value < self.last):
            self.clock_failed = True
            raise Refusal('Expired, regressed or invalid channel clock')
        self.last = value
        if self.clock_failed: raise Refusal('Temporal refusal is irreversible')
        if phase_end is not None and value >= phase_end:
            raise Refusal('Diagnostic launch phase expired')

    def begin(self, phase_end=None):
        if self.busy: raise self.fail(Refusal('Channel reentry'))
        self.busy = True
        revision = self.revision
        self.tick(phase_end)
        if revision != self.revision: raise Refusal('Clock callback failed/reentered')
        return revision

    def sample(self, phase_end=None):
        if phase_end is not None and (type(phase_end) is not int or not 0 < phase_end <= self.end):
            raise self.fail(Refusal("Invalid diagnostic phase bound"))
        if self.primary is not None: raise self.primary
        if self.eof or self.error_fd in self.close_attempted or self.calls >= ctypes.sizeof(ctypes.c_int)+2:
            raise self.fail(Refusal('Channel ended or call budget exhausted'))
        if self.busy: raise self.fail(Refusal('Channel reentry'))
        try:
            revision = self.begin(phase_end)
            self.calls += 1
            result = self.read(self.error_fd, ctypes.sizeof(ctypes.c_int)+1-len(self.raw))
            if type(result) is not bytes or len(result) > ctypes.sizeof(ctypes.c_int)+1-len(self.raw):
                raise Refusal('Unsupported/oversized channel return')
            self.raw += result  # custody before clock/sticky checks
            if not result: self.eof = True
            self.tick(phase_end)
            if self.revision != revision: raise Refusal('Read callback failed/reentered')
            size = ctypes.sizeof(ctypes.c_int)
            if len(self.raw) > size: raise Refusal('Excess diagnostic bytes')
            if self.eof:
                if not self.raw: return 'EOF_EXEC_UNKNOWN'
                if len(self.raw) != size: raise Refusal('Partial child diagnostic')
                self.errno = ctypes.c_int.from_buffer_copy(self.raw).value
                if self.errno <= 0: raise Refusal('Invalid child errno')
                raise OSError(self.errno, 'Held child reported launch failure')
            return 'PENDING'
        except Exception as error:
            self.fail(error)
            raise self.primary
        finally: self.busy = False

    def finish(self, *, reaped):
        if reaped is not True: raise self.fail(Refusal('Original child must be reaped before FD retirement'))
        if self.busy: raise self.fail(Refusal('Channel reentry'))
        # Each close is independently admitted. An uncertain close is never retried:
        # its descriptor number might already have been reused by another owner.
        for fd in (self.error_fd, self.pidfd):
            if fd is None or fd in self.close_attempted: continue
            try:
                revision = self.begin()
                self.close_attempted.add(fd)
                result = self.close(fd)
                if result is not None: raise Refusal('Invalid close return')
                self.closed.add(fd)
                self.tick()
                if self.revision != revision: raise Refusal('Close callback failed/reentered')
            except Exception as error: self.fail(error)
            finally: self.busy = False
        return {'attempted': sorted(self.close_attempted), 'closed': sorted(self.closed),
                'complete': all(fd is None or fd in self.closed for fd in (self.error_fd, self.pidfd)),
                'exec_proven': False, 'writers_settled': False}
