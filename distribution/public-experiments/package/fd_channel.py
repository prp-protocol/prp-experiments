"""Bounded QMP I/O on one already-owned, connected, nonblocking socket FD.

No socket creation, peer discovery, descriptor duplication or implicit close.
The owner establishes peer provenance and exclusive descriptor ownership. Inode
checks detect some replacement, not hostile same-process descriptor races.
"""
import fcntl
import os
import select
import stat


class Refusal(Exception):
    pass


class Channel:
    def __init__(self, fd, identity, clock_ns, end_ns, *, calls, chunk_bytes,
                 fstat=os.fstat, getflags=lambda fd: fcntl.fcntl(fd, fcntl.F_GETFL),
                 poll_factory=select.poll, read=os.read, write=os.write):
        if (type(fd) is not int or fd < 0 or type(identity) is not tuple or len(identity) != 2
                or any(type(v) is not int or v < 0 for v in identity)
                or any(type(v) is not int or v <= 0 for v in (end_ns, calls, chunk_bytes))):
            raise Refusal('Exact FD identity, absolute deadline and finite reservations required')
        self.fd, self.identity, self.clock, self.end = fd, identity, clock_ns, end_ns
        self.call_limit, self.chunk_limit = calls, chunk_bytes
        self.fstat, self.getflags, self.poll_factory = fstat, getflags, poll_factory
        self.read, self.write = read, write
        self.calls = 0; self.busy = False; self.retired = False
        self.primary = None; self.revision = 0; self.last = None
        self.possible_write = False
        self.readiness = []  # at most call_limit records; preserve closure diagnostics

    def fail(self, error):
        self.revision += 1
        if self.primary is None: self.primary = error
        return self.primary

    def time(self, end, revision):
        value = self.clock()
        if (type(value) is not int or value < 0 or self.last is not None and value < self.last):
            raise Refusal('Invalid/regressed channel clock')
        self.last = value
        if value >= end: raise Refusal('Channel deadline reached')
        if self.retired: raise Refusal("Descriptor retired during callback")
        if revision != self.revision or self.primary is not None:
            raise self.primary or Refusal("Channel state changed")
        return value

    def check_fd(self):
        info = self.fstat(self.fd)
        if not stat.S_ISSOCK(info.st_mode) or (info.st_dev, info.st_ino) != self.identity:
            raise Refusal('Socket identity changed')
        flags = self.getflags(self.fd)
        if type(flags) is not int or not flags & os.O_NONBLOCK:
            raise Refusal('Nonblocking descriptor required')

    def operation(self, value, end, writing):
        if self.busy: raise self.fail(Refusal('Channel reentry'))
        if self.primary is not None: raise self.primary
        self.busy = True
        revision = self.revision
        try:
            if self.retired: raise Refusal('Descriptor retired')
            if type(end) is not int or not 0 < end <= self.end:
                raise Refusal('Original absolute phase bound required')
            size = len(value) if writing and type(value) is bytes else value
            if type(size) is not int or not 0 < size <= self.chunk_limit:
                raise Refusal('Channel chunk reservation exceeded')
            if writing and type(value) is not bytes: raise Refusal('Bytes required')
            if self.calls >= self.call_limit: raise Refusal('Channel call budget exhausted')
            self.calls += 1  # no retry/refund on failure
            self.time(end, revision)
            self.check_fd()
            poller = self.poll_factory()
            flag = select.POLLOUT if writing else select.POLLIN
            poller.register(self.fd, flag)
            now = self.time(end, revision)
            timeout = min((end-now)//1000000, 2147483647)
            if timeout <= 0: raise Refusal('Less than one poll millisecond remains')
            events = poller.poll(timeout)  # one bounded wait; EINTR is not retried
            self.time(end, revision)
            if (type(events) is not list or len(events) != 1 or type(events[0]) is not tuple
                    or len(events[0]) != 2 or events[0][0] != self.fd
                    or type(events[0][1]) is not int):
                raise Refusal('Missing or foreign readiness')
            mask = events[0][1]
            self.readiness.append((mask, writing, self.last))
            # A connected UNIX peer may close with unread input while its final
            # reply is still queued: POLLIN|POLLERR|POLLHUP. Drain that readable
            # prefix once. Neither the mask nor EOF substitutes for a QMP ACK.
            allowed = flag | select.POLLHUP
            if not writing and mask & select.POLLIN: allowed |= select.POLLERR
            if mask & ~allowed or not mask & (flag | select.POLLHUP):
                raise Refusal('Invalid/error readiness')
            if writing and mask & select.POLLHUP: raise Refusal('Peer hung up before write')
            self.check_fd()
            self.time(end, revision)  # last admission after all metadata callbacks
            if writing:
                self.possible_write = True
                return self.write(self.fd, value)
            return self.read(self.fd, size)
            # The QMP client owns returned-byte custody and post-I/O clock checks.
        except Exception as error:
            raise self.fail(error)
        finally:
            self.busy = False

    def recv_until(self, size, end_ns):
        return self.operation(size, end_ns, False)

    def send_until(self, raw, end_ns):
        return self.operation(raw, end_ns, True)

    def check_return(self):
        # QMP calls this only after retaining the returned bytes/count.
        if self.primary is not None: raise self.primary
        if self.retired: raise self.fail(Refusal('Descriptor retired during I/O'))

    def retire(self):
        self.retired = True  # before owner closes; never closes/reuses FD here
        self.revision += 1
