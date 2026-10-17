"""Finite image download/cache preparation, independent of experiment execution."""
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import ssl
import time
import urllib.parse
import urllib.error
import urllib.request


class DownloadError(Exception):
    pass


def https_url(url):
    if not isinstance(url, str) or len(url) > 4096 or any(ord(c) <= 32 for c in url):
        raise DownloadError("Invalid image URL")
    value = urllib.parse.urlsplit(url)
    if (value.scheme != "https" or not value.hostname or value.username is not None
            or value.password is not None or value.fragment):
        raise DownloadError("Image URL must be HTTPS without credentials or fragment")
    return url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DownloadError("Redirect refused: release must pin a direct image URL")


def open_https(url, timeout):
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"})
    return opener.open(request, timeout=timeout)


def download(spec, cache, seconds, verify, opener=open_https, clock=time.monotonic):
    """One attempt, explicit timeout; no retry, resume, redirect or decompression.

    Callers supply a validated, independently pinned manifest and file verifier.
    Timeout checks reject late results; they are not hard wall-clock containment.
    """
    if type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds <= 0:
        raise DownloadError("A finite positive download timeout is required")
    start = clock()
    if not math.isfinite(start) or not math.isfinite(start + seconds):
        raise DownloadError("Invalid initial clock/deadline")
    end = start + seconds
    last = start

    def remaining():
        nonlocal last
        now = clock()
        if not math.isfinite(now) or now < last or now >= end:
            raise DownloadError("Download clock regressed or deadline reached")
        last = now
        return end - now

    cache = Path(cache).absolute()
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = cache / (spec["image_sha256"] + ".qcow2")
    if os.path.lexists(target):
        actual, _ = verify(target, spec["image_bytes"])
        remaining()
        if actual != spec["image_sha256"]:
            raise DownloadError("Existing cache does not match; not overwritten")
        return target
    url = https_url(spec.get("image_url"))
    # Stable attempt path forbids implicit retry after incomplete effects.
    attempt = cache / (spec["image_sha256"] + ".attempt")
    attempt.mkdir(mode=0o700)
    part = attempt / "body.partial"
    receipt = {"state": "INCOMPLETE", "url": url, "requests": 0, "bytes": 0,
               "sha256": None, "primary": None, "secondary": [],
               "transport_partial": "NONE_OBSERVED", "deadline": end,
               "start": start, "published": False}
    digest = hashlib.sha256()
    response = None
    failure = None
    try:
        with open(part, "xb") as stream:
            timeout = min(60.0, remaining())
            receipt["requests"] = 1
            try:
                response = opener(url, timeout)
            except urllib.error.HTTPError as exc:
                response = exc
                receipt["transport_partial"] = "UNREAD_ERROR_RESPONSE"
                raise
            remaining()
            if response.status != 200 or response.geturl() != url:
                raise DownloadError("Unexpected response status or URL")
            headers = response.headers
            lengths = headers.get_all("Content-Length", [])
            encodings = headers.get_all("Content-Encoding", [])
            transfers = headers.get_all("Transfer-Encoding", [])
            if encodings and encodings != ["identity"]:
                raise DownloadError("Encoded image body refused")
            if transfers and (transfers != ["chunked"] or lengths
                              or not getattr(response, "chunked", False)):
                raise DownloadError("Unsupported transfer framing")
            if lengths and (len(lengths) != 1 or not lengths[0].isascii()
                            or not lengths[0].isdigit()
                            or int(lengths[0]) != spec["image_bytes"]):
                raise DownloadError("Conflicting/incorrect Content-Length")

            def retain(block):
                if type(block) is not bytes or len(block) > 1048576:
                    raise DownloadError("Unsupported returned body")
                receipt["bytes"] += len(block)
                digest.update(block)
                # At most expected size + one byte is read/retained.
                stream.write(block)
                if receipt["bytes"] > spec["image_bytes"]:
                    raise DownloadError("Image body exceeds declared size")

            while True:
                remaining()
                try:
                    block = response.read1(min(1048576, spec["image_bytes"] + 1 - receipt["bytes"]))
                except http.client.IncompleteRead as exc:
                    receipt["transport_partial"] = "EXPOSED_OUTER_PARTIAL"
                    try:
                        retain(exc.partial)
                    except Exception as retention_error:
                        exc.add_note("Partial retention failure: " + str(retention_error)[:2048])
                    raise
                except Exception:
                    receipt["transport_partial"] = "UNKNOWN_UNEXPOSED_BYTES"
                    raise
                retain(block)
                remaining()
                if not block:
                    break
            if receipt["bytes"] != spec["image_bytes"] or digest.hexdigest() != spec["image_sha256"]:
                raise DownloadError("Incomplete or wrong image body")
            stream.flush()
            os.fsync(stream.fileno())
            remaining()
        closing = response
        response = None
        closing.close()
        remaining()
        os.chmod(part, 0o444)
        remaining()
        # Atomic no-overwrite publication; a hard link does not copy the image.
        os.link(part, target)
        receipt["published"] = True
        remaining()
        receipt["state"] = "VERIFIED_IMAGE_CACHED"
    except Exception as exc:
        failure = exc
        receipt["primary"] = type(exc).__name__ + ": " + str(exc)[:2048]
    finally:
        receipt["sha256"] = digest.hexdigest()
        if response is not None:
            try:
                response.close()
            except Exception as exc:
                receipt["secondary"].append(type(exc).__name__ + ": " + str(exc)[:2048])
        # Failure receipt is best effort, not a promise of post-deadline durability.
        try:
            with open(attempt / "receipt.json", "x", encoding="utf-8") as out:
                json.dump(receipt, out, indent=2)
                out.write("\n")
        except Exception as exc:
            if failure is None:
                failure = exc
            else:
                failure.add_note("Secondary receipt failure: " + str(exc)[:2048])
    if failure is not None:
        raise failure
    return target
