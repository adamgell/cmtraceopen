"""Skip publication when this exact CMTrace Open version is already in winget."""

import json
import os
from pathlib import Path
import re
from urllib import error, parse, request


class GuardError(Exception):
    """A credential-free publication preflight failure."""


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise GuardError("API redirect refused")


def already_published(tag, token):
    version = tag.removeprefix("v")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version):
        raise GuardError("Expected a release version tag")
    if not token:
        raise GuardError("Required read-only API credential is unavailable")
    path = f"manifests/a/AdamGell/CMTraceOpen/{version}/AdamGell.CMTraceOpen.yaml"
    req = request.Request(
        "https://api.github.com/repos/microsoft/winget-pkgs/contents/" + parse.quote(path),
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "cmtraceopen-winget-publication-guard",
        },
        method="GET",
    )
    opener = request.build_opener(NoRedirect())
    try:
        with opener.open(req, timeout=20) as response:
            manifest = json.load(response)
    except error.HTTPError as failure:
        failure.close()
        if failure.code == 404:
            return False
        raise
    if not isinstance(manifest, dict) or manifest.get("type") != "file" or manifest.get("path") != path:
        raise GuardError("Unexpected upstream manifest metadata")
    return True


def main():
    try:
        exists = already_published(os.environ.get("TAG_NAME", ""), os.environ.get("GITHUB_TOKEN", ""))
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write(f"already_published={str(exists).lower()}\n")
    except error.HTTPError as failure:
        print(f"Publication check failed: HTTP {failure.code}; response body omitted")
        return 1
    except GuardError as failure:
        print(f"Publication check failed: {failure}")
        return 1
    except Exception:
        # API bodies and exception text must not expose the request credential.
        print("Publication check failed: unreadable API response, connection, or output error")
        return 1
    print("Version already exists in microsoft/winget-pkgs; skipping publication" if exists
          else "Version is not yet in microsoft/winget-pkgs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
