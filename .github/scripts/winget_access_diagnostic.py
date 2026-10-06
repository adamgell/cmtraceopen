"""Read-only metadata probe for the existing winget publication credential."""

import json
import os
import re
from urllib import error, request


FORK_ID = "R_kgDOR7rtDA"
FORK_NAME = "adamgell/winget-pkgs"
FIELDS = """id nameWithOwner owner { login } viewerPermission
            isArchived isDisabled isFork parent { nameWithOwner }"""
QUERY = """query WingetAccessDiagnostic {
  fork: repository(owner: "adamgell", name: "winget-pkgs") { %s }
  byId: node(id: "R_kgDOR7rtDA") { ... on Repository { %s } }
}""" % (FIELDS, FIELDS)


class DiagnosticError(Exception):
    """A fixed, credential-free diagnostic failure."""


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DiagnosticError("API redirect refused")


def fork_metadata(value):
    if not isinstance(value, dict):
        raise DiagnosticError("Expected fork metadata is unavailable")
    return {
        "id": value["id"],
        "nameWithOwner": value["nameWithOwner"],
        "owner": value["owner"]["login"],
        "viewerPermission": value["viewerPermission"],
        "isArchived": value["isArchived"],
        "isDisabled": value["isDisabled"],
        "isFork": value["isFork"],
        "parent": (value.get("parent") or {}).get("nameWithOwner"),
    }


def diagnose(token):
    # Neither API destinations nor the GraphQL query can be supplied by inputs.
    opener = request.build_opener(NoRedirect())
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "User-Agent": "cmtraceopen-winget-access-diagnostic",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    user_request = request.Request("https://api.github.com/user", headers=headers, method="GET")
    with opener.open(user_request, timeout=20) as response:
        user = json.load(response)
        scopes = {}
        for name in ("X-OAuth-Scopes", "X-Accepted-OAuth-Scopes"):
            value = response.headers.get(name)
            # Print only the requested scope headers, never arbitrary headers.
            if value is not None and not re.fullmatch(r"[a-zA-Z0-9_:, -]*", value):
                value = "[invalid scope header omitted]"
            scopes[name] = value
    graphql_request = request.Request(
        "https://api.github.com/graphql",
        data=json.dumps({"query": QUERY}).encode(),
        headers={**headers, "Content-Type": "application/json"}, method="POST",
    )
    with opener.open(graphql_request, timeout=20) as response:
        result = json.load(response)
    if result.get("errors"):
        raise DiagnosticError("GraphQL read failed; response body omitted")
    by_name = fork_metadata(result["data"]["fork"])
    by_id = fork_metadata(result["data"]["byId"])
    return {
        "authenticated_login": user["login"],
        "oauth_scope_headers": scopes,
        "fork_by_name": by_name,
        "fork_by_id": by_id,
        "fork_identity_matches": all(
            fork["id"] == FORK_ID and fork["nameWithOwner"] == FORK_NAME
            for fork in (by_name, by_id)
        ),
    }


def main():
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("Diagnostic failed: required credential is unavailable")
        return 1
    try:
        result = diagnose(token)
    except error.HTTPError as failure:
        print(f"Diagnostic failed: HTTP {failure.code}; response body omitted")
        return 1
    except DiagnosticError as failure:
        print(f"Diagnostic failed: {failure}")
        return 1
    except Exception:
        # Exception strings and API bodies can contain sensitive data.
        print("Diagnostic failed: unreadable API response or connection failure")
        return 1
    print(json.dumps(result, indent=2))
    return 0 if result["fork_identity_matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
