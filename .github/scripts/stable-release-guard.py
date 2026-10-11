"""Reject non-stable or unpublished releases before WinGet tooling/submission."""
import json
import os
import re
import subprocess
from urllib.parse import quote


def validate_tag(tag):
    if not isinstance(tag, str) or not re.fullmatch(r'v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', tag):
        raise ValueError('Expected a stable MAJOR.MINOR.PATCH tag with optional v prefix')


def validate_release(tag, release):
    validate_tag(tag)
    if (release.get('tag_name') != tag or release.get('draft') is not False
            or release.get('prerelease') is not False or not release.get('published_at')):
        raise ValueError('Expected the selected published, non-draft, non-prerelease release')


def main():
    tag = os.environ['TAG_NAME']
    # Validate before using the tag as an API path component.
    validate_tag(tag)
    repository = os.environ['GITHUB_REPOSITORY']
    response = subprocess.run(
        ['gh', 'api', f'repos/{repository}/releases/tags/{quote(tag, safe="")}'],
        check=False, capture_output=True, text=True, timeout=30)
    if response.returncode != 0:
        raise RuntimeError(f'Release lookup failed ({response.returncode}): {response.stderr.strip()}')
    validate_release(tag, json.loads(response.stdout))
    print(f'Validated published stable release {tag}')


if __name__ == '__main__':
    main()
