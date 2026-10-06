# CI Artifact Delivery Reference

## CMTrace Open example

For a Windows x64 artifact from a PR or issue lane:

```bash
gh run list --repo adamgell/cmtraceopen --branch <branch> --limit 10 \
  --json databaseId,status,conclusion,headSha,name,url

gh api repos/adamgell/cmtraceopen/actions/runs/<run-id>/artifacts \
  --jq '.artifacts[] | [.id,.name,.size_in_bytes,.expired,.archive_download_url] | @tsv'

gh run download <run-id> --repo adamgell/cmtraceopen \
  --name cmtrace-open-Windows-x64 --dir /tmp/cmtrace-artifact
```

If direct API download is needed:

```bash
GH_TOKEN=$(gh auth token)
curl -fsSL \
  -H "Authorization: Bearer $GH_TOKEN" \
  -H 'Accept: application/vnd.github+json' \
  -o artifact.zip \
  'https://api.github.com/repos/<owner>/<repo>/actions/artifacts/<artifact-id>/zip'
```

Inspect the archive before naming the deliverable:

```bash
unzip -l artifact.zip
file <payload>
shasum -a 256 <payload>
stat -f '%N %z bytes' <payload>       # macOS
sha256sum <payload>                   # Linux/Windows Git Bash alternative
```

## Portable-versus-installer rule

- `cmtrace-open.exe` or a CI-staged edition EXE: standalone/portable candidate.
- `*-setup.exe`: NSIS installer, not portable.
- `*.msi`: MSI installer, not portable.

A normal CI artifact named `cmtrace-open-Windows-x64` may contain only the bundled
MSI and NSIS installer. The artifact name does not establish portability. If the
portable executable was not uploaded, do not manufacture a portable claim by
renaming the installer. State the exact file that is available and the limitation.

## Evidence report

Report:

- source commit SHA and PR/branch;
- workflow run ID and artifact ID;
- target architecture;
- exact filename, size, SHA-256;
- whether signature/provenance was present;
- whether the binary was only extracted/inspected or actually run on Windows.

Do not claim runtime acceptance from a successful build or a PE header check.
