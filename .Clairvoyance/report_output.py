#!/usr/bin/env python3
import subprocess, json, sys

lines = []

# Open PRs
prs_resp = subprocess.getoutput("cd /Users/Adam.Gell/repo/cmtraceopen && gh pr list --state open -L 40 --json number,title,state,url,headRefName,reviewDecision")
try:
    prs = json.loads(prs_resp)
except:
    prs = []

lines.append("# adamgell/cmtraceopen — GitHub Report\n")
lines.append("## Open Pull Requests (10 pending review)")
lines.append("")

for p in prs[:12]:
    rdec = p.get('reviewDecision', 'NO_REVIEW') or 'NO_REVIEW'
    lines.append(f"- #{p['number']} `{rdec}` — {p['title'].strip()[:75]}")

lines.append("")
lines.append("## Recently Merged PRs (latest)")
lines.append("")

merged_resp = subprocess.getoutput("cd /Users/Adam.Gell/repo/cmtraceopen && gh pr list --state merged -L 20 --json number,title,mergeCommit,headRefName")
try:
    merged = json.loads(merged_resp)
except:
    merged = []

for p in merged[:8]:
    mc = p.get('mergeCommit', {})
    oid = mc.get('oid', '?')[:8] if isinstance(mc, dict) else '?'
    lines.append(f"- #{p['number']} `[{oid}]` — {p['title'].strip()[:75]}")

lines.append("")
lines.append("## Milestones\n")
ms_resp = subprocess.getoutput("cd /Users/Adam.Gell/repo/cmtraceopen && gh api repos/adamgell/cmtraceopen/milestones --jq '.[] | \"\\(.number): \\(.title) — \\(.closed_issues) closed, \\(.open_issues) open\"'")
try:
    for line in ms_resp.strip().split('\n'):
        lines.append(f"  - {line}")
except:
    lines.append("  - (could not parse milestones)")

lines.append("")
lines.append("## Open Issues\n")
issues_resp = subprocess.getoutput("cd /Users/Adam.Gell/repo/cmtraceopen && gh issue list --state open -L 100 --json number,title,labels,assignees")
try:
    issues = json.loads(issues_resp)
except:
    issues = []

for i in issues[:25]:
    assign = ", ".join(a.get('login', '') for a in i.get('assignees', []))
    labels = " | ".join(l.get('name', '') for l in i.get('labels', []))
    if assign:
        lines.append(f"- #{i['number']} - {i['title'].strip()[:70]} (`{assign}`)")
    else:
        lines.append(f"- #{i['number']} - {i['title'].strip()[:70]}")

lines.append("")
lines.append("## Repository Stats\n")
rv_resp = subprocess.getoutput("cd /Users/Adam.Gell/repo/cmtraceopen && gh repo view --json stargazerCount,forkCount,primaryLanguage,pushedAt,defaultBranchRef")
try:
    rv = json.loads(rv_resp)
    lines.append(f"- Language: `{rv.get('primaryLanguage', {}).get('name','?')}`\n")
    lines.append(f"- Stars: ⭐ {rv['stargazerCount']} | Forks: 🍴 {rv['forkCount']}\n")
    lines.append(f"- Default branch: `{rv['defaultBranchRef']['name']}`\n")
except:
    lines.append("  (could not parse repo view)")

# Print all lines joined with newline
output = '\n'.join(lines)
print(output)
