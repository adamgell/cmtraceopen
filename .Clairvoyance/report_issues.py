#!/usr/bin/env python3
import subprocess, json

resp = subprocess.getoutput("cd /Users/Adam.Gell/repo/cmtraceopen && gh issue list --state open -L 100 --json number,title,state,url,labels,assignees,body")
try:
    issues = json.loads(resp)
except:
    issues = []

out_lines = []
out_lines.append("# adamgell/cmtraceopen - Full Open Issues Report")
total = len(issues)
out_lines.append("**Total: %d open issues**" % total)
out_lines.append("")

lanes = {"SCCM": [], "Intune": [], "Windows": [], "Other": []}
for i in issues:
    ln = ",".join(l.get("name", "").lower() for l in i.get("labels", []))
    if "sccm" in ln or "cmg" in ln or "pxe" in ln or "osd" in ln:
        lanes["SCCM"].append(i)
    elif "intune" in ln or "cnpp" in ln or "esm" in ln or "esp" in ln:
        lanes["Intune"].append(i)
    elif "windows" in ln or "winget" in ln or "dsregcmd" in ln or "msi" in ln or "autoloopit" in ln.replace(" ", "") or "event" in ln:
        lanes["Windows"].append(i)
    else:
        lanes["Other"].append(i)

for lane_name, items in sorted(lanes.items()):
    if not items:
        continue
    out_lines.append("### %s (%d issues)" % (lane_name, len(items)))
    out_lines.append("")
    for i in items:
        assign = ", ".join(a.get("login", "") for a in i.get("assignees", []))
        labels = ", ".join(l.get("name", "") for l in i.get("labels", []))
        
        body_str = str(i.get("body", "")).strip()
        first_line = ""
        if body_str:
            blines = [l.strip() for l in body_str.split("\n") if l.strip()]
            if blines:
                first_line = blines[0][:300]
        
        out_lines.append("#### #%d: %s" % (i["number"], i["title"]))
        out_lines.append("- **Labels:** `%s`" % labels)
        if assign:
            out_lines.append("- **Assigned to:** `@%s`" % assign)
        if first_line and len(first_line) > 20:
            out_lines.append("- **Summary:** %s..." % first_line[:250])
        elif first_line:
            out_lines.append("- **Summary:** %s" % first_line)
        out_lines.append("")

out_lines.append("---")
rv = subprocess.getoutput("cd /Users/Adam.Gell/repo/cmtraceopen && gh repo view --json stargazerCount,forkCount,primaryLanguage,pushedAt,defaultBranchRef")
rv_json = {}
if rv.strip():
    try:
        rv_json = json.loads(rv)
    except:
        pass
lines = ["**Repo Stats**: Rust | Stars: %d | Forks: %d | Main: %s" % (
    rv_json.get("stargazerCount", 0), 
    rv_json.get("forkCount", 0),
    str(rv_json.get("defaultBranchRef", {}).get("name", "main")))
]
out_lines.append(lines[0])

print("\n".join(out_lines))
