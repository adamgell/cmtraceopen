const REPO = "adamgell/cmtraceopen";
const API = `https://api.github.com/repos/${REPO}`;

const workflows = [
  {
    id: "nightly-status",
    file: "cmtrace-nightly-signed.yml",
    title: "Nightly signed build",
  },
  {
    id: "windows-status",
    file: "codesign.yml",
    title: "Windows signed release",
  },
  {
    id: "release-status",
    file: "cmtrace-release.yml",
    title: "Release build",
  },
  {
    id: "ci-status",
    file: "cmtrace-ci.yml",
    title: "CI",
  },
];

const els = {
  nightly: document.querySelector("#nightly-release"),
  stable: document.querySelector("#stable-release"),
  runs: document.querySelector("#workflow-runs"),
  apiState: document.querySelector("#api-state"),
  refresh: document.querySelector("#refresh-button"),
  assetTemplate: document.querySelector("#asset-template"),
};

els.refresh.addEventListener("click", () => loadBuilds({ force: true }));

loadBuilds();

async function loadBuilds({ force = false } = {}) {
  const stamp = new Date().toLocaleString();
  els.apiState.textContent = force ? `Refreshing at ${stamp}.` : "Loading GitHub API data.";
  els.refresh.disabled = true;

  try {
    const [nightly, latest, runGroups] = await Promise.all([
      fetchMaybe(`${API}/releases/tags/nightly`),
      fetchJson(`${API}/releases/latest`),
      Promise.all(workflows.map(loadWorkflowRuns)),
    ]);

    renderRelease(els.nightly, nightly, {
      emptyTitle: "No nightly release yet",
      emptyBody: "The first successful nightly signed workflow will publish the mutable nightly prerelease.",
      fallbackHref: `https://github.com/${REPO}/actions/workflows/cmtrace-nightly-signed.yml`,
    });

    renderRelease(els.stable, latest, {
      emptyTitle: "No stable release found",
      emptyBody: "GitHub did not return a latest release.",
      fallbackHref: `https://github.com/${REPO}/releases`,
    });

    renderWorkflowRuns(runGroups);
    renderStatusCards(runGroups);
    els.apiState.textContent = `Updated ${new Date().toLocaleString()}.`;
  } catch (error) {
    els.apiState.textContent = `GitHub API error: ${error.message}`;
    renderError(els.nightly, error);
    renderError(els.stable, error);
    renderError(els.runs, error);
  } finally {
    els.refresh.disabled = false;
  }
}

async function loadWorkflowRuns(workflow) {
  const url = `${API}/actions/workflows/${encodeURIComponent(workflow.file)}/runs?branch=main&per_page=5`;
  try {
    const data = await fetchJson(url);
    return { ...workflow, runs: data.workflow_runs ?? [] };
  } catch (error) {
    if (error.message.startsWith("404")) {
      return { ...workflow, runs: [], error: "Workflow is not available on main yet." };
    }

    throw error;
  }
}

async function fetchJson(url) {
  const response = await fetch(url, {
    headers: {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });

  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }

  return response.json();
}

async function fetchMaybe(url) {
  const response = await fetch(url, {
    headers: {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });

  if (response.status === 404) {
    return null;
  }

  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }

  return response.json();
}

function renderRelease(target, release, empty) {
  target.classList.remove("loading-block");
  target.replaceChildren();

  if (!release) {
    target.append(emptyRelease(empty));
    return;
  }

  const summary = document.createElement("div");
  summary.className = "release-summary";

  const title = document.createElement("div");
  title.className = "release-title";
  title.append(el("strong", release.name || release.tag_name));
  title.append(chip(release.prerelease ? "pre-release" : "stable"));
  summary.append(title);

  const meta = document.createElement("div");
  meta.className = "release-meta";
  meta.append(
    el("span", `Tag ${release.tag_name}`),
    el("span", `Published ${formatDate(release.published_at || release.created_at)}`),
    link(`https://github.com/${REPO}/releases/tag/${release.tag_name}`, "Open on GitHub"),
  );
  summary.append(meta);

  if (release.target_commitish) {
    const commit = document.createElement("div");
    commit.className = "release-meta";
    commit.append(el("span", `Target ${release.target_commitish}`));
    summary.append(commit);
  }

  const groups = groupAssets(release.assets ?? []);
  for (const group of groups) {
    summary.append(assetSection(group.title, group.assets));
  }

  if (!groups.length) {
    summary.append(emptyRelease({
      emptyTitle: "No downloadable assets",
      emptyBody: "This release exists but does not have assets attached.",
      fallbackHref: release.html_url,
    }));
  }

  target.append(summary);
}

function renderWorkflowRuns(groups) {
  els.runs.classList.remove("loading-block");
  els.runs.replaceChildren();

  for (const group of groups) {
    const card = document.createElement("article");
    card.className = "run-card";
    card.append(el("h3", group.title));

    if (group.error) {
      card.append(el("p", group.error));
      els.runs.append(card);
      continue;
    }

    if (!group.runs.length) {
      card.append(el("p", "No runs found."));
      els.runs.append(card);
      continue;
    }

    for (const run of group.runs.slice(0, 4)) {
      const row = document.createElement("a");
      row.className = "run-line";
      row.href = run.html_url;
      row.innerHTML = `
        <span class="run-title">${escapeHtml(run.display_title || run.name || "Run")}</span>
        <span class="run-badge ${statusClass(run)}">${statusText(run)}</span>
      `;

      const time = document.createElement("span");
      time.className = "run-time";
      time.textContent = formatDate(run.run_started_at || run.created_at);

      const wrapper = document.createElement("div");
      wrapper.append(row, time);
      card.append(wrapper);
    }

    els.runs.append(card);
  }
}

function renderStatusCards(groups) {
  for (const group of groups) {
    const card = document.querySelector(`#${group.id}`);
    if (!card) {
      continue;
    }

    const latest = group.runs[0];
    const status = latest ? statusClass(latest) : "pending";
    card.className = `status-card ${status}`;
    card.querySelector("strong").textContent = latest ? statusText(latest) : group.error ? "Unavailable" : "No runs";
    card.querySelector(".meta").textContent = latest
      ? `${formatDate(latest.run_started_at || latest.created_at)} on ${latest.head_branch}`
      : group.error
        ? group.error
        : "No matching workflow runs found.";
  }
}

function groupAssets(assets) {
  const visible = assets
    .filter((asset) => !asset.name.endsWith(".sig"))
    .sort((a, b) => assetRank(a.name) - assetRank(b.name) || a.name.localeCompare(b.name));

  const groups = new Map();
  for (const asset of visible) {
    const title = assetGroup(asset.name);
    if (!groups.has(title)) {
      groups.set(title, []);
    }
    groups.get(title).push(asset);
  }

  return Array.from(groups, ([title, groupAssets]) => ({ title, assets: groupAssets }));
}

function assetSection(title, assets) {
  const section = document.createElement("section");
  section.className = "asset-section";
  section.append(el("h3", title));

  const list = document.createElement("div");
  list.className = "asset-list";

  for (const asset of assets) {
    list.append(assetCard(asset));
  }

  section.append(list);
  return section;
}

function assetCard(asset) {
  const node = els.assetTemplate.content.firstElementChild.cloneNode(true);
  node.href = asset.browser_download_url;
  node.querySelector(".asset-kind").textContent = assetKind(asset.name);
  node.querySelector("strong").textContent = assetLabel(asset.name);
  node.querySelector(".asset-meta").textContent = `${formatBytes(asset.size)} · ${formatDate(asset.updated_at || asset.created_at)}`;
  return node;
}

function emptyRelease({ emptyTitle, emptyBody, fallbackHref }) {
  const box = document.createElement("div");
  box.className = "empty-state";
  box.append(el("h3", emptyTitle), el("p", emptyBody));

  if (fallbackHref) {
    box.append(link(fallbackHref, "Open GitHub"));
  }

  return box;
}

function renderError(target, error) {
  target.classList.remove("loading-block");
  target.replaceChildren(emptyRelease({
    emptyTitle: "Could not load build data",
    emptyBody: error.message,
    fallbackHref: `https://github.com/${REPO}/actions`,
  }));
}

function assetGroup(name) {
  if (/macos|darwin|\.dmg$|\.app\.tar\.gz$/i.test(name)) {
    return "macOS";
  }

  if (/linux|appimage|\.deb$/i.test(name)) {
    return "Linux";
  }

  if (/arm64|aarch64/i.test(name)) {
    return "Windows arm64";
  }

  if (/x64|x86_64/i.test(name)) {
    return "Windows x64";
  }

  return "Other assets";
}

function assetKind(name) {
  if (/\.msi$/i.test(name)) {
    return "MSI";
  }

  if (/-setup\.exe$/i.test(name)) {
    return "Setup EXE";
  }

  if (/lite.*\.exe$/i.test(name)) {
    return "Lite EXE";
  }

  if (/\.exe$/i.test(name)) {
    return "Full EXE";
  }

  if (/\.dmg$/i.test(name)) {
    return "DMG";
  }

  if (/\.appimage$/i.test(name)) {
    return "AppImage";
  }

  if (/\.deb$/i.test(name)) {
    return "DEB";
  }

  if (/\.app\.tar\.gz$/i.test(name)) {
    return "App TAR";
  }

  if (/latest\.json$/i.test(name)) {
    return "Update JSON";
  }

  return "Asset";
}

function assetLabel(name) {
  return name
    .replace(/^CMTrace-Open[_-]?/i, "")
    .replace(/^Nightly[_-]?/i, "Nightly ")
    .replace(/_/g, " ");
}

function assetRank(name) {
  const kind = assetKind(name);
  return ["MSI", "Setup EXE", "Full EXE", "Lite EXE", "DMG", "App TAR", "DEB", "AppImage", "Update JSON", "Asset"].indexOf(kind);
}

function statusClass(run) {
  return run.conclusion || run.status || "pending";
}

function statusText(run) {
  const raw = run.conclusion || run.status || "pending";
  return raw.replace(/_/g, " ");
}

function formatDate(value) {
  if (!value) {
    return "unknown";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "unknown";
  }

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function formatBytes(value) {
  if (!Number.isFinite(value)) {
    return "unknown size";
  }

  const units = ["B", "KB", "MB", "GB"];
  let size = value;
  let unit = 0;

  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }

  return `${size.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function el(tag, text) {
  const node = document.createElement(tag);
  node.textContent = text;
  return node;
}

function link(href, text) {
  const node = document.createElement("a");
  node.href = href;
  node.textContent = text;
  return node;
}

function chip(text) {
  const node = document.createElement("span");
  node.className = "chip";
  node.textContent = text;
  return node;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#039;",
  }[char]));
}
