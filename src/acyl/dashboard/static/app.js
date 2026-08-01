const app = document.getElementById("app");
const healthPill = document.getElementById("health-pill");
const cacheHint = document.getElementById("cache-hint");

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || JSON.stringify(body);
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) return res.json();
  return res.text();
}

function toast(message) {
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = message;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function badge(text, cls = "") {
  return `<span class="badge ${cls}">${esc(text)}</span>`;
}

function route() {
  const hash = location.hash.replace(/^#\/?/, "");
  const [page, id, tab] = hash.split("/");
  if (!page || page === "") return { name: "home" };
  if (page === "scan") return { name: "scan" };
  if (page === "runs" && id) return { name: "run", id, tab: tab || "findings" };
  return { name: "home" };
}

function setActiveNav() {
  const r = route();
  document.querySelectorAll(".nav a").forEach((a) => {
    const href = a.getAttribute("href") || "";
    const active =
      (r.name === "home" && href === "#/") || (r.name === "scan" && href === "#/scan");
    a.classList.toggle("active", active);
  });
}

async function renderHome() {
  const runs = await api("/api/runs");
  const confirmed = runs.reduce((n, r) => n + (r.confirmed || 0), 0);
  const review = runs.reduce((n, r) => n + (r.needs_review || 0), 0);
  app.innerHTML = `
    <section class="hero">
      <h1>acyl</h1>
      <p>Local AppSec control surface. Browse scan runs, triage survivors, and launch new evaluations without leaving your machine.</p>
    </section>
    <section class="stats">
      <div class="stat"><div class="label">Runs</div><div class="value">${runs.length}</div></div>
      <div class="stat"><div class="label">Confirmed</div><div class="value">${confirmed}</div></div>
      <div class="stat"><div class="label">Needs review</div><div class="value">${review}</div></div>
      <div class="stat"><div class="label">Jobs</div><div class="value" id="job-count">—</div></div>
    </section>
    <section class="panel">
      <div class="panel-head">
        <h2>Recent runs</h2>
        <a class="btn primary" href="#/scan" data-link>New scan</a>
      </div>
      ${
        runs.length
          ? `<div class="table-wrap"><table>
            <thead><tr><th>Run</th><th>Target</th><th>Confirmed</th><th>Review</th><th>When</th></tr></thead>
            <tbody>
              ${runs
                .map(
                  (r) => `<tr>
                  <td class="mono"><a href="#/runs/${esc(r.id)}" data-link>${esc(r.id)}</a></td>
                  <td class="mono">${esc(shortPath(r.target_path))}</td>
                  <td>${badge(r.confirmed ?? 0, r.confirmed ? "confirmed" : "")}</td>
                  <td>${badge(r.needs_review ?? 0, r.needs_review ? "needs-review" : "")}</td>
                  <td class="mono">${esc(r.created_at || "—")}</td>
                </tr>`
                )
                .join("")}
            </tbody></table></div>`
          : `<div class="empty">No runs yet. Start with a scan of <span class="mono">fixtures/vulnerable-app</span>.</div>`
      }
    </section>
  `;
  const jobs = await api("/api/jobs");
  const jc = document.getElementById("job-count");
  if (jc) jc.textContent = String(jobs.length);
}

function shortPath(path) {
  if (!path) return "—";
  const parts = path.split(/[/\\]/);
  return parts.slice(-3).join("/");
}

async function renderScan() {
  app.innerHTML = `
    <section class="hero">
      <h1>New scan</h1>
      <p>Point acyl at a local checkout or git URL. Leave goals blank to use the bundled <span class="mono">goals/standard.md</span> default.</p>
    </section>
    <section class="panel">
      <form class="form" id="scan-form">
        <div class="field">
          <label for="path">Local path</label>
          <input id="path" name="path" type="text" placeholder="/targets/app or /path/to/repo" />
        </div>
        <div class="field">
          <label for="git_url">Git URL (optional)</label>
          <input id="git_url" name="git_url" type="text" placeholder="git@github.com:org/repo.git" />
        </div>
        <div class="field">
          <label for="goals">Goals file (optional — defaults to bundled standard.md)</label>
          <input id="goals" name="goals" type="text" placeholder="goals/minimal.md or leave empty" />
        </div>
        <div class="field">
          <label for="revision">Pinned revision (optional)</label>
          <input id="revision" name="revision" type="text" placeholder="commit sha / tag" />
        </div>
        <div class="checks">
          <label><input type="checkbox" name="no_antares" checked /> Skip Antares</label>
          <label><input type="checkbox" name="no_docker" checked /> No Docker sandbox</label>
          <label><input type="checkbox" name="llm_codeguard" /> CodeGuard LLM sweep</label>
        </div>
        <div>
          <button class="btn primary" type="submit" id="scan-submit">Start scan</button>
        </div>
        <p class="mono" id="scan-status" style="color: var(--muted)"></p>
      </form>
    </section>
  `;

  const form = document.getElementById("scan-form");
  const status = document.getElementById("scan-status");
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const fd = new FormData(form);
    const body = {
      path: fd.get("path") || null,
      git_url: fd.get("git_url") || null,
      goals: fd.get("goals") || null,
      revision: fd.get("revision") || null,
      no_antares: fd.get("no_antares") === "on",
      no_docker: fd.get("no_docker") === "on",
      llm_codeguard: fd.get("llm_codeguard") === "on",
    };
    if (!body.path && !body.git_url) {
      toast("Provide a local path or git URL");
      return;
    }
    const btn = document.getElementById("scan-submit");
    btn.disabled = true;
    status.textContent = "Queueing scan…";
    try {
      const job = await api("/api/scans", { method: "POST", body: JSON.stringify(body) });
      status.textContent = `Job ${job.id} ${job.status}`;
      pollJob(job.id, status, btn);
    } catch (err) {
      status.textContent = String(err.message || err);
      btn.disabled = false;
    }
  });
}

async function pollJob(jobId, statusEl, btn) {
  const tick = async () => {
    try {
      const job = await api(`/api/jobs/${jobId}`);
      statusEl.textContent = `Job ${job.id}: ${job.status}${job.run_id ? ` → ${job.run_id}` : ""}${
        job.error ? ` — ${job.error}` : ""
      }`;
      if (job.status === "completed" && job.run_id) {
        toast(`Scan complete: ${job.run_id}`);
        btn.disabled = false;
        location.hash = `#/runs/${job.run_id}`;
        return;
      }
      if (job.status === "failed") {
        toast(`Scan failed: ${job.error || "unknown error"}`);
        btn.disabled = false;
        return;
      }
      setTimeout(tick, 1200);
    } catch (err) {
      statusEl.textContent = String(err.message || err);
      btn.disabled = false;
    }
  };
  tick();
}

async function renderRun(id, tab) {
  const [run, findings] = await Promise.all([
    api(`/api/runs/${id}`),
    api(`/api/runs/${id}/findings`),
  ]);
  const confirmed = findings.filter((f) => f.state === "confirmed");
  const review = findings.filter((f) => f.state === "needs-review");
  const filter = tab === "review" ? review : tab === "all" ? findings : confirmed;
  const tabs = [
    ["findings", "Confirmed", confirmed.length],
    ["review", "Needs review", review.length],
    ["all", "All", findings.length],
    ["report", "Report", run.has_report ? "md" : "—"],
    ["coverage", "Coverage", (run.coverage || []).length],
  ];

  app.innerHTML = `
    <section class="hero">
      <h1 class="mono" style="font-size:1.6rem">${esc(run.id)}</h1>
      <p class="mono">${esc(run.target_path || "")}<br/>rev ${esc(run.pinned_revision || "—")}</p>
    </section>
    <section class="stats">
      <div class="stat"><div class="label">Confirmed</div><div class="value">${confirmed.length}</div></div>
      <div class="stat"><div class="label">Needs review</div><div class="value">${review.length}</div></div>
      <div class="stat"><div class="label">Total</div><div class="value">${findings.length}</div></div>
      <div class="stat"><div class="label">Rule gaps</div><div class="value">${(run.rule_gaps || []).length}</div></div>
    </section>
    <section class="panel">
      <div class="panel-head">
        <h2>Run detail</h2>
        <div style="display:flex;gap:.5rem;flex-wrap:wrap">
          ${tabs
            .map(
              ([key, label, count]) =>
                `<a class="btn ${tab === key || (!tab && key === "findings") ? "primary" : ""}" href="#/runs/${esc(
                  id
                )}/${key}" data-link>${label} (${count})</a>`
            )
            .join("")}
        </div>
      </div>
      <div id="run-body"></div>
    </section>
  `;

  const body = document.getElementById("run-body");
  if (tab === "report") {
    try {
      const md = await api(`/api/runs/${id}/report`);
      body.innerHTML = `<pre class="report">${esc(md)}</pre>`;
    } catch {
      body.innerHTML = `<div class="empty">No report for this run.</div>`;
    }
    return;
  }
  if (tab === "coverage") {
    const rows = run.coverage || [];
    body.innerHTML = rows.length
      ? `<div class="table-wrap"><table><thead><tr><th>Goal</th><th>Technique</th><th>State</th></tr></thead><tbody>
        ${rows
          .map(
            (c) =>
              `<tr><td class="mono">${esc(c.goal)}</td><td class="mono">${esc(c.technique)}</td><td>${badge(
                c.state,
                c.state
              )}</td></tr>`
          )
          .join("")}
      </tbody></table></div>`
      : `<div class="empty">No coverage rows.</div>`;
    return;
  }

  if (!filter.length) {
    body.innerHTML = `<div class="empty">No findings in this view.</div>`;
    return;
  }

  body.innerHTML = filter
    .map(
      (f) => `<article class="finding" data-id="${esc(f.id)}">
        <h3>${esc(f.title)}</h3>
        <div class="meta">
          ${badge(f.state, f.state)}
          ${badge(f.severity || "n/a", f.severity || "info")}
          ${badge(f.vuln_class)}
          <span class="mono">${esc(f.path || "—")}</span>
        </div>
        <p>${esc(f.summary || "")}</p>
        <ul class="evidence">
          ${(f.evidence || [])
            .map(
              (e) =>
                `<li><strong>${esc(e.kind)}</strong> ${esc(e.path || "")}${
                  e.line ? ":" + e.line : ""
                } — ${esc(e.note || "")}</li>`
            )
            .join("")}
        </ul>
        ${
          f.state === "confirmed"
            ? `<p style="margin-top:0.75rem"><button class="btn" data-fix="${esc(f.id)}">Autofix offline</button></p>`
            : ""
        }
      </article>`
    )
    .join("");

  body.querySelectorAll("[data-fix]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      try {
        const result = await api(`/api/findings/${btn.dataset.fix}/fix`, {
          method: "POST",
          body: JSON.stringify({ run_id: id, offline: true }),
        });
        toast(`${result.mode}: ${result.message}`);
      } catch (err) {
        toast(String(err.message || err));
      } finally {
        btn.disabled = false;
      }
    });
  });
}

async function render() {
  setActiveNav();
  const r = route();
  try {
    if (r.name === "scan") await renderScan();
    else if (r.name === "run") await renderRun(r.id, r.tab || "findings");
    else await renderHome();
  } catch (err) {
    app.innerHTML = `<div class="empty">Failed to load: ${esc(err.message || err)}</div>`;
  }
}

async function refreshHealth() {
  try {
    await api("/api/health");
    healthPill.textContent = "online";
    healthPill.classList.add("ok");
    cacheHint.textContent = "runs · ~/.cache/acyl/runs";
  } catch {
    healthPill.textContent = "offline";
    healthPill.classList.remove("ok");
  }
}

window.addEventListener("hashchange", render);
document.addEventListener("click", (ev) => {
  const a = ev.target.closest("a[data-link]");
  if (!a) return;
  // hash routing — allow default
});

refreshHealth();
render();
setInterval(refreshHealth, 15000);
