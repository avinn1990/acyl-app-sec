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
  const [runs, jobs] = await Promise.all([api("/api/runs"), api("/api/jobs")]);
  const confirmed = runs.reduce((n, r) => n + (r.confirmed || 0), 0);
  const review = runs.reduce((n, r) => n + (r.needs_review || 0), 0);
  const activeJobs = jobs.filter((j) => ["queued", "running", "stopping"].includes(j.status));
  app.innerHTML = `
    <section class="hero">
      <h1>Foundry Spec Repository Scanning</h1>
      <p>Local AppSec control surface. Browse scan runs, triage survivors, and launch new evaluations without leaving your machine.</p>
    </section>
    <section class="stats">
      <div class="stat"><div class="label">Runs</div><div class="value">${runs.length}</div></div>
      <div class="stat"><div class="label">Confirmed</div><div class="value">${confirmed}</div></div>
      <div class="stat"><div class="label">Needs review</div><div class="value">${review}</div></div>
      <div class="stat"><div class="label">Jobs</div><div class="value">${jobs.length}</div></div>
    </section>
    ${
      activeJobs.length
        ? `<section class="panel">
      <div class="panel-head"><h2>Active jobs</h2></div>
      <div class="table-wrap"><table>
        <thead><tr><th>Job</th><th>Status</th><th>Run</th><th>Actions</th></tr></thead>
        <tbody>
          ${activeJobs
            .map(
              (j) => `<tr>
              <td class="mono">${esc(j.id)}</td>
              <td>${badge(j.status, j.status === "stopping" ? "warn" : "info")}</td>
              <td class="mono">${
                j.run_id ? `<a href="#/runs/${esc(j.run_id)}" data-link>${esc(j.run_id)}</a>` : "—"
              }</td>
              <td class="actions">
                <button class="btn warn" data-stop-job="${esc(j.id)}" ${
                  j.status === "stopping" ? "disabled" : ""
                }>Force stop</button>
              </td>
            </tr>`
            )
            .join("")}
        </tbody></table></div>
      </section>`
        : ""
    }
    <section class="panel">
      <div class="panel-head">
        <h2>Recent runs</h2>
        <a class="btn primary" href="#/scan" data-link>New scan</a>
      </div>
      ${
        runs.length
          ? `<div class="table-wrap"><table>
            <thead><tr><th>Run</th><th>Target</th><th>State</th><th>Confirmed</th><th>Review</th><th>When</th><th>Actions</th></tr></thead>
            <tbody>
              ${runs
                .map(
                  (r) => `<tr>
                  <td class="mono"><a href="#/runs/${esc(r.id)}" data-link>${esc(r.id)}</a></td>
                  <td class="mono">${esc(shortPath(r.target_path))}</td>
                  <td>${badge(r.state || "—", r.state === "cancelled" ? "warn" : "")}</td>
                  <td>${badge(r.confirmed ?? 0, r.confirmed ? "confirmed" : "")}</td>
                  <td>${badge(r.needs_review ?? 0, r.needs_review ? "needs-review" : "")}</td>
                  <td class="mono">${esc(r.created_at || "—")}</td>
                  <td class="actions">
                    ${
                      r.active_job
                        ? `<button class="btn warn" data-stop-run="${esc(r.id)}" ${
                            r.active_job.status === "stopping" ? "disabled" : ""
                          }>Force stop</button>`
                        : ""
                    }
                    <button class="btn danger" data-delete-run="${esc(r.id)}">Delete</button>
                  </td>
                </tr>`
                )
                .join("")}
            </tbody></table></div>`
          : `<div class="empty">No runs yet. Start with a scan of <span class="mono">fixtures/vulnerable-app</span>.</div>`
      }
    </section>
  `;
  bindRunControls(app, () => render());
}

function shortPath(path) {
  if (!path) return "—";
  const parts = path.split(/[/\\]/);
  return parts.slice(-3).join("/");
}

function bindRunControls(root, onDone) {
  root.querySelectorAll("[data-stop-job]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      try {
        await api(`/api/jobs/${btn.dataset.stopJob}/stop`, { method: "POST", body: "{}" });
        toast(`Stopping job ${btn.dataset.stopJob}`);
        if (onDone) onDone();
      } catch (err) {
        toast(String(err.message || err));
        btn.disabled = false;
      }
    });
  });
  root.querySelectorAll("[data-stop-run]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      try {
        await api(`/api/runs/${btn.dataset.stopRun}/stop`, { method: "POST", body: "{}" });
        toast(`Stopping run ${btn.dataset.stopRun}`);
        if (onDone) onDone();
      } catch (err) {
        toast(String(err.message || err));
        btn.disabled = false;
      }
    });
  });
  root.querySelectorAll("[data-delete-run]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.deleteRun;
      if (!window.confirm(`Delete run ${id}? This removes local artifacts under ~/.cache/acyl/runs/.`)) {
        return;
      }
      btn.disabled = true;
      try {
        await api(`/api/runs/${id}`, { method: "DELETE" });
        toast(`Deleted ${id}`);
        if (onDone) onDone();
      } catch (err) {
        toast(String(err.message || err));
        btn.disabled = false;
      }
    });
  });
}

async function renderScan() {
  app.innerHTML = `
    <section class="hero">
      <h1>New scan</h1>
      <p>Point Foundry Spec Repository Scanning at a local checkout or git URL. Leave goals blank to use the bundled <span class="mono">goals/standard.md</span> default.</p>
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
          <label><input type="checkbox" name="no_antares" /> Skip Antares</label>
          <label><input type="checkbox" name="no_docker" checked /> No Docker sandbox</label>
          <label><input type="checkbox" name="llm_codeguard" /> CodeGuard LLM sweep</label>
        </div>
        <div>
          <button class="btn primary" type="submit" id="scan-submit">Start scan</button>
          <button class="btn warn" type="button" id="scan-stop" hidden>Force stop</button>
        </div>
        <p class="mono" id="scan-status" style="color: var(--muted)"></p>
      </form>
    </section>
  `;

  const form = document.getElementById("scan-form");
  const status = document.getElementById("scan-status");
  const stopBtn = document.getElementById("scan-stop");
  let activeJobId = null;
  stopBtn.addEventListener("click", async () => {
    if (!activeJobId) return;
    stopBtn.disabled = true;
    try {
      await api(`/api/jobs/${activeJobId}/stop`, { method: "POST", body: "{}" });
      status.textContent = `Job ${activeJobId}: stopping…`;
      toast("Force stop requested");
    } catch (err) {
      toast(String(err.message || err));
      stopBtn.disabled = false;
    }
  });
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
    stopBtn.hidden = false;
    stopBtn.disabled = false;
    status.textContent = "Queueing scan…";
    try {
      const job = await api("/api/scans", { method: "POST", body: JSON.stringify(body) });
      activeJobId = job.id;
      status.textContent = `Job ${job.id} ${job.status}`;
      pollJob(job.id, status, btn, stopBtn, () => {
        activeJobId = null;
      });
    } catch (err) {
      status.textContent = String(err.message || err);
      btn.disabled = false;
      stopBtn.hidden = true;
      activeJobId = null;
    }
  });
}

async function pollJob(jobId, statusEl, btn, stopBtn, onDone) {
  const tick = async () => {
    try {
      const job = await api(`/api/jobs/${jobId}`);
      statusEl.textContent = `Job ${job.id}: ${job.status}${job.run_id ? ` → ${job.run_id}` : ""}${
        job.error ? ` — ${job.error}` : ""
      }`;
      if (job.status === "completed" && job.run_id) {
        toast(`Scan complete: ${job.run_id}`);
        btn.disabled = false;
        if (stopBtn) stopBtn.hidden = true;
        if (onDone) onDone();
        location.hash = `#/runs/${job.run_id}`;
        return;
      }
      if (job.status === "failed" || job.status === "cancelled") {
        toast(
          job.status === "cancelled"
            ? `Scan stopped${job.run_id ? `: ${job.run_id}` : ""}`
            : `Scan failed: ${job.error || "unknown error"}`
        );
        btn.disabled = false;
        if (stopBtn) stopBtn.hidden = true;
        if (onDone) onDone();
        if (job.run_id && job.status === "cancelled") {
          location.hash = `#/runs/${job.run_id}`;
        }
        return;
      }
      setTimeout(tick, 1200);
    } catch (err) {
      statusEl.textContent = String(err.message || err);
      btn.disabled = false;
      if (stopBtn) stopBtn.hidden = true;
      if (onDone) onDone();
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
      <p class="mono">${esc(run.target_path || "")}<br/>rev ${esc(run.pinned_revision || "—")} · state ${esc(
        run.state || "—"
      )}</p>
      <div class="actions" style="margin-top:1rem">
        ${
          run.active_job
            ? `<button class="btn warn" data-stop-run="${esc(id)}" ${
                run.active_job.status === "stopping" ? "disabled" : ""
              }>Force stop</button>`
            : ""
        }
        <button class="btn danger" data-delete-run="${esc(id)}">Delete run</button>
        <a class="btn" href="#/" data-link>Back to runs</a>
      </div>
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

  bindRunControls(app, () => {
    location.hash = "#/";
    render();
  });

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
