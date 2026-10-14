"use strict";
const $ = id => document.getElementById(id);
let token = "", files = [], currentJob = null, pollTimer = null, pollFailures = 0;
const activeStates = new Set(["queued", "running", "cancelling"]);

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function error(message) { $("form-error").hidden = !message; $("form-error").textContent = message || ""; }
async function api(path, options = {}, retry = true) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.body ? 45000 : 15000);
  try {
    const response = await fetch(path, { ...options, signal: controller.signal, headers: { Authorization: `Bearer ${token}`, ...(options.body ? {"Content-Type": "application/json"} : {}), ...options.headers } });
    if (response.status === 401 && retry) {
      const sessionResponse = await fetch('/api/session', {signal: controller.signal});
      if (sessionResponse.ok) { token = (await sessionResponse.json()).token; return await api(path, options, false); }
    }
    if (!response.ok) { const body = await response.json(); const exc = new Error(body.error || `Request failed (${response.status})`); exc.status = response.status; throw exc; }
    return response;
  } catch (exc) {
    if (exc.name === 'AbortError') throw new Error('Server request timed out. Check that the server terminal is running, then refresh.');
    throw exc;
  } finally { clearTimeout(timer); }
}
function renderFiles() {
  $("files").replaceChildren();
  files.forEach((file, index) => {
    const row = element("div", undefined, "file-row");
    const remove = element("button", "×"); remove.type = "button"; remove.setAttribute("aria-label", `Remove ${file.name}`);
    remove.addEventListener("click", () => { files.splice(index, 1); renderFiles(); });
    row.append(element("span", file.name), element("small", `${(file.size / 1024).toFixed(1)} KiB`), remove);
    $("files").append(row);
  });
}
function addFiles(incoming) {
  const updated = [...files, ...incoming];
  if (updated.length > 8) return error("Choose at most 8 files.");
  if (updated.some(file => file.size === 0 || file.size > 8 * 1024 * 1024)) return error("Each file must contain 1 byte to 8 MiB.");
  if (updated.reduce((total, file) => total + file.size, 0) > 16 * 1024 * 1024) return error("Total file size must be at most 16 MiB.");
  files = updated; error(""); renderFiles();
}
$("file-input").addEventListener("change", event => { addFiles([...event.target.files]); event.target.value = ""; });
for (const type of ["dragenter", "dragover"]) $("dropzone").addEventListener(type, event => { event.preventDefault(); $("dropzone").classList.add("drag"); });
for (const type of ["dragleave", "drop"]) $("dropzone").addEventListener(type, event => { event.preventDefault(); $("dropzone").classList.remove("drag"); });
$("dropzone").addEventListener("drop", event => addFiles([...event.dataTransfer.files]));

function asBase64(file) {
  return new Promise((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result).split(",")[1]); reader.onerror = () => reject(new Error("Cannot read file")); reader.readAsDataURL(file); });
}
$("challenge-form").addEventListener("submit", async event => {
  event.preventDefault(); error(""); $("analyze").disabled = true;
  try {
    if (!files.length && !$("question").value.trim()) throw new Error("Add a question or at least one file.");
    const upload = await Promise.all(files.map(async file => ({ name: file.name, data: await asBase64(file) })));
    const response = await api("/api/jobs", { method: "POST", body: JSON.stringify({ question: $("question").value, prefix: $("prefix").value.trim(), target: $("target").value.trim(), deep: $("deep").checked, files: upload }) });
    const job = await response.json(); await selectJob(job.id); await history();
  } catch (exc) { error(exc.message); } finally { $("analyze").disabled = false; }
});
async function history() {
  const jobs = await (await api("/api/jobs")).json();
  $("history").replaceChildren();
  if (!jobs.length) $("history").append(element("p", "No investigations yet.", "muted"));
  for (const job of jobs) {
    const button = element("button", undefined, job.id === currentJob ? "selected" : "");
    button.append(element("span", job.title), element("small", `${job.status.toUpperCase()} · ${new Date(job.created * 1000).toLocaleDateString()}`));
    button.addEventListener("click", () => selectJob(job.id).catch(exc => error(exc.message)));
    $("history").append(button);
  }
}
async function selectJob(id) {
  currentJob = id; clearTimeout(pollTimer);
  pollFailures = 0;
  $("empty-state").hidden = true; $("job-view").hidden = false;
  await poll(id);
}
async function poll(id) {
  try {
    const job = await (await api(`/api/jobs/${id}`)).json();
    if (id !== currentJob) return;
    pollFailures = 0;
    renderJob(job);
    if (activeStates.has(job.status)) pollTimer = setTimeout(() => poll(id), 900);
    else await history();
  } catch (exc) { if (id === currentJob) { error(exc.message); if (++pollFailures < 5 && exc.status !== 404) pollTimer = setTimeout(() => poll(id), 3000); else { $("running-indicator").hidden = true; $("job-status").textContent = "CONNECTION LOST"; } } }
}
function renderJob(job) {
  $("job-status").textContent = job.status.toUpperCase(); $("job-status").dataset.status = job.status;
  $("job-title").textContent = job.title;
  $("cancel").hidden = !activeStates.has(job.status); $("cancel").disabled = job.status === "cancelling";
  $("running-indicator").hidden = !activeStates.has(job.status);
  $("job-error").hidden = !job.error; $("job-error").textContent = job.error || "";
  const result = job.result;
  if (job.status === 'completed' && result && !result.candidates.length) $("job-status").textContent = result.outcome === 'needs_solver' ? 'NEEDS SOLVER' : result.outcome === 'budget_exhausted' ? 'LIMIT REACHED' : 'NO MATCH';
  $("metric-artifacts").textContent = result?.stats.artifacts ?? job.events.filter(e => e.type === "artifact").length;
  $("metric-experiments").textContent = result?.stats.experiments ?? "—";
  $("metric-candidates").textContent = result?.candidates.length ?? job.events.filter(e => e.type === "candidate").length;
  $("metric-time").textContent = result ? `${result.stats.elapsed_seconds}s` : "—";
  $("events").replaceChildren(...job.events.map(event => element("div", event.message)));
  $("events").scrollTop = $("events").scrollHeight;
  $("result-sections").hidden = !result; $("result-notice").hidden = !result;
  $("no-candidates").hidden = !result || result.candidates.length > 0;
  $("candidate-list").replaceChildren();
  $("diagnostics").replaceChildren();
  if (!result) return;
  $("no-candidates").textContent = result.outcome === 'needs_solver' ? 'Analysis finished; this challenge needs a solving method beyond the implemented checks. This job is not frozen and no flag has been recovered.' : result.outcome === 'budget_exhausted' ? 'A configured analysis limit was reached. Review limits below; no flag was recovered.' : 'Analysis finished without a matching candidate. Review the exact flag prefix and diagnostic findings.';
  const suggestions = result.suggested_prefixes || [];
  if (suggestions.length && !suggestions.includes($("prefix").value.trim())) {
    const row = element('div', undefined, 'notice'); row.append(element('p', `Question suggests prefix: ${suggestions.join(', ')}. Current field: ${$("prefix").value.trim() || '(blank)'}.`));
    for (const prefix of suggestions) { const button = element('button', `Use ${prefix}`, 'secondary'); button.addEventListener('click', () => { $("prefix").value = prefix; error('Prefix updated. Click Rerun saved inputs below.'); }); row.append(button); }
    $("diagnostics").append(row);
  }
  for (const finding of result.diagnostics || []) { const card = element('div', undefined, 'notice'); card.append(element('strong', `${finding.file}${finding.line ? ':' + finding.line : ''}`), element('p', finding.message)); if (finding.evidence) card.append(element('code', finding.evidence)); card.append(element('p', finding.next_step)); $("diagnostics").append(card); }
  $("result-notice").textContent = result.verification_notice;
  for (const candidate of result.candidates) {
    const card = element("div", undefined, "candidate");
    const top = element("div", undefined, "candidate-header");
    const copy = element("button", "Copy", "secondary");
    copy.addEventListener("click", async () => { try { await navigator.clipboard.writeText(candidate.value); copy.textContent = "Copied"; setTimeout(() => copy.textContent = "Copy", 1800); } catch { error("Clipboard unavailable. Select and copy the candidate text."); } });
    top.append(element("span", `${candidate.status.toUpperCase()} · NOT PLATFORM VERIFIED`), copy);
    card.append(top, element("code", candidate.value), element("p", `Artifact ${candidate.artifact} · byte offset ${candidate.offset}`));
    for (const warning of candidate.warnings) card.append(element("p", warning, "warning"));
    const context = element("details"); context.append(element("summary", "Source context"), element("code", candidate.context)); card.append(context);
    $("candidate-list").append(card);
  }
  $("artifact-count").textContent = result.artifacts.length;
  $("artifacts").replaceChildren();
  for (const artifact of result.artifacts) {
    const row = element("div", undefined, "artifact");
    row.append(element("strong", `${artifact.id} · ${artifact.name}`), element("small", `${artifact.type} · ${artifact.bytes} bytes · entropy ${artifact.entropy} · ${artifact.parent ? `from ${artifact.parent} via ${artifact.step.op}` : "original input"}`), element("code", `SHA-256 ${artifact.sha256}`));
    $("artifacts").append(row);
  }
  const notes = [...result.notes, ...result.limits.map(note => `Limit: ${note}`), ...result.recommendations];
  $("notes").replaceChildren(...(notes.length ? notes : ["No additional notes."]).map(note => element("li", note)));
  $("native-section").hidden = !result.native_reports?.length;
  $("native-output").replaceChildren();
  for (const report of result.native_reports || []) { $("native-output").append(element("p", `${report.tool} · ${report.input} · exit ${report.exit_code}${report.timeout ? " · timed out" : ""}${report.truncated ? " · truncated" : ""}`), element("pre", report.output)); }
}
$("cancel").addEventListener("click", async () => { try { await api(`/api/jobs/${currentJob}/cancel`, { method: "POST", body: "{}" }); } catch (exc) { error(exc.message); } });
$("rerun").addEventListener('click', async () => {
  $("rerun").disabled = true; error('');
  try { const response = await api(`/api/jobs/${currentJob}/rerun`, {method:'POST', body:JSON.stringify({prefix:$("prefix").value.trim(),deep:$("deep").checked})}); await selectJob((await response.json()).id); await history(); }
  catch (exc) { error(exc.message); } finally { $("rerun").disabled = false; }
});
$("export").addEventListener("click", async () => {
  $("export").disabled = true;
  try { const response = await api(`/api/jobs/${currentJob}/export`); const url = URL.createObjectURL(await response.blob()); const link = element("a"); link.href = url; link.download = `apostrophe-${currentJob.slice(0, 8)}.zip`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
  catch (exc) { error(exc.message); } finally { $("export").disabled = false; }
});
$("new-job").addEventListener("click", () => { currentJob = null; clearTimeout(pollTimer); $("challenge-form").reset(); files = []; renderFiles(); error(""); $("job-view").hidden = true; $("empty-state").hidden = false; $("job-status").textContent = "READY"; $("job-status").dataset.status = ""; $("question").focus(); history().catch(exc => error(exc.message)); });
$("refresh-history").addEventListener("click", () => history().catch(exc => error(exc.message)));
async function init() {
  try { const response = await fetch("/api/session"); if (!response.ok) throw new Error("Local session unavailable"); const session = await response.json(); token = session.token; $("version").textContent = `v${session.version} · Connected`; $("tool-state").textContent = session.native ? `Passive adapters enabled: ${session.tools.filter(tool => tool.available).map(tool => tool.name).join(", ") || "none installed"}` : "Built-in analyzers enabled · native adapters off"; await history(); }
  catch (exc) { error(exc.message); $("version").textContent = "Connection failed"; }
}
init();
