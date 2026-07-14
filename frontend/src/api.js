// Thin client for the PacketIQ backend API.

async function handleResponse(res) {
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.detail || `Request failed (${res.status})`);
  }
  return data;
}

export async function listPcaps() {
  return handleResponse(await fetch('/api/pcaps'));
}

export async function analyzeUpload(file) {
  const formData = new FormData();
  formData.append('file', file);
  return handleResponse(await fetch('/api/analyze/upload', { method: 'POST', body: formData }));
}

export async function analyzePath(path) {
  return handleResponse(await fetch('/api/analyze/path', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path }),
  }));
}

export async function getJob(jobId) {
  return handleResponse(await fetch(`/api/jobs/${jobId}`));
}

export async function getJobResult(jobId) {
  return handleResponse(await fetch(`/api/jobs/${jobId}/result`));
}

export async function listJobs(limit = 10) {
  return handleResponse(await fetch(`/api/jobs?limit=${limit}`));
}

export async function deleteJob(jobId) {
  return handleResponse(await fetch(`/api/jobs/${jobId}`, { method: 'DELETE' }));
}

export async function getConnections(jobId, params = {}) {
  const qs = new URLSearchParams(
    Object.entries(params).filter(([, v]) => v !== '' && v != null)
  ).toString();
  return handleResponse(await fetch(`/api/jobs/${jobId}/connections?${qs}`));
}

export async function getProtocolEvents(jobId, protocol, params = {}) {
  const qs = new URLSearchParams(
    Object.entries(params).filter(([, v]) => v !== '' && v != null)
  ).toString();
  return handleResponse(await fetch(`/api/jobs/${jobId}/${protocol}?${qs}`));
}

export async function searchConnections(jobId, query, params = {}) {
  return handleResponse(await fetch(`/api/jobs/${jobId}/connections/search`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, ...params }),
  }));
}

export async function getGeoip(jobId, limit = 100) {
  return handleResponse(await fetch(`/api/jobs/${jobId}/geoip?limit=${limit}`));
}

// Trigger a browser download of the markdown report.
export async function downloadReport(jobId, pcapName) {
  const res = await fetch(`/api/jobs/${jobId}/report`);
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || `Report failed (${res.status})`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `packetiq-report-${(pcapName || jobId).replace(/\.[^.]+$/, '')}.md`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// Poll a job until it finishes, reporting stage changes; returns the result payload.
export async function waitForJob(jobId, onStage) {
  let lastStage = null;
  for (;;) {
    const job = await getJob(jobId);
    if (job.status === 'completed') return getJobResult(jobId);
    if (job.status === 'failed') throw new Error(job.error_message || 'Analysis failed');
    if (job.stage && job.stage !== lastStage) {
      lastStage = job.stage;
      onStage?.(job.stage);
    }
    await sleep(1500);
  }
}

// Stream an answer over SSE; calls onToken per fragment, resolves with full text.
export async function askQuestionStream(jobId, question, onToken, viewContext = '') {
  const res = await fetch('/api/ask', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ job_id: jobId, question, view_context: viewContext }),
  });

  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || `Request failed (${res.status})`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let fullText = '';

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const events = buffer.split('\n\n');
    buffer = events.pop();

    for (const event of events) {
      const line = event.trim();
      if (!line.startsWith('data: ')) continue;
      const payload = JSON.parse(line.slice(6));
      if (payload.error) throw new Error(payload.error);
      if (payload.token) {
        fullText += payload.token;
        onToken?.(payload.token, fullText);
      }
      if (payload.done) return fullText;
    }
  }
  return fullText;
}
