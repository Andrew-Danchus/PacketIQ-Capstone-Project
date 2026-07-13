# PacketIQ Redesign Plan

Assessment date: 2026-07-13. This document lists everything that should change before and during the redesign, ordered by phase. Phase 0 items are cleanup/bug fixes worth doing *before* any new features so the redesign starts from a stable base.

---

## Current-state assessment (short version)

The concept is solid: PCAP → Zeek → Postgres → detections + RAG → local LLM chat. But the implementation has a broken data path at its core, three copies of the same logic, dead code from an abandoned FAISS approach, and a frontend that reverse-engineers a human-readable string instead of consuming structured JSON. None of this is fatal — but building new features on top of it would multiply the mess.

**The single most important finding:** detection results never reach the RAG index or the database. `build_rag_index(job_id, *_args, **_kwargs)` in [backend/rag/pipeline.py](backend/rag/pipeline.py) silently discards the `detection_results` argument, and nothing ever inserts `run_detections()` output into the `detections` table — the only rows that land there are Zeek `notice.log` entries (mislabeled with hardcoded `"medium"` severity by `insert_notice`). So the AI chat literally cannot see the port scans / brute force / DDoS alerts the Detections tab displays.

---

## Phase 0 — Bug fixes & cleanup (do these first)

### Correctness bugs

- [ ] **Wire detections into the DB and RAG index.** Insert `run_detections()` results into the `detections` table (real severity, real timestamps), then let `build_rag_index` embed them. Remove the `*_args, **_kwargs` signature that swallows arguments.
- [ ] **Fix `schema.sql` duplicate index.** `idx_rag_chunks_job_created_at` is created twice (lines 111 and 118). The Postgres docker entrypoint runs init scripts with `ON_ERROR_STOP=1`, so a fresh volume fails to initialize. Anyone cloning the repo today gets a broken DB.
- [ ] **Fix the broken `backend/Dockerfile` CMD:** `CMD ["uvicorn", "api:app", "--host", "]` is an unterminated string. It only works because docker-compose overrides `command`.
- [ ] **Fix per-session job tracking.** `api.py` stores `_current_job_id` in module-level globals. Loading a "Past Session" in the UI restores the evidence text but *not* the job — so `/api/ask` retrieves RAG chunks from whatever PCAP was analyzed last, or 400s after a restart. Return `job_id` from `/api/analyze`, store it in the session, and pass it in `/api/ask`.
- [ ] **Fix frontend error handling:** the frontend reads `data.error` but FastAPI returns `data.detail`, so users always see the generic "Analysis failed" instead of the real reason.
- [ ] **Use Ollama `/api/chat` instead of `/api/generate`.** `OllamaClient.chat` flattens the messages into a single `"system: ...\nuser: ..."` string, so the system prompt loses its role semantics entirely.
- [ ] **Raise `num_ctx`.** 2048 tokens cannot hold the statistical summary + 8 RAG chunks + question; Ollama silently truncates from the top — which cuts off the system prompt first. Use 8192+ (llama3.2 supports it) and budget the prompt.
- [ ] **Clean the RAG context before prompting.** `query_rag_context` returns raw `RealDictRow` objects (including cosine distances) that get f-stringed into the prompt. Format them as plain text lines.
- [ ] **Fix the Overview "Processing time" display.** `processingSeconds` is a live loading counter, resets to 0 on each request, and is rendered inside an always-true `{ (...) }` expression. Either persist the real analysis duration returned by the backend or remove it.
- [ ] **Sanitize uploaded filenames.** `PCAP_DIR / upload.filename` and `PCAP_DIR / body["path"]` allow path traversal (`../../`). Use `Path(name).name` and validate extensions; reject absolute paths.

### Security / hygiene

- [ ] **Stop printing secrets:** `api.py` logs the full `DATABASE_URL` (with password) at startup of every analyze call.
- [ ] **Remove ~60 `print("DEBUG: ...")` statements** across api.py, main.py, detection.py, pipeline.py, client.py. Replace with the `logging` module at DEBUG level.
- [ ] **Tighten CORS** from `allow_origins=["*"]` to the frontend origin (and it's barely needed at all since Vite proxies `/api`).
- [ ] **Delete committed junk:** empty `.env` (add `.env.example` instead), `frontend/firebase-debug.log`, root `detection.json`, `output/detection.json`, `README.txt` (duplicates README.md). Fix `.gitignore` duplicates and the backslash entry `backend\ollama\__pycache__`.

### Dead code removal

- [ ] `backend/rag/retriever.py` and `backend/rag/vectorstore.py` — the abandoned FAISS/LangChain path; nothing imports them.
- [ ] `backend/rag/chunker.py` lower half (`build_chunks_from_logs`, `chunk_conn_records`, etc.) — only the DB-row chunk functions at the top are used.
- [ ] `backend/parsing/zeek_runner.py` and `backend/models/connection.py` — empty files.
- [ ] Drop `langchain`, `langchain-core`, `langchain-ollama`, `langchain-community`, `faiss-cpu` from requirements.txt (heavy, unused). Also pick **one** Postgres driver — `psycopg` (v3) is used by ingest, `psycopg2-binary` by the RAG pipeline; standardize on psycopg v3.
- [ ] Update README: it claims "FAISS + pgvector" and LangChain; neither is true after cleanup.

### Deduplication / structure

- [ ] **One copy of `load_json_log`** (currently in main.py, detection.py, chunker.py, ingest_logs.py) → `backend/parsing/zeek_logs.py`.
- [ ] **Move all backend code into `backend/`.** `api.py` and `main.py` live at repo root and import from `backend.*`; main.py is a CLI that duplicates the entire api.py pipeline. Extract the shared pipeline (zeek → ingest → detect → index → summarize) into one `backend/pipeline.py` used by both the API and the CLI.
- [ ] **Return structured JSON from `/api/analyze`** (stats object with top ports/services/states/DNS/etc.) instead of a prose string the frontend re-parses with regexes (`parseEvidence` in App.jsx). Keep the prose summary only as LLM context, generated server-side from the same structured object.
- [ ] **Split App.jsx (666 lines)** into components: `Sidebar`, `ChatView`, `OverviewView`, `DetectionsView`, plus an `api.js` client module and a small state store.
- [ ] **Batch embeddings.** `embed_texts` claims a `batch_size` param but embeds one text per HTTP request. Use Ollama's `/api/embed` with an array input — index builds are currently the slowest step for no reason.

### Detection-quality fixes (still Phase 0 — they're wrong, not just crude)

- [ ] Brute-force (conn.log) ignores its own `FAILED_STATES` filter — it alerts on *any* 10 connections to port 22/21/etc., so a legitimate SFTP batch job flags as "high" brute force. Require a failed-state ratio, and use `failed >= threshold` not `total >= 10`.
- [ ] DDoS triggers on ≥200 connections to one host in 60s *or* ≥50 sources — any moderately busy web server PCAP flags as "high" DDoS. Require both conditions, or weight by SYN-only/failed states.
- [ ] Deduplicate/merge alerts: one scanning IP can produce a port-scan alert, a DDoS alert on the target, and N brute-force alerts. Group by actor.
- [ ] Make thresholds configurable (env or a `detection_config.json`) instead of module constants.

---

## Phase 1 — Architecture changes for the redesign

- [ ] **Job-based API.** `POST /api/analyze` → returns `job_id` immediately, runs the pipeline in a background task; `GET /api/jobs/{id}` for status/progress (zeek → ingest → detect → index), `GET /api/jobs/{id}/summary`, `/detections`, `/connections?filter=...`. Sessions become server-side (the DB already has a `jobs` table — use it) instead of localStorage blobs.
- [ ] **Streaming chat.** `/api/ask` should stream tokens (SSE or WebSocket) — a 30s frozen "Analyzing..." is the single worst UX element right now. Render answers as markdown.
- [ ] **Hybrid retrieval instead of pure vector RAG.** Semantic search over prose chunks is a weak fit for questions like "how many connections hit port 445?" The DB already holds every connection — give the LLM tool access: (a) canned SQL templates (top talkers, port activity, time ranges, conversations between X and Y), or (b) real tool-calling with a read-only SQL tool. Keep vector search for fuzzy questions; route by question type.
- [ ] **Rewrite the system prompt** (see draft below) and pass detections + capture metadata into context, not just the stats summary.
- [ ] **Frontend rebuild:** proper component structure, a real chart library or clean CSS charts, virtualized tables for connection lists, dark SOC-style theme, keyboard-first filter bar.

### Draft system prompt

```
You are PacketIQ, a senior network security analyst performing PCAP forensics.
You are examining a single packet capture that has been parsed with Zeek. You
will receive: (1) a statistical summary of the capture, (2) automated detection
alerts (port scan / brute force / DDoS) with evidence, (3) log records retrieved
as relevant to the analyst's question, and (4) the analyst's question.

Rules of evidence:
- Base every claim on the provided data. Cite the specific IPs, ports, counts,
  timestamps, and log records that support it.
- Never invent hosts, ports, protocols, or events not present in the evidence.
- Distinguish clearly between OBSERVED facts, INFERRED interpretations, and
  RECOMMENDED actions — label them when the distinction matters.
- If the evidence is insufficient, say exactly what additional data would
  answer the question (e.g., "payloads are not available from conn.log").
- This is a static capture: you cannot see current state, and "block the IP"
  advice should be framed as follow-up for the analyst's environment.

Analysis approach:
- Interpret Zeek conn_state codes correctly (S0 = no reply, REJ = rejected,
  SF = normal completion, RSTO/RSTR = resets) and use them as signal.
- Consider base rates: high volume to port 443 is normal; high volume of S0
  to sequential ports is not. Say when something is likely benign.
- When relevant, map behavior to MITRE ATT&CK techniques by ID and name
  (e.g., T1046 Network Service Discovery) — only when the evidence supports it.

Output style:
- Lead with the direct answer to the question in one or two sentences.
- Follow with supporting evidence, then recommended next steps.
- Use defanged notation for suspicious external IPs/domains (e.g., 1.2.3[.]4).
- Be concise. No filler, no restating the question.
```

---

## Phase 2 — New features

### Copilot layout: persistent side-by-side chat

Currently Chat is one of several mutually-exclusive tabs — you lose the AI the moment you open Connections or Detections. Restructure the app shell so chat is a **persistent right-hand panel** (copilot style) that stays visible while the left/main region switches between Overview, Detections, Connections, and Protocols. This lets the analyst ask questions *about what they're looking at*.

Implementation notes:
- App shell becomes three columns: sidebar | main view area | chat panel. Chat is no longer in the view-tab rotation.
- Make the chat panel collapsible (toggle button) and resizable, so narrow screens can reclaim the space; remember the collapsed/width state in localStorage.
- **Context-aware questions (the payoff):** the chat should know which view is active and what's filtered. Pass the current view + active filters (e.g. "Connections filtered to 192.168.1.70:21") to `/api/ask` so a question like "is this normal?" has referent. Add quick-action chips per view — e.g. on a detection card, an "Ask AI about this alert" button that pre-fills the prompt with that alert's evidence; on a filtered connections table, "Explain these connections."
- Keep the existing SSE streaming + markdown rendering; only the layout and context-passing change.
- Responsive fallback: below a breakpoint, collapse the copilot back into a toggle/overlay so mobile still works.

### Live packet capture (the Wireshark-like feature)

Reality check: the backend container **cannot** sniff host NICs under Docker Desktop on Windows (WSL2/Hyper-V isolation). Two viable designs:

1. **Host capture agent (recommended).** A small Python agent that runs on the host with [Npcap](https://npcap.com/) installed, lists interfaces, captures with `scapy`/`pyshark` or shells out to `dumpcap`, writes rotating PCAP segments, and POSTs them to the backend (or streams packet summaries over WebSocket). The `start-packetiq.bat` script can launch it alongside compose.
2. **Dual-mode install:** run the backend natively on the host (no container) when capture is needed; keep Docker for db/ollama only.

Feature slice, in order:
- [ ] Interface enumeration + capture start/stop + BPF filter + ring buffer size, exposed in a new "Capture" tab.
- [ ] Live packet table (time, src, dst, proto, length, info) streamed over WebSocket, with pause/scroll-lock like Wireshark.
- [ ] Packet detail: click a row → dissection tree + hex/ASCII pane (tshark `-T json` gives full dissection for free).
- [ ] "Snapshot & analyze": stop capture → feed the rolling PCAP through the existing Zeek pipeline so live captures get the same detections/chat.
- [ ] Later: continuous mode — run Zeek/detections on each rotated segment, raise alerts in near-real-time.

### PCAP analysis depth (uses data you already collect but never show)

- [ ] **Connections explorer:** searchable, sortable, filterable table over the `connections` table (the DB is populated and the UI never queries it). Filter by IP/port/proto/state/time; click-through from any alert to its underlying flows.
- [ ] **Timeline view:** connections/alerts bucketed over the capture's timespan; brush to zoom a time range.
- [ ] **Conversation view:** talker pairs with bytes each way — the Wireshark "Conversations" equivalent.
- [ ] **HTTP/TLS/DNS detail tabs:** you ingest http_events, tls_events, dns_events and display none of them. Show URIs, user-agents, status codes; TLS versions/SNI/cipher (flag SSLv3/TLS1.0, self-signed certs); DNS NXDOMAIN rates.

### More detections (each is a self-contained module, good for iterating)

- [ ] DNS tunneling / DGA: query-name entropy, length, NXDOMAIN ratio, TXT volume.
- [ ] Beaconing: fixed-interval connections to one external host (low jitter, uniform size).
- [ ] Data exfiltration: outbound/inbound byte ratio outliers per host.
- [ ] Weak/legacy TLS and cleartext credentials (FTP/telnet/HTTP basic auth ports).
- [ ] JA3/JA3S fingerprinting via Zeek package for client identification.
- [ ] Consider running **Suricata** alongside Zeek for signature-based coverage; merge its EVE alerts into the same detections table.

### Enrichment & reporting

- [ ] GeoIP + ASN for external IPs (MaxMind GeoLite2, offline, free) — show country/org on every alert and in the connections table.
- [ ] Threat-intel tagging: offline feeds (abuse.ch SSLBL/Feodo) bundled at build time; optional VirusTotal lookup behind an API-key setting.
- [ ] IOC export: one click → CSV/JSON of suspicious IPs/domains/JA3 hashes.
- [ ] **Report generation:** "Export report" → markdown/PDF containing capture metadata, stats, detections with evidence, AI summary, and recommendations. This is the feature that makes it portfolio/demo gold.

---

## Suggested order of work

1. Phase 0 correctness bugs (detections→RAG, schema.sql, session/job_id, chat API) — ~the app starts being *truthful*.
2. Phase 0 cleanup/dedup/dead code — the codebase becomes safe to build on.
3. Phase 1 API restructure + streaming + system prompt — the core experience gets good.
4. Connections explorer + HTTP/TLS/DNS tabs (cheap wins, data already there). ✅ done
5. Copilot layout (persistent side-by-side chat) + context-aware questions.
6. GeoIP/ASN enrichment + report export (high-visibility, low-risk).
7. Live capture agent (biggest new feature, isolated from the rest).
8. New detections (DNS tunneling, beaconing, exfil) — iterate indefinitely.
