# PacketIQ

**Transform raw packet capture files into structured, AI-powered network intelligence.**

PacketIQ is a full-stack network analysis platform that ingests PCAP files, parses them with Zeek, stores the results in a PostgreSQL database, and lets you interrogate the traffic through a conversational AI interface powered by a local LLM (Ollama). It also automatically detects port scans, DDoS patterns, and brute-force attempts.

---

## Features

- **PCAP ingestion** — upload via file picker, drag-and-drop paste, or file path
- **Zeek-powered parsing** — extracts connections, DNS, HTTP, TLS, and anomaly events
- **AI chat interface** — ask natural-language questions about any traffic capture
- **RAG pipeline** — retrieves relevant log records and detection alerts as LLM context via pgvector
- **Traffic Overview** — stat cards, bar charts for top services/ports, connection-state breakdown, DNS queries, and weird events
- **Threat Detection** — automatic identification of port scans, DDoS, and brute-force attacks with severity ratings and remediation recommendations
- **Copilot chat** — a persistent side-by-side AI panel that stays open while you browse the tabs; it knows which view and filters are active, so you can ask "is this normal?" about what's on screen. "Ask AI about this" chips on detections and filtered connections pre-fill the question
- **Connections explorer** — searchable, filterable, paged table over every connection, plus an **AI search** box that turns plain English ("failed SSH from 192.168.1.70") into filters (hallucinated IPs are validated away)
- **Protocol detail** — dedicated DNS, HTTP, and TLS tables with full-text search; weak TLS versions and HTTP error codes are highlighted
- **GeoIP/ASN enrichment** — external hosts annotated with country and network owner (optional MaxMind GeoLite2 databases; degrades to public/private classification without them)
- **Report export** — one click downloads a full markdown report (executive summary, stats, detections with evidence)
- **Session history** — past analyses stored server-side and reloadable from any browser

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 19, Vite 8 |
| Backend API | FastAPI, Uvicorn (Python) |
| Database | PostgreSQL 16 + pgvector (HNSW index) |
| LLM | Ollama (`llama3.2`) |
| Embeddings | `nomic-embed-text` via Ollama |
| Packet Parsing | Zeek |
| Containerization | Docker Compose |

---

## Architecture

```
┌──────────────┐     HTTP      ┌─────────────────┐
│   Browser    │ ◄──────────► │  FastAPI Backend │
│  (React/Vite)│  :5173/:8000  │   (port 8000)   │
└──────────────┘               └────────┬────────┘
                                        │
                    ┌───────────────────┼───────────────────┐
                    │                   │                   │
             ┌──────▼──────┐   ┌───────▼──────┐   ┌───────▼──────┐
             │  PostgreSQL  │   │    Ollama     │   │    Zeek       │
             │  + pgvector  │   │  (LLM + emb) │   │  (in-process) │
             │  (port 55432)│   │  (port 11434) │   └──────────────┘
             └─────────────┘   └──────────────┘
```

**Request flow for a PCAP upload:**
1. Frontend POSTs the file to `/api/analyze/upload` (or a known filename to `/api/analyze/path`) and immediately receives a `job_id`
2. The pipeline runs as a background job — Zeek parsing, threat detection, DB ingestion, RAG indexing — while the frontend polls `GET /api/jobs/{id}` and shows each stage
3. On completion, `GET /api/jobs/{id}/result` returns structured traffic stats, detections, and the evidence summary; sessions live server-side, so past analyses can be reloaded from any browser
4. `POST /api/ask` streams the AI answer over SSE. Context is hybrid: exact SQL aggregates targeted at the question (IPs, ports, DNS/HTTP/TLS keywords) plus semantically retrieved log chunks from pgvector
5. `GET /api/jobs/{id}/connections` serves filtered, paged connection records for exploration

### Repository layout

```
backend/
  api.py          FastAPI app (upload, analyze, ask)
  cli.py          Interactive terminal client (python -m backend.cli)
  pipeline.py     Shared pipeline: Zeek → detect → ingest → RAG index → stats
  config.py       Environment configuration and logging
  parsing/        Zeek runner, JSON log loader, traffic summarizer
  detection/      Port scan / DDoS / brute force detection engine
  db/             Postgres schema and ingestion
  ollama/         LLM client, system prompt, analysis service
  rag/            Embedding pipeline and pgvector retrieval
frontend/
  src/            React app (Sidebar, Chat, Overview, Detections views)
scripts/          Standalone offline analysis tools
```

---

## Prerequisites

- [Docker Desktop](https://docs.docker.com/get-docker/) (Windows)
- ~8 GB of free disk space (for the Ollama model weights)

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/PacketIQ-Capstone-Project.git
cd PacketIQ-Capstone-Project
```

### 2. Start PacketIQ

Double-click **`start-packetiq.bat`** (or run it from a terminal):

```bat
start-packetiq.bat
```

The script will:
1. Detect whether Docker Desktop is running and launch it automatically if not
2. Build and start all four containers (`backend`, `db`, `ollama`, `frontend`) in detached mode
3. Pull the `llama3.2` and `nomic-embed-text` Ollama models if they aren't already downloaded
4. Open [http://localhost:5173](http://localhost:5173) in your default browser

> **First run:** model downloads can take several minutes depending on your connection.

### 3. Stop PacketIQ

Double-click **`stop-packetiq.bat`** — this runs `docker compose down`.

---

## Usage

| Action | How |
|---|---|
| Upload a PCAP | Click the **+** button and select a `.pcap`, `.pcapng`, or `.cap` file |
| Paste a PCAP | Paste a file directly into the chat window |
| Analyze by path | Type a filename (from the `pcaps/` directory) and click **Analyze** |
| Ask a question | After analysis, type any question in the chat and press **Ask** |
| View traffic stats | Click the **Overview** tab |
| View threat alerts | Click the **Detections** tab |
| Explore raw connections | Click the **Connections** tab; filter by IP, port, or state |
| Inspect DNS/HTTP/TLS | Click the **Protocols** tab and pick a sub-tab |
| Reload a past session | Click any entry under **Past Sessions** in the sidebar |

There is also a terminal client that runs the same pipeline:

```bash
python -m backend.cli
```

---

## Threat Detection

PacketIQ automatically scans every capture for:

| Threat | Detection Logic |
|---|---|
| **Port Scan** | Single source IP contacting many ports/hosts within a time window |
| **DDoS** | High connection volume from many distinct source IPs targeting a single destination (both required) |
| **Brute Force** | Two connection-level signals against any authenticating service — repeated **failed** connections, or repeated **completed-but-tiny** connections (application-layer login failures, e.g. FTP/SSH rejecting credentials after the TCP handshake). Targets are matched by well-known port (SSH, FTP, telnet, RDP, VNC, SMB, mail, LDAP, Kerberos, WinRM, SIP, and MySQL/PostgreSQL/MSSQL/Oracle/Redis/MongoDB) **or** by Zeek's protocol identification, so services on non-standard ports are still caught. Plus `ssh.log` auth failures and `http.log` 401/403 floods when available |

Each alert includes severity (`high` / `medium` / `low`), supporting evidence, and an actionable recommendation. Detection alerts are stored in the database and embedded into the RAG index, so the AI chat can reason about them directly.

Thresholds are tunable via environment variables — see [.env.example](.env.example).

---

## Configuration

All settings are environment variables with sensible defaults; Docker Compose wires them for the containers. For native runs, copy `.env.example` to `.env`. Key variables:

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | — (required) | Postgres connection string |
| `OLLAMA_MODEL` | `llama3.2` | Chat model |
| `OLLAMA_NUM_CTX` | `8192` | LLM context window |
| `DETECT_*` | see `.env.example` | Detection thresholds |

---

## Standalone Analysis Scripts

The `scripts/` directory contains self-contained Python tools for offline log analysis:

```bash
python scripts/zeek_log_analyzer.py   # Summarize connections, weird events, packet filter data
python scripts/brute_force.py         # Detect brute-force attempts from a conn.log
python scripts/dos.py                 # Detect DoS patterns
python scripts/port_scanning.py       # Detect port scans
```

These expect Zeek JSON logs in a `logs/` directory relative to the script.

---

## Acknowledgements

- [Zeek](https://zeek.org/) — network analysis framework
- [Ollama](https://ollama.com/) — local LLM inference
- [pgvector](https://github.com/pgvector/pgvector) — vector similarity search for PostgreSQL
