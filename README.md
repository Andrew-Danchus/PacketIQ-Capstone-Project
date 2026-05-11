# PacketIQ

**Transform raw packet capture files into structured, AI-powered network intelligence.**

PacketIQ is a full-stack network analysis platform that ingests PCAP files, parses them with Zeek, stores the results in a PostgreSQL database, and lets you interrogate the traffic through a conversational AI interface powered by a local LLM (Ollama). It also automatically detects port scans, DDoS patterns, and brute-force attempts.

---

## Features

- **PCAP ingestion** — upload via file picker, drag-and-drop paste, or file path
- **Zeek-powered parsing** — extracts connections, DNS, HTTP, TLS, and anomaly events
- **AI chat interface** — ask natural-language questions about any traffic capture
- **RAG pipeline** — semantically retrieves relevant log chunks before querying the LLM
- **Traffic Overview** — stat cards, bar charts for top services/ports, connection-state breakdown, DNS queries, and weird events
- **Threat Detection** — automatic identification of port scans, DDoS, and brute-force attacks with severity ratings and remediation recommendations
- **Session history** — up to 10 past analyses cached in the browser for instant reload

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 19, Vite 8 |
| Backend API | FastAPI, Uvicorn (Python) |
| Database | PostgreSQL 16 + pgvector |
| LLM | Ollama (`llama3.2`) |
| Embeddings | `nomic-embed-text` via Ollama |
| Vector Search | FAISS + pgvector (HNSW index) |
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
1. Frontend POSTs the file to `/api/analyze`
2. Backend runs Zeek to produce JSON logs (`conn`, `dns`, `http`, `ssl`, `notice`)
3. Logs are ingested into PostgreSQL and chunked into the RAG store
4. Frontend switches to the Chat view; subsequent `/api/ask` calls retrieve relevant chunks via FAISS and pass them as context to the LLM

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

Double-click **`stop-packetiq.bat`** (or run it from a terminal):

```bat
stop-packetiq.bat
```

This runs `docker compose down` and shuts down all containers.

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
| Reload a past session | Click any entry under **Past Sessions** in the sidebar |

---

## Threat Detection

PacketIQ automatically scans every capture for:

| Threat | Detection Logic |
|---|---|
| **Port Scan** | Single source IP contacting many ports/hosts within a time window |
| **DDoS** | High connection volume from many source IPs targeting a single destination |
| **Brute Force** | Repeated failed authentication attempts on SSH (22), FTP (21), or RDP (3389) |

Each alert includes severity (`high` / `medium` / `low`), supporting evidence, and an actionable recommendation.

---


## Standalone Analysis Scripts

The `scripts/` directory contains self-contained Python tools for offline log analysis:

```bash
# Summarize connections, weird events, and packet filter data
python scripts/zeek_log_analyzer.py

# Detect brute-force attempts from a conn.log
python scripts/brute_force.py

# Detect DoS patterns
python scripts/dos.py

# Detect port scans
python scripts/port_scanning.py
```

These expect Zeek JSON logs in a `logs/` directory relative to the script.

---


## Acknowledgements

- [Zeek](https://zeek.org/) — network analysis framework
- [Ollama](https://ollama.com/) — local LLM inference
- [LangChain](https://langchain.com/) — RAG pipeline components
- [pgvector](https://github.com/pgvector/pgvector) — vector similarity search for PostgreSQL
