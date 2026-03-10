CREATE TABLE jobs (
    id UUID PRIMARY KEY,
    filename TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'uploaded',
    file_size_bytes BIGINT,
    error_message TEXT
);

CREATE TABLE connections(
    id BIGSERIAL PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    ts TIMESTAMPTZ NOT NULL,
    src_ip INET,
    src_port INTEGER,
    dst_ip INET,
    dst_port INTEGER,
    proto TEXT,
    service TEXT,
    duration DOUBLE PRECISION,
    orig_bytes BIGINT,
    resp_bytes BIGINT,
    conn_state TEXT
);


CREATE TABLE dns_events(
    id BIGSERIAL PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    ts TIMESTAMPTZ NOT NULL,
    src_ip INET,
    src_port INTEGER,
    dst_ip INET,
    dst_port INTEGER,
    proto TEXT,
    query TEXT,
    qtype INT,
    rcode INTEGER,
    answers TEXT
);

CREATE TABLE http_events(
    id BIGSERIAL PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    ts TIMESTAMPTZ NOT NULL,
    src_ip INET,
    src_port INTEGER,
    dst_ip INET,
    dst_port INTEGER,
    proto TEXT,
    method TEXT,
    host TEXT,
    uri TEXT,
    user_agent TEXT,
    status_code INTEGER
);

CREATE TABLE tls_events(
    id BIGSERIAL PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    ts TIMESTAMPTZ NOT NULL,
    src_ip INET,
    dst_ip INET,
    server_name TEXT,
    cert TEXT,
    version TEXT,
    cipher TEXT
);

CREATE TABLE detections(
    id BIGSERIAL PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    detection_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip INET,
    dst_ip INET,
    dst_port INTEGER,
    evidence JSONB NOT NULL

);

CREATE TABLE rag_chunks(
    id BIGSERIAL PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    chunk_text TEXT NOT NULL
);


CREATE INDEX idx_jobs_status ON jobs(status);
CREATE INDEX idx_jobs_created_at ON jobs(created_at);

CREATE INDEX idx_connections_job_ts ON connections(job_id, ts);
CREATE INDEX idx_connections_job_src_ip ON connections(job_id, src_ip);
CREATE INDEX idx_connections_job_dst_ip ON connections(job_id, dst_ip);
CREATE INDEX idx_connections_job_dst_port ON connections(job_id, dst_port);

CREATE INDEX idx_dns_events_ts ON dns_events(job_id, ts);
CREATE INDEX idx_dns_events_job_query ON dns_events(job_id, query);

CREATE INDEX idx_http_events_job_ts ON http_events(job_id, ts);
CREATE INDEX idx_http_events_job_host ON http_events(job_id, host);

CREATE INDEX idx_detections_job_ts ON detections(job_id, ts);
CREATE INDEX idx_detections_job_type ON detections(job_id, detection_type);


CREATE INDEX idx_rag_chunks_job_source ON rag_chunks(job_id, source);  
CREATE INDEX idx_rag_chunks_job_created_at ON rag_chunks(job_id, created_at);