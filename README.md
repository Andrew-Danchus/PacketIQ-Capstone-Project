# PacketIQ
Overview

PacketIQ is a network forensic analysis platform designed to simplify the investigation of packet capture (PCAP) files. Traditional tools such as Wireshark require advanced knowledge of networking concepts and filtering syntax, which can make them difficult for beginners and students to use effectively.

This project addresses that challenge by allowing users to upload PCAP files and interact with network data using plain English queries. The system processes raw packet data, extracts structured network information, and generates clear, evidence-based responses using a retrieval-augmented generation (RAG) approach.

Features
Upload and process PCAP files
Automated parsing using Zeek
Structured data storage in PostgreSQL
Natural language querying of network activity
AI-generated responses using a local model via Ollama
Rule-based detection of suspicious behavior (port scanning, brute force attempts, DoS patterns)
Web-based dashboard for visualization and interaction
Fully local deployment for data privacy

Installation and Setup
