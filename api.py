from flask import Flask, request, jsonify
from flask_cors import CORS
from pathlib import Path

from main import run_zeek_on_pcap, summarize_logs, list_pcap_files
from backend.ollama.service import analyze_evidence

app = Flask(__name__)
CORS(app)

PROJECT_ROOT = Path(__file__).resolve().parent
PCAP_DIR = PROJECT_ROOT / "pcaps"


@app.route('/api/pcaps', methods=['GET'])
def get_pcaps():
    pcaps = list_pcap_files()
    return jsonify([p.name for p in pcaps])


@app.route('/api/analyze', methods=['POST'])
def analyze():
    pcap_path = None

    if 'file' in request.files:
        file = request.files['file']
        if not file.filename:
            return jsonify({'error': 'No file selected'}), 400
        PCAP_DIR.mkdir(parents=True, exist_ok=True)
        pcap_path = PCAP_DIR / file.filename
        file.save(pcap_path)

    elif request.is_json:
        path_str = request.json.get('path', '').strip()
        if not path_str:
            return jsonify({'error': 'No file or path provided'}), 400
        candidate = Path(path_str)
        if candidate.is_absolute():
            pcap_path = candidate
        else:
            pcap_path = PCAP_DIR / path_str

    else:
        return jsonify({'error': 'No file or path provided'}), 400

    if not pcap_path.exists():
        return jsonify({'error': f'PCAP file not found: {pcap_path.name}'}), 404

    success = run_zeek_on_pcap(pcap_path)
    if not success:
        return jsonify({'error': 'Zeek analysis failed. Check that Docker is running and the zeek/zeek image is available.'}), 500

    evidence = summarize_logs()
    return jsonify({'evidence': evidence, 'filename': pcap_path.name})


@app.route('/api/ask', methods=['POST'])
def ask():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    question = data.get('question', '').strip()
    evidence = data.get('evidence', '').strip()

    if not question:
        return jsonify({'error': 'question is required'}), 400
    if not evidence:
        return jsonify({'error': 'evidence is required — analyze a PCAP first'}), 400

    try:
        answer = analyze_evidence(question, evidence)
        return jsonify({'answer': answer})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)
