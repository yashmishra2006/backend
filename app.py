import requests
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import time
import json
import os
import traceback
import uuid
from PIL import Image
import logging

# Initialize Flask app
app = Flask(__name__)


# Directory to store temporary audio files
TEMP_DIR = os.path.join(os.getcwd(), 'temp_audio_files')

# Ensure the temporary directory exists
os.makedirs(TEMP_DIR, exist_ok=True)

# model = resnet50(weights=ResNet50_Weights.DEFAULT)
# model.eval()

# transform = transforms.Compose([
#     transforms.Resize((224, 224)),
#     transforms.ToTensor(),
# ])

CORS(app)

# Groq API key (replace with yours securely in real deployment)
GROQ_API_KEY = "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"

ASSEMBLYAI_API_KEY="44b4b6ca73d3421c8e27ab64e32660ac"

# Endpoint
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# In-memory storage
analysis_results = {}

import re
import json
import requests


def extract_json(text):
    try:
        # Remove triple backticks and optional language specifier
        cleaned = text.strip().strip("```json").strip("```").strip()
        return json.loads(cleaned)
    except Exception:
        # Fallback: extract JSON-like block using regex
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except Exception as e:
                print("❌ Still failed parsing fallback JSON:", e)
        return None

def analyze_with_groq(content, content_type):
    prompt = f"""You are a threat analysis expert. Analyze the following {content_type} content and provide a detailed threat assessment:

Content: {content}

Provide your analysis in the following JSON format:
{{
    "threat_level": "safe|suspicious|dangerous",
    "score": 0.0-1.0,
    "summary": "detailed explanation",
    "confidence": 0.0-1.0,
    "categories": ["category1", "category2"],
    "highlights": [
        {{"text": "specific concerning elements"}}
    ]
}}"""

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    data = {
        "model": "mistral-saba-24b",
        "messages": [
            {"role": "system", "content": "You are a threat analysis AI specializing in detecting security threats, malicious content, and potential risks."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1,
        "max_tokens": 1000,
        "top_p": 1,
        "stream": False
    }

    response = requests.post(GROQ_API_URL, headers=headers, json=data)
    print("🔍 Groq API Raw Response:")
    print(json.dumps(response.json(), indent=4))

    if response.status_code == 200:
        try:
            result = response.json()
            content = result['choices'][0]['message']['content']
            parsed = extract_json(content)

            if parsed is not None:
                return parsed
            else:
                raise ValueError("Failed to extract JSON from response")

        except Exception as e:
            print("❌ Error parsing Groq response:", e)
            return {
                "threat_level": "suspicious",
                "score": 0.6,
                "summary": "Unable to parse response from Groq.",
                "confidence": 0.5,
                "categories": ["ParsingError"],
                "highlights": []
            }

    return {
        "threat_level": "suspicious",
        "score": 0.8,
        "summary": "Groq API call failed.",
        "confidence": 0.4,
        "categories": ["APIError"],
        "highlights": []
    }




@app.route('/api/analyze/text', methods=['POST'])
def analyze_text():
    """Endpoint for text threat analysis"""
    if not request.json or not 'text' in request.json:
        return jsonify({'success': False, 'error': 'No text provided'}), 400
    
    text = request.json['text']
    analysis_id = str(uuid.uuid4())
    
    try:
        analysis = analyze_with_groq(text, "text")
        print(f"Analysis ID: {analysis_id}, Analysis Result: {analysis}")
        
        result = {
            'id': analysis_id,
            'type': 'text',
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'score': analysis['score'],
            'threat_level': analysis['threat_level'],
            'details': {
                'summary': analysis['summary'],
                'confidence': analysis['confidence'],
                'categories': analysis['categories'],
                'highlights': analysis['highlights']
            }
        }
        
        analysis_results[analysis_id] = result
        
        return jsonify({
            'success': True,
            'result': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/analyze/url', methods=['POST'])
def analyze_url():
    """Endpoint for URL threat analysis"""
    if not request.json or not 'url' in request.json:
        return jsonify({'success': False, 'error': 'No URL provided'}), 400
    
    url = request.json['url']
    analysis_id = str(uuid.uuid4())
    
    try:
        analysis = analyze_with_groq(url, "URL")
        
        result = {
            'id': analysis_id,
            'type': 'url',
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'score': analysis['score'],
            'threat_level': analysis['threat_level'],
            'details': {
                'summary': analysis['summary'],
                'confidence': analysis['confidence'],
                'categories': analysis['categories'],
                'highlights': analysis['highlights']
            }
        }

        
        analysis_results[analysis_id] = result
        
        return jsonify({
            'success': True,
            'result': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    

@app.route("/api/analyze/audio", methods=["POST"])
def analyze_audio():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No audio file uploaded"}), 400

        audio_file = request.files['file']
        temp_dir = os.path.join(os.path.dirname(__file__), "temp_audio_files")
        os.makedirs(temp_dir, exist_ok=True)

        filename = f"{uuid.uuid4()}.wav"
        file_path = os.path.join(temp_dir, filename)
        audio_file.save(file_path)

        # Check if file exists
        if not os.path.exists(file_path):
            raise Exception(f"File does not exist: {file_path}")

        # Upload the audio file to AssemblyAI
        headers = {'authorization': ASSEMBLYAI_API_KEY}
        with open(file_path, 'rb') as f:
            upload_response = requests.post(
                "https://api.assemblyai.com/v2/upload", 
                headers=headers, 
                files={'file': f}
            )
        upload_response.raise_for_status()
        audio_url = upload_response.json()['upload_url']

        # Request transcription from AssemblyAI
        transcribe_headers = {
            'authorization': ASSEMBLYAI_API_KEY,
            'content-type': 'application/json'
        }
        transcribe_data = {'audio_url': audio_url}
        transcribe_response = requests.post(
            "https://api.assemblyai.com/v2/transcript",
            headers=transcribe_headers,
            json=transcribe_data
        )
        transcribe_response.raise_for_status()
        transcript_id = transcribe_response.json()['id']

        # Poll for transcription result
        polling_url = f"https://api.assemblyai.com/v2/transcript/{transcript_id}"
        while True:
            poll_response = requests.get(polling_url, headers={'authorization': ASSEMBLYAI_API_KEY})
            poll_response.raise_for_status()
            status = poll_response.json()['status']

            if status == 'completed':
                text = poll_response.json()['text']
                break
            elif status == 'failed':
                raise Exception(f"Transcription failed: {poll_response.json()}")
            else:
                time.sleep(3)

        # Analyze with Groq
        analysis = analyze_with_groq(text, content_type="audio")

        # Prepare the result
        analysis_id = str(uuid.uuid4())
        result = {
            'id': analysis_id,
            'type': "audio",
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'score': analysis['score'],
            'threat_level': analysis['threat_level'],
            'details': {
                'summary': analysis['summary'],
                'confidence': analysis['confidence'],          
                'categories': analysis['categories'],
                'highlights': analysis['highlights']
            }
        }

        # Store analysis results (assuming a dictionary `analysis_results` is defined elsewhere)
        analysis_results[analysis_id] = result

        # Return the analysis result as a JSON response
        return jsonify({
            'success': True,
            'result': result
        })

    except requests.exceptions.RequestException as e:
        # Catch errors related to HTTP requests (e.g., upload or transcription requests)
        return jsonify({"error": f"Request failed: {str(e)}"}), 500
    except Exception as e:
        # Catch any other errors
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    finally:
        # Cleanup: Remove temporary file
        if os.path.exists(file_path):
            os.remove(file_path)


# @app.route('/api/analyze/image', methods=['POST'])
# def analyze_image():
#     """Endpoint for image threat analysis"""
#     if 'file' not in request.files:
#         return jsonify({'success': False, 'error': 'No file provided'}), 400

#     file = request.files['file']
#     file_type = request.form.get('type', 'unknown')

#     if file.filename == '':
#         return jsonify({'success': False, 'error': 'No file selected'}), 400

#     analysis_id = str(uuid.uuid4())
#     metadata = {
#         'filename': file.filename,
#         'content_type': file.content_type,
#         'size': file.content_length or 0
#     }

#     try:
#         img = Image.open(file).convert('RGB')
#         input_tensor = transform(img).unsqueeze(0)

#         with torch.no_grad():
#             outputs = model(input_tensor)
#             _, indices = torch.topk(outputs, 3)
#             top_indices = indices[0].tolist()
#             top_predictions = [ResNet50_Weights.IMAGENET1K_V1.meta['categories'][i] for i in top_indices]

#         # Turn into human-readable string for Groq
#         description = f"Top predictions from ResNet50: {top_predictions}"
#         print("🔍 Image Analysis Description:", description)

#         analysis = analyze_with_groq(description, "image")

#         result = {
#             'id': analysis_id,
#             'type': file_type,
#             'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
#             'score': analysis['score'],
#             'threat_level': analysis['threat_level'],
#             'details': {
#                 'summary': analysis['summary'],
#                 'confidence': analysis['confidence'],
#                 'categories': analysis['categories'],
#                 'metadata': None,
#                 'highlights': analysis['highlights']
#             }}

#         analysis_results[analysis_id] = result

#         return jsonify({
#             'success': True,
#             'result': result
#         })
#     except Exception as e:
#         return jsonify({
#             'success': False,
#             'error': str(e)
#         }), 500


@app.route('/api/results/<analysis_id>', methods=['GET'])
def get_result(analysis_id):
    """Retrieve a specific analysis result"""
    if analysis_id not in analysis_results:
        return jsonify({'success': False, 'error': 'Analysis result not found'}), 404
    
    return jsonify({
        'success': True,
        'result': analysis_results[analysis_id]
    })

    
    