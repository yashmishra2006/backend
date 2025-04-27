import requests
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import time
import json
import torch
import os
import traceback
import uuid
from PIL import Image
import torchvision.transforms as transforms
from torchvision.models import resnet50, ResNet50_Weights

# Set the path to ffmpeg binary
os.environ["PATH"] += os.pathsep + r"C:\Program Files\ffmpeg-7.1.1\bin"

# Load environment variables

# Initialize Flask app
app = Flask(__name__)


# Directory to store temporary audio files
TEMP_DIR = os.path.join(os.getcwd(), 'temp_audio_files')

# Ensure the temporary directory exists
os.makedirs(TEMP_DIR, exist_ok=True)

model = resnet50(weights=ResNet50_Weights.DEFAULT)
model.eval()

transform = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.ToTensor(),
])


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




@app.route('/api/analyze/image', methods=['POST'])
def analyze_image():
    """Endpoint for image threat analysis"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400

    file = request.files['file']
    file_type = request.form.get('type', 'unknown')

    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400

    analysis_id = str(uuid.uuid4())
    metadata = {
        'filename': file.filename,
        'content_type': file.content_type,
        'size': file.content_length or 0
    }

    try:
        img = Image.open(file).convert('RGB')
        input_tensor = transform(img).unsqueeze(0)

        with torch.no_grad():
            outputs = model(input_tensor)
            _, indices = torch.topk(outputs, 3)
            top_indices = indices[0].tolist()
            top_predictions = [ResNet50_Weights.IMAGENET1K_V1.meta['categories'][i] for i in top_indices]

        # Turn into human-readable string for Groq
        description = f"Top predictions from ResNet50: {top_predictions}"
        print("🔍 Image Analysis Description:", description)

        analysis = analyze_with_groq(description, "image")

        result = {
            'id': analysis_id,
            'type': file_type,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'score': analysis['score'],
            'threat_level': analysis['threat_level'],
            'details': {
                'summary': analysis['summary'],
                'confidence': analysis['confidence'],
                'categories': analysis['categories'],
                'metadata': None,
                'highlights': analysis['highlights']
            }}

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


@app.route('/api/results/<analysis_id>', methods=['GET'])
def get_result(analysis_id):
    """Retrieve a specific analysis result"""
    if analysis_id not in analysis_results:
        return jsonify({'success': False, 'error': 'Analysis result not found'}), 404
    
    return jsonify({
        'success': True,
        'result': analysis_results[analysis_id]
    })

    
    