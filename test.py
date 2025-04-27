import os
import time
import uuid
import requests
import traceback

# AssemblyAI API Key
ASSEMBLYAI_API_KEY = "44b4b6ca73d3421c8e27ab64e32660ac"

# AssemblyAI Endpoints
ASSEMBLY_UPLOAD_URL = "https://api.assemblyai.com/v2/upload"
ASSEMBLY_TRANSCRIBE_URL = "https://api.assemblyai.com/v2/transcript"

# ---- Helper Functions ----

def upload_audio(file_path):
    print(f"[DEBUG] Uploading file: {file_path}")
    headers = {'authorization': ASSEMBLYAI_API_KEY}
    with open(file_path, 'rb') as f:
        response = requests.post(ASSEMBLY_UPLOAD_URL, headers=headers, files={'file': f})
    print(f"[DEBUG] Upload status code: {response.status_code}")
    response.raise_for_status()
    return response.json()['upload_url']

def request_transcription(audio_url):
    print(f"[DEBUG] Requesting transcription for: {audio_url}")
    headers = {
        'authorization': ASSEMBLYAI_API_KEY,
        'content-type': 'application/json'
    }
    data = {'audio_url': audio_url}
    response = requests.post(ASSEMBLY_TRANSCRIBE_URL, headers=headers, json=data)
    print(f"[DEBUG] Transcription request status: {response.status_code}")
    response.raise_for_status()
    return response.json()['id']

def get_transcription_result(transcript_id):
    print(f"[DEBUG] Polling transcription for ID: {transcript_id}")
    headers = {'authorization': ASSEMBLYAI_API_KEY}
    polling_endpoint = f"{ASSEMBLY_TRANSCRIBE_URL}/{transcript_id}"

    while True:
        response = requests.get(polling_endpoint, headers=headers)
        print(f"[DEBUG] Polling status: {response.status_code}")
        response.raise_for_status()
        status = response.json()['status']
        print(f"[DEBUG] Current transcription status: {status}")

        if status == 'completed':
            return response.json()['text']
        elif status == 'failed':
            raise Exception(f"Transcription failed: {response.json()}")
        else:
            time.sleep(3)

# ---- Main Execution ----

if __name__ == "__main__":
    try:
        # 1. Set your local file path here
        file_path = r"C:\Users\yash4\Desktop\backend\audio.mp3"  # <-- Change if needed

        if not os.path.exists(file_path):
            raise Exception(f"File does not exist: {file_path}")

        # 2. Upload the file
        audio_url = upload_audio(file_path)
        print(f"[INFO] Audio file uploaded to: {audio_url}")

        # 3. Request transcription
        transcript_id = request_transcription(audio_url)
        print(f"[INFO] Transcript request ID: {transcript_id}")

        # 4. Poll for result
        transcription_text = get_transcription_result(transcript_id)
        print("\n=== Final Transcription ===\n")
        print(transcription_text)

    except Exception as e:
        print("[EXCEPTION] Something went wrong!")
        traceback.print_exc()
