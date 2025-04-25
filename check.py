import subprocess

def check_ffmpeg_version():
    try:
        result = subprocess.run(["ffmpeg", "-version"], capture_output=True, text=True)
        print("FFmpeg is installed:")
        print(result.stdout.splitlines()[0])  # First line with version info
    except FileNotFoundError:
        print("❌ FFmpeg is not installed or not in system PATH.")

check_ffmpeg_version()
