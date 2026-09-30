"""Session recording — compatible with WineBot /recording endpoints.
ffmpeg-based screen capture with start/stop support.
Records to session artifacts directory for later retrieval."""

import os
import subprocess
import threading
import time
from typing import Optional

RECORDINGS_DIR = os.environ.get("WINBOT_RECORDINGS_DIR", "C:\\WinBot\\sessions\\recordings")
os.makedirs(RECORDINGS_DIR, exist_ok=True)


class Recorder:
    """Manages ffmpeg-based screen recording for session capture."""

    def __init__(self):
        self._process: Optional[subprocess.Popen] = None
        self._lock = threading.RLock()
        self._recording = False
        self._started_at: Optional[float] = None
        self._output_path: Optional[str] = None
        self._frame_count = 0
        self._bitrate = "2M"

    @property
    def is_recording(self) -> bool:
        return self._recording

    def status(self) -> dict:
        with self._lock:
            duration = 0.0
            if self._recording and self._started_at:
                duration = round(time.time() - self._started_at, 1)
            return {
                "recording": self._recording,
                "started_at": self._started_at,
                "duration_seconds": duration,
                "output_path": self._output_path,
                "frame_count": self._frame_count,
            }

    def start(self, fps: int = 15, bitrate: str = "2M") -> dict:
        """Start recording the primary display with ffmpeg."""
        with self._lock:
            if self._recording:
                return {"status": "already_recording", **self.status()}

            timestamp = time.strftime("%Y%m%d-%H%M%S")
            self._output_path = os.path.join(RECORDINGS_DIR, f"session-{timestamp}.mp4")

            cmd = [
                "ffmpeg",
                "-f", "gdigrab",          # Windows GDI screen grabber
                "-framerate", str(fps),
                "-i", "desktop",          # Capture entire desktop
                "-c:v", "libx264",
                "-preset", "ultrafast",
                "-b:v", bitrate,
                "-pix_fmt", "yuv420p",
                "-y",                     # Overwrite output
                self._output_path,
            ]

            try:
                self._process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self._recording = True
                self._started_at = time.time()
                return {"status": "started", **self.status()}
            except FileNotFoundError:
                return {
                    "status": "error",
                    "detail": "ffmpeg not found. Install ffmpeg and ensure it is on PATH.",
                }
            except Exception as e:
                return {"status": "error", "detail": str(e)}

    def stop(self) -> dict:
        """Stop the current recording."""
        with self._lock:
            if not self._recording or not self._process:
                return {"status": "not_recording"}

            duration = round(time.time() - (self._started_at or time.time()), 1)
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()

            self._recording = False
            result = {
                "status": "stopped",
                "output_path": self._output_path,
                "duration_seconds": duration,
                "file_size_bytes": os.path.getsize(self._output_path) if os.path.exists(self._output_path) else 0,
            }
            self._process = None
            self._started_at = None
            return result


# Global singleton
recorder = Recorder()
