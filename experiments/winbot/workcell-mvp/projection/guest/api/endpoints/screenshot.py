"""
WinBot Screenshot Endpoint
Multi-strategy: wininspect (native TCP) > dxcam > mss > pyautogui.
WinInspect uses native C++ with DXGI/WARP/GDI fallback via TCP protocol.
"""

import base64
import datetime
import os
import tempfile
from io import BytesIO

from fastapi import HTTPException
from fastapi.responses import Response

from core import wininspect

# ── Fallback capture strategies ──────────────────────────────────────────

Image = None
try:
    from PIL import Image as _PIL
    Image = _PIL
except ImportError:
    pass

# dxcam — DXGI Desktop Duplication (Python fallback)
dxcam = None
try:
    import dxcam as _dxcam
    dxcam = _dxcam
except Exception:
    pass

# mss — GDI/BitBlt fallback
try:
    import mss
except ImportError:
    mss = None

# pyautogui — PIL ImageGrab last resort
try:
    import pyautogui
except ImportError:
    pyautogui = None

_dxcam_camera = None


def _capture_wininspect():
    """Capture using WinInspect native TCP protocol (DXGI/WARP/GDI fallback).
    Works reliably from Session 0 (NSSM service), Hyper-V VMs, and RDP sessions."""
    if not Image:
        raise RuntimeError("PIL not available")

    # Get desktop info via TCP
    try:
        info = wininspect.request("screen.desktopInfo")
        width = int(info.get("width", 1920))
        height = int(info.get("height", 1080))
    except Exception:
        width = 1920
        height = 1080

    # Capture full desktop via TCP
    result = wininspect.request("screen.capture", {
        "left": 0, "top": 0, "right": width, "bottom": height
    })

    bmp_b64 = result.get("data_b64")
    if not bmp_b64:
        raise RuntimeError("WinInspect: no data_b64 in response")

    # Decode base64 BMP to PIL Image
    bmp_bytes = base64.b64decode(bmp_b64)
    tmp = tempfile.NamedTemporaryFile(suffix=".bmp", delete=False)
    try:
        tmp.write(bmp_bytes)
        tmp.close()
        img = Image.open(tmp.name)
        img.load()
        return img.convert("RGB")
    finally:
        os.unlink(tmp.name)


def _capture_dxcam():
    """Capture using dxcam (DXGI Desktop Duplication). Falls back if unavailable."""
    global _dxcam_camera
    if not dxcam:
        raise RuntimeError("dxcam not installed")
    if _dxcam_camera is None:
        _dxcam_camera = dxcam.create()
    frame = _dxcam_camera.grab()
    if frame is None:
        frame = _dxcam_camera.grab()
    if frame is None:
        raise RuntimeError("dxcam: no frame (desktop may not be active)")
    return Image.fromarray(frame)


def _capture_mss():
    """Capture using mss (GDI/BitBlt). Needs desktop access."""
    if not mss or not Image:
        raise RuntimeError("mss not available")
    with mss.mss() as sct:
        monitor = sct.monitors[0]
        img = sct.grab(monitor)
        return Image.frombytes("RGB", (img.width, img.height), img.rgb)


def _capture_pyautogui():
    """Capture using pyautogui (PIL ImageGrab). Last resort."""
    if not pyautogui:
        raise RuntimeError("pyautogui not available")
    return pyautogui.screenshot()


# ── Main capture entry point ─────────────────────────────────────────────

def capture(format: str = "png", output_dir: str = None):
    """Capture a screenshot via WinInspect TCP, falling back to dxcam/mss/pyautogui."""

    if format.lower() not in ("png", "jpg", "jpeg"):
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")

    errors = []
    screenshot = None
    method = None

    # Strategy 0: WinInspect (native TCP, works from Session 0)
    try:
        screenshot = _capture_wininspect()
        method = "wininspect"
    except Exception as e:
        errors.append(f"wininspect: {e}")

    # Strategy 1: dxcam (Python DXGI library)
    if screenshot is None and dxcam is not None:
        try:
            screenshot = _capture_dxcam()
            method = "dxcam"
        except Exception as e:
            errors.append(f"dxcam: {e}")

    # Strategy 2: mss (GDI/BitBlt)
    if screenshot is None and mss is not None and Image is not None:
        try:
            screenshot = _capture_mss()
            method = "mss"
        except Exception as e:
            errors.append(f"mss: {e}")

    # Strategy 3: pyautogui (PIL ImageGrab - last resort)
    if screenshot is None and pyautogui is not None and Image is not None:
        try:
            screenshot = _capture_pyautogui()
            method = "pyautogui"
        except Exception as e:
            errors.append(f"pyautogui: {e}")

    if screenshot is None:
        raise HTTPException(
            status_code=500,
            detail=f"Screenshot failed ({len(errors)} methods tried): {'; '.join(errors)}. Service may not have desktop access."
        )

    now = datetime.datetime.now()
    filename = f"winbot-screenshot-{now.strftime('%Y%m%d-%H%M%S')}.{format}"

    if output_dir:
        save_dir = output_dir
    else:
        save_dir = os.path.join(
            os.environ.get("WINBOT_SESSION_ROOT", r"C:\WinBot\sessions"),
            "screenshots"
        )
    os.makedirs(save_dir, exist_ok=True)
    filepath = os.path.join(save_dir, filename)

    if format.lower() in ("jpg", "jpeg"):
        screenshot = screenshot.convert("RGB")
    screenshot.save(filepath)

    buf = BytesIO()
    save_format = "JPEG" if format.lower() in ("jpg", "jpeg") else "PNG"
    screenshot.save(buf, format=save_format)
    buf.seek(0)

    media_type = "image/jpeg" if format.lower() == "jpg" else f"image/{format.lower()}"

    return Response(
        content=buf.read(),
        media_type=media_type,
        headers={
            "X-Screenshot-Path": filepath,
            "X-Screenshot-Width": str(screenshot.width),
            "X-Screenshot-Height": str(screenshot.height),
            "X-Screenshot-Method": method,
            "Content-Disposition": f'attachment; filename="{filename}"',
        }
    )
