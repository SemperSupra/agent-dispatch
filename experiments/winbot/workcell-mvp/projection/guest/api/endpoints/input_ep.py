"""
WinBot Input Endpoints
Mouse clicks, movement, keyboard typing — mirrors WineBot's /input endpoints.
"""


from fastapi import HTTPException

try:
    import pyautogui
    pyautogui.FAILSAFE = False  # Allow edge-of-screen for VM
    PYAUTOGUI_AVAILABLE = True
except ImportError:
    PYAUTOGUI_AVAILABLE = False


def _ensure_pyautogui():
    if not PYAUTOGUI_AVAILABLE:
        raise HTTPException(status_code=500, detail="pyautogui not installed. Run: pip install pyautogui")


def mouse_click(x: int, y: int, button: str = "left", clicks: int = 1, interval: float = 0.0):
    """
    Click at screen coordinates.

    Args:
        x: X position in pixels
        y: Y position in pixels
        button: 'left', 'right', or 'middle'
        clicks: Number of clicks (2 = double-click)
        interval: Seconds between clicks
    """
    _ensure_pyautogui()

    try:
        pyautogui.click(x, y, clicks=clicks, interval=interval, button=button)
        return {
            "status": "clicked",
            "x": x,
            "y": y,
            "button": button,
            "clicks": clicks,
            "position": pyautogui.position(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Mouse click failed: {str(e)}")


def mouse_move(x: int, y: int):
    """
    Move mouse to absolute coordinates.
    """
    _ensure_pyautogui()

    try:
        pyautogui.moveTo(x, y)
        return {
            "status": "moved",
            "x": x,
            "y": y,
            "position": pyautogui.position(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Mouse move failed: {str(e)}")


def keyboard_type(text: str, interval: float = 0.0):
    """
    Type text using the keyboard.

    Args:
        text: Text string to type
        interval: Delay between keystrokes in seconds
    """
    _ensure_pyautogui()

    try:
        pyautogui.typewrite(text, interval=interval)
        return {
            "status": "typed",
            "text_length": len(text),
            "interval": interval,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Keyboard type failed: {str(e)}")


def keyboard_press(keys: str):
    """
    Press a key combination like 'ctrl+c', 'alt+tab', 'win+r'.

    Args:
        keys: Key combination string (e.g., 'ctrl+c', 'alt+tab', 'enter')
    """
    _ensure_pyautogui()

    try:
        # Parse key combination
        parts = [k.strip().lower() for k in keys.split('+')]
        pyautogui.hotkey(*parts)
        return {
            "status": "pressed",
            "keys": keys,
            "parts": parts,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Key press failed: {str(e)}")
