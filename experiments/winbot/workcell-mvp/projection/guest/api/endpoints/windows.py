"""
WinBot Window Management Endpoints
List windows and focus windows — mirrors WineBot's /windows and /windows/focus.
"""

import ctypes

from fastapi import HTTPException

# ============================================================
# Win32 API definitions for window enumeration
# ============================================================
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

EnumWindows = user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
GetWindowTextW = user32.GetWindowTextW
GetWindowTextLengthW = user32.GetWindowTextLengthW
IsWindowVisible = user32.IsWindowVisible
GetWindowRect = user32.GetWindowRect
SetForegroundWindow = user32.SetForegroundWindow
GetForegroundWindow = user32.GetForegroundWindow
ShowWindow = user32.ShowWindow
GetWindowThreadProcessId = user32.GetWindowThreadProcessId
GetClassNameW = user32.GetClassNameW

SW_RESTORE = 9
SW_SHOW = 5


class RECT(ctypes.Structure):
    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


def _get_all_windows():
    """Enumerate all visible windows with titles."""
    windows = []

    def callback(hwnd, lparam):
        if IsWindowVisible(hwnd):
            length = GetWindowTextLengthW(hwnd)
            if length > 0:
                buf = ctypes.create_unicode_buffer(length + 1)
                GetWindowTextW(hwnd, buf, length + 1)
                title = buf.value
                if title:
                    rect = RECT()
                    GetWindowRect(hwnd, ctypes.byref(rect))
                    windows.append({
                        "handle": hex(hwnd),
                        "title": title,
                        "visible": True,
                        "rect": {
                            "left": rect.left,
                            "top": rect.top,
                            "right": rect.right,
                            "bottom": rect.bottom,
                            "width": rect.right - rect.left,
                            "height": rect.bottom - rect.top,
                        }
                    })
        return True

    EnumWindows(EnumWindowsProc(callback), 0)
    return windows


def _find_window_by_title(title: str, substring: bool = True) -> dict:
    """Find a window by title match."""
    windows = _get_all_windows()

    if substring:
        matches = [w for w in windows if title.lower() in w["title"].lower()]
    else:
        matches = [w for w in windows if w["title"].lower() == title.lower()]

    return matches[0] if matches else None


def list_windows():
    """
    List all visible windows on the desktop.

    Returns:
        JSON with window list
    """
    try:
        windows = _get_all_windows()
        return {
            "count": len(windows),
            "windows": windows,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Window enumeration failed: {str(e)}")


def focus_window(title: str = None, substring: bool = True):
    """
    Focus a window by title.

    Args:
        title: Window title to focus (None = just return available windows)
        substring: If True, match title as substring

    Returns:
        JSON with focus result
    """
    try:
        if not title:
            return {
                "status": "no_title",
                "available_windows": [w["title"] for w in _get_all_windows()[:20]],
            }
        win = _find_window_by_title(title, substring)
        if not win:
            return {
                "status": "not_found",
                "title_searched": title,
                "substring": substring,
                "available_windows": [w["title"] for w in _get_all_windows()[:20]],
            }

        hwnd = int(win["handle"], 16)

        # Restore window if minimized
        ShowWindow(hwnd, SW_RESTORE)
        ShowWindow(hwnd, SW_SHOW)

        # Bring to foreground
        SetForegroundWindow(hwnd)

        # Verify
        foreground = GetForegroundWindow()
        focused = hex(foreground) == win["handle"]

        return {
            "status": "focused" if focused else "focus_attempted",
            "handle": win["handle"],
            "title": win["title"],
            "focused": focused,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Window focus failed: {str(e)}")


def inspect_window(title: str = None, handle: str = None):
    """
    Inspect a window by title or handle — detailed properties.

    Returns window class name, process ID, thread ID, rect, visibility, and z-order.
    Compatible with WineBot's POST /inspect/window.
    """
    try:
        if handle:
            hwnd = int(handle, 16)
            win_info = None
            # Verify this window still exists with the given title if both provided
            windows = _get_all_windows()
            for w in windows:
                if w["handle"] == hex(hwnd):
                    win_info = w
                    break
            if not win_info:
                return {"status": "not_found", "handle": handle}
        elif title:
            win_info = _find_window_by_title(title, substring=True)
            if not win_info:
                return {"status": "not_found", "title_searched": title}
            hwnd = int(win_info["handle"], 16)
        else:
            return {"status": "no_query", "available_windows": [w["title"] for w in _get_all_windows()[:20]]}

        # Get class name
        class_buf = ctypes.create_unicode_buffer(256)
        GetClassNameW(hwnd, class_buf, 256)

        # Get process/thread
        thread_id = GetWindowThreadProcessId(hwnd, None)

        # Check if foreground
        foreground_hwnd = GetForegroundWindow()
        is_foreground = (hwnd == foreground_hwnd)

        # Get window text (full, uncapped)
        full_length = GetWindowTextLengthW(hwnd)
        if full_length > 0:
            full_buf = ctypes.create_unicode_buffer(full_length + 1)
            GetWindowTextW(hwnd, full_buf, full_length + 1)
            full_title = full_buf.value
        else:
            full_title = win_info.get("title", "") if win_info else ""

        return {
            "status": "found",
            "handle": hex(hwnd),
            "title": full_title,
            "class_name": class_buf.value,
            "thread_id": thread_id,
            "is_foreground": is_foreground,
            "visible": win_info.get("visible", True) if win_info else False,
            "rect": win_info.get("rect", {}) if win_info else {},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Window inspection failed: {str(e)}")
