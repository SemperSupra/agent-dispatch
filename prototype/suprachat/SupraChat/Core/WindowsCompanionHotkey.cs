using System.Runtime.InteropServices;
using Avalonia.Controls;
using Avalonia.Threading;

namespace SupraChat.Core;

public sealed class WindowsCompanionHotkey : IDisposable
{
    public const string ShortcutDescription = "Alt+Space";

    private const int HotkeyId = 0x5355;
    private const uint WmHotkey = 0x0312;
    private const uint ModAlt = 0x0001;
    private const uint VkSpace = 0x20;

    private readonly Window _window;
    private Win32Properties.CustomWndProcHookCallback? _hook;
    private IntPtr _hwnd;
    private bool _registered;

    public WindowsCompanionHotkey(Window window) => _window = window;

    public bool TryRegister()
    {
        if (!OperatingSystem.IsWindows() || _registered)
            return _registered;

        _hwnd = _window.TryGetPlatformHandle()?.Handle ?? IntPtr.Zero;
        if (_hwnd == IntPtr.Zero)
            return false;

        _hook = WndProc;
        Win32Properties.AddWndProcHookCallback(_window, _hook);

        _registered = RegisterHotKey(_hwnd, HotkeyId, ModAlt, VkSpace);
        if (!_registered)
        {
            Win32Properties.RemoveWndProcHookCallback(_window, _hook);
            _hook = null;
            _hwnd = IntPtr.Zero;
        }

        return _registered;
    }

    private IntPtr WndProc(
        IntPtr hWnd,
        uint msg,
        IntPtr wParam,
        IntPtr lParam,
        ref bool handled)
    {
        if (msg != WmHotkey || wParam.ToInt32() != HotkeyId)
            return IntPtr.Zero;

        handled = true;
        Dispatcher.UIThread.Post(ToggleWindow);
        return IntPtr.Zero;
    }

    private void ToggleWindow()
    {
        if (_window.IsVisible && _window.WindowState != WindowState.Minimized && _window.IsActive)
        {
            _window.Hide();
            return;
        }

        if (!_window.IsVisible)
            _window.Show();

        if (_window.WindowState == WindowState.Minimized)
            _window.WindowState = WindowState.Normal;

        _window.Activate();
    }

    public void Dispose()
    {
        if (_registered && _hwnd != IntPtr.Zero)
            UnregisterHotKey(_hwnd, HotkeyId);

        if (_hook is not null)
            Win32Properties.RemoveWndProcHookCallback(_window, _hook);

        _registered = false;
        _hook = null;
        _hwnd = IntPtr.Zero;
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool UnregisterHotKey(IntPtr hWnd, int id);
}
