using System.Runtime.InteropServices;
using Avalonia.Controls;

namespace SupraChat.Core;

public static class WindowsNotificationService
{
    public const string Adapter = "shell-notification-area";

    private const uint NimAdd = 0x00000000;
    private const uint NimModify = 0x00000001;
    private const uint NimDelete = 0x00000002;

    private const uint NifMessage = 0x00000001;
    private const uint NifIcon = 0x00000002;
    private const uint NifTip = 0x00000004;
    private const uint NifInfo = 0x00000010;

    private const uint NiifInfo = 0x00000001;
    private const uint CallbackMessage = 0x8000 + 0x5355;
    private const uint NotificationId = 0x53555052;
    private static readonly IntPtr IdiApplication = new(32512);

    public static bool TryNotify(Window owner, string title, string message)
    {
        if (!OperatingSystem.IsWindows())
            return false;

        var hwnd = owner.TryGetPlatformHandle()?.Handle ?? IntPtr.Zero;
        if (hwnd == IntPtr.Zero)
            return false;

        var icon = LoadIcon(IntPtr.Zero, IdiApplication);
        var data = new NotifyIconData
        {
            cbSize = (uint)Marshal.SizeOf<NotifyIconData>(),
            hWnd = hwnd,
            uID = NotificationId,
            uFlags = NifMessage | NifIcon | NifTip,
            uCallbackMessage = CallbackMessage,
            hIcon = icon,
            szTip = "SupraChat"
        };

        if (!Shell_NotifyIcon(NimAdd, ref data))
            return false;

        data.uFlags = NifInfo;
        data.szInfoTitle = Truncate(title, 63);
        data.szInfo = Truncate(message, 255);
        data.dwInfoFlags = NiifInfo;

        var shown = Shell_NotifyIcon(NimModify, ref data);
        _ = Task.Run(async () =>
        {
            await Task.Delay(TimeSpan.FromSeconds(10));
            var cleanup = new NotifyIconData
            {
                cbSize = (uint)Marshal.SizeOf<NotifyIconData>(),
                hWnd = hwnd,
                uID = NotificationId
            };
            Shell_NotifyIcon(NimDelete, ref cleanup);
        });

        return shown;
    }

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max];

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NotifyIconData
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szTip;

        public uint dwState;
        public uint dwStateMask;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szInfo;

        public uint uTimeoutOrVersion;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string szInfoTitle;

        public uint dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Shell_NotifyIcon(uint dwMessage, ref NotifyIconData lpData);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadIcon(IntPtr hInstance, IntPtr lpIconName);
}
