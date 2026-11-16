using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows;
using NetSecurityScanner.Services;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Views
{
    public partial class LicenseDialog : Window
    {
        public LicenseDialog()
        {
            InitializeComponent();
            UpdateStatusDisplay();
        }

        private void UpdateStatusDisplay()
        {
            var licenseService = new LicenseService();
            var status = licenseService.GetLicenseStatus();

            StatusTextBlock.Text = status.StatusText;
            if (status.IsLicensed && !status.IsExpired)
            {
                StatusTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0x27, 0xAE, 0x60));
            }
            else if (status.IsExpired)
            {
                StatusTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0xE7, 0x4C, 0x3C));
            }
            else
            {
                StatusTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0x95, 0xA5, 0xA6));
            }

            LicenseTypeTextBlock.Text = status.LicenseInfo != null
                ? $"授权类型：{status.LicenseInfo.DisplayName}"
                : "授权类型：无";

            ExpiryTextBlock.Text = status.LicenseInfo != null && status.LicenseInfo.ExpiryTime.HasValue
                ? $"到期时间：{status.LicenseInfo.ExpiryTime.Value:yyyy-MM-dd HH:mm:ss}"
                : status.LicenseInfo != null && status.LicenseInfo.IsPermanent
                    ? "到期时间：永久"
                    : "到期时间：-";

            MachineIdTextBox.Text = status.MachineId;
        }

        private void ActivateButton_Click(object sender, RoutedEventArgs e)
        {
            string code = LicenseCodeTextBox.Text.Trim();
            if (string.IsNullOrEmpty(code))
            {
                MessageBox.Show("请输入授权码", "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            ActivateButton.IsEnabled = false;

            try
            {
                var licenseService = new LicenseService();
                bool success = licenseService.ActivateLicense(code);

                if (success)
                {
                    MessageBox.Show("授权激活成功！", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                    UpdateStatusDisplay();
                    DialogResult = true;
                }
                else
                {
                    licenseService.ValidateLicenseCode(code, out _, out string errorMessage);
                    MessageBox.Show(errorMessage, "激活失败", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            finally
            {
                ActivateButton.IsEnabled = true;
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void CopyMachineIdButton_Click(object sender, RoutedEventArgs e)
        {
            var licenseService = new LicenseService();
            string machineId = licenseService.GetCurrentMachineId();

            // 修复：Clipboard.SetText 在其他进程占用剪贴板时会抛出 CLIPBRD_E_CANT_OPEN（0x800401D0）。
            // 退避重试 + 退化方案：先尝试 SetText，失败则回退到 Clipboard.SetDataObject(..., copy: true)，
            // 仍失败则用 STA 线程延迟重试。
            if (!TrySetClipboardText(machineId, out var ex))
            {
                // 退化：提示用户机器码，可手动复制
                MessageBox.Show(
                    $"复制到剪贴板失败：{ex?.Message}\n\n请手动复制以下机器码：\n{machineId}",
                    "复制失败",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            CopyMachineIdButton.Content = "✅ 已复制";
            CopyMachineIdButton.Background = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(0x27, 0xAE, 0x60));

            var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            timer.Tick += (s, args) =>
            {
                CopyMachineIdButton.Content = "📋 复制机器码";
                CopyMachineIdButton.Background = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0x34, 0x98, 0xDB));
                timer.Stop();
            };
            timer.Start();
        }

        /// <summary>
        /// 健壮地设置剪贴板文本。
        /// WPF 的 Clipboard.SetText / SetDataObject 在另一个进程持有剪贴板时会抛
        /// CLIPBRD_E_CANT_OPEN（0x800401D0），且在 UI 线程上 Thread.Sleep 会冻结界面。
        /// 本方法改用 Win32 OpenClipboard / SetClipboardData 直接写入，并把整个
        /// 流程放到专用 STA 线程：1) 不阻塞 UI；2) 多次重试 OpenClipboard；
        /// 3) 重试全部失败时回退到 WPF Clipboard，捕获所有异常。
        /// </summary>
        private static bool TrySetClipboardText(string text, out Exception? lastError)
        {
            lastError = null;
            if (text == null) text = string.Empty;

            // 1) Win32 直写：独立 STA 线程，避免阻塞 UI，并允许重试。
            Exception? win32Error = null;
            bool win32Ok = false;
            var staThread = new Thread(() =>
            {
                try
                {
                    win32Ok = SetClipboardTextWin32(text, out var ex);
                    if (!win32Ok) win32Error = ex;
                }
                catch (Exception ex)
                {
                    win32Error = ex;
                }
            });
            staThread.SetApartmentState(ApartmentState.STA);
            staThread.IsBackground = true;
            staThread.Start();
            staThread.Join();

            if (win32Ok) return true;
            lastError = win32Error;
            return false;
        }

        // ===================== Win32 剪贴板原生 API =====================
        private const uint CF_UNICODETEXT = 13;
        private const uint GMEM_MOVEABLE = 0x0002;

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool OpenClipboard(IntPtr hWndNewOwner);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool CloseClipboard();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool EmptyClipboard();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetClipboardData(uint uFormat, IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GlobalAlloc(uint uFlags, UIntPtr dwBytes);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GlobalLock(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GlobalUnlock(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GlobalFree(IntPtr hMem);

        /// <summary>
        /// 使用 Win32 API 在专用 STA 线程上写入剪贴板文本。
        /// OpenClipboard 失败时按 30 / 60 / 120 ms 退避重试，最多重试 4 次。
        /// </summary>
        private static bool SetClipboardTextWin32(string text, out Exception? lastError)
        {
            lastError = null;
            IntPtr hGlobal = IntPtr.Zero;
            try
            {
                // 构造 UTF-16 + 终止 NUL 的字节缓冲
                byte[] bytes = Encoding.Unicode.GetBytes(text + "\0");
                hGlobal = GlobalAlloc(GMEM_MOVEABLE, (UIntPtr)bytes.Length);
                if (hGlobal == IntPtr.Zero)
                {
                    lastError = new InvalidOperationException("GlobalAlloc 失败");
                    return false;
                }
                IntPtr dest = GlobalLock(hGlobal);
                if (dest == IntPtr.Zero)
                {
                    lastError = new InvalidOperationException("GlobalLock 失败");
                    return false;
                }
                Marshal.Copy(bytes, 0, dest, bytes.Length);
                GlobalUnlock(hGlobal);

                // 退避重试 OpenClipboard
                int[] delaysMs = { 0, 30, 60, 120 };
                bool opened = false;
                int lastErr = 0;
                for (int i = 0; i < delaysMs.Length; i++)
                {
                    if (delaysMs[i] > 0) Thread.Sleep(delaysMs[i]);
                    if (OpenClipboard(IntPtr.Zero))
                    {
                        opened = true;
                        break;
                    }
                    lastErr = Marshal.GetLastWin32Error();
                }
                if (!opened)
                {
                    lastError = new InvalidOperationException(
                        $"OpenClipboard 失败 (Win32 错误码={lastErr}, 0x{lastErr:X})");
                    return false;
                }

                try
                {
                    EmptyClipboard();
                    if (SetClipboardData(CF_UNICODETEXT, hGlobal) == IntPtr.Zero)
                    {
                        lastError = new InvalidOperationException(
                            $"SetClipboardData 失败 (Win32 错误码={Marshal.GetLastWin32Error()})");
                        return false;
                    }
                    // 句柄所有权已转移给系统，不能再 GlobalFree
                    hGlobal = IntPtr.Zero;
                    return true;
                }
                finally
                {
                    CloseClipboard();
                }
            }
            catch (Exception ex)
            {
                lastError = ex;
                return false;
            }
            finally
            {
                if (hGlobal != IntPtr.Zero)
                {
                    GlobalFree(hGlobal);
                }
            }
        }
    }
}
