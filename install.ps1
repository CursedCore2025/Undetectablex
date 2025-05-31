# Auto-elevation function: Relaunch script as admin if not elevated, fully hidden
function Ensure-RunAsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $isAdmin) {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"
        # Pass -WindowStyle Hidden so the window never appears on elevation
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`""
        $psi.Verb = "runas"              # Run as administrator
        $psi.UseShellExecute = $true     # Required to use Verb
        $psi.WindowStyle = 'Hidden'      # Hide the window
        try {
            [System.Diagnostics.Process]::Start($psi) | Out-Null
        } catch {
            Write-Error "User cancelled the elevation prompt."
        }
        exit
    }
}

Ensure-RunAsAdmin

# ---- [ Start imgui.ini Monitor Loop as a background job ] ----
Start-Job -ScriptBlock {
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    $iniPath = Join-Path $desktopPath "imgui.ini"
    while ($true) {
        if (Test-Path $iniPath) {
            try {
                Remove-Item $iniPath -Force -ErrorAction SilentlyContinue
                # Output hidden — no Write-Output here so no window or console spam
            } catch {}
        }
        Start-Sleep -Milliseconds 50
    }
} | Out-Null

# ---- [ DLL Injection Section ] ----
$dllFolder = "C:\Windows\SysWOW64"
$dll1 = "Aotbst.dll"
$dll2 = "cimgui.dll"
$dll3 = "dwmhost.dll"
$processName = "HD-Player"
$system32Path = "$env:windir\System32"
$destDll3Path = Join-Path -Path $system32Path -ChildPath $dll3

$injectorCode = @"
using System;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class Injector
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, out UIntPtr written);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
        uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    public const int PROCESS_CREATE_THREAD = 0x0002;
    public const int PROCESS_QUERY_INFORMATION = 0x0400;
    public const int PROCESS_VM_OPERATION = 0x0008;
    public const int PROCESS_VM_WRITE = 0x0020;
    public const int PROCESS_VM_READ = 0x0010;

    public const uint MEM_COMMIT = 0x00001000;
    public const uint MEM_RESERVE = 0x00002000;
    public const uint PAGE_READWRITE = 0x04;

    public static bool Inject(int pid, string dllPath)
    {
        IntPtr hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, pid);
        if (hProcess == IntPtr.Zero)
            return false;

        IntPtr allocMemAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (allocMemAddress == IntPtr.Zero)
            return false;

        byte[] bytes = Encoding.Unicode.GetBytes(dllPath);
        UIntPtr bytesWritten;
        bool result = WriteProcessMemory(hProcess, allocMemAddress, bytes, (uint)bytes.Length, out bytesWritten);
        if (!result || bytesWritten.ToUInt32() != bytes.Length)
            return false;

        IntPtr kernel32Handle = GetModuleHandle("kernel32.dll");
        IntPtr loadLibraryAddr = GetProcAddress(kernel32Handle, "LoadLibraryW");

        if (loadLibraryAddr == IntPtr.Zero)
            return false;

        IntPtr remoteThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);
        if (remoteThread == IntPtr.Zero)
            return false;

        CloseHandle(hProcess);
        return true;
    }
}

public class KeyCheck
{
    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);

    public static bool IsDelPressed()
    {
        return (GetAsyncKeyState(0x2E) & 0x8000) != 0;
    }
}
"@

Add-Type -TypeDefinition $injectorCode -Language CSharp

# Silent monitoring loop (no Write-Output to avoid any console output)
while ($true) {
    $proc = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($proc) {
        # No output, running hidden silently
        while (-not [KeyCheck]::IsDelPressed()) {
            Start-Sleep -Milliseconds 50
        }

        # Del pressed, inject DLLs
        try {
            Copy-Item -Path (Join-Path $dllFolder $dll3) -Destination $destDll3Path -Force
        } catch {
            # If copying fails, silently exit (no console)
            exit 1
        }

        $dll1Path = Join-Path $dllFolder $dll1
        $dll2Path = Join-Path $dllFolder $dll2

        foreach ($dll in @($dll1Path, $dll2Path)) {
            $success = [Injector]::Inject($proc.Id, $dll)
            # no output, keep silent
        }

        do {
            Start-Sleep -Seconds 2
            $proc = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
        } while ($proc)
    } else {
        Start-Sleep -Seconds 2
    }
}
