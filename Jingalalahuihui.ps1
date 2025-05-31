# Auto-elevation
function Ensure-RunAsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`""
        $psi.Verb = "runas"
        $psi.UseShellExecute = $true
        $psi.WindowStyle = 'Hidden'
        try {
            [System.Diagnostics.Process]::Start($psi) | Out-Null
        } catch {
            Write-Error "User cancelled the elevation prompt."
        }
        exit
    }
}
Ensure-RunAsAdmin

# imgui.ini monitor
Start-Job -ScriptBlock {
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    $iniPath = Join-Path $desktopPath "imgui.ini"
    while ($true) {
        if (Test-Path $iniPath) {
            try {
                Remove-Item $iniPath -Force -ErrorAction SilentlyContinue
                Write-Output "Deleted imgui.ini at $(Get-Date -Format 'HH:mm:ss')"
            } catch {}
        }
        Start-Sleep -Milliseconds 50
    }
} | Out-Null

# DLL Injector C# Code
$injectorCode = @"
using System;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class Injector {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProc, IntPtr addr, uint size, uint allocType, uint protect);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProc, IntPtr addr, byte[] buffer, uint size, out UIntPtr written);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hMod, string procName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string modName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProc, IntPtr attrs, uint stackSize, IntPtr startAddr, IntPtr param, uint flags, IntPtr threadId);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);

    public const int PROCESS_ALL = 0x1F0FFF;
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint PAGE_READWRITE = 0x04;

    public static bool Inject(int pid, string dllPath) {
        IntPtr hProc = OpenProcess(PROCESS_ALL, false, pid);
        if (hProc == IntPtr.Zero) return false;

        IntPtr addr = VirtualAllocEx(hProc, IntPtr.Zero, (uint)((dllPath.Length + 1) * 2), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (addr == IntPtr.Zero) return false;

        byte[] bytes = Encoding.Unicode.GetBytes(dllPath);
        UIntPtr written;
        if (!WriteProcessMemory(hProc, addr, bytes, (uint)bytes.Length, out written)) return false;

        IntPtr hMod = GetModuleHandle("kernel32.dll");
        IntPtr loadLib = GetProcAddress(hMod, "LoadLibraryW");
        if (loadLib == IntPtr.Zero) return false;

        IntPtr thread = CreateRemoteThread(hProc, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
        if (thread == IntPtr.Zero) return false;

        CloseHandle(hProc);
        return true;
    }
}

public class KeyCheck {
    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);

    public static bool IsDelPressed() {
        return (GetAsyncKeyState(0x2E) & 0x8000) != 0;
    }
}
"@
Add-Type -TypeDefinition $injectorCode -Language CSharp

# Paths & Dlls
$dllFolder = "C:\Windows\SysWOW64"
$system32Path = "$env:windir\System32"

$dll1 = Join-Path $dllFolder "Aotbst.dll"
$dll2 = Join-Path $dllFolder "cimgui.dll"
$dll3 = Join-Path $dllFolder "dwmhost.dll"
$dll3Dest = Join-Path $system32Path "dwmhost.dll"
$extraDll = "abal.dll"
$extraDllPath = Join-Path $system32Path $extraDll

$targetProcess = "HD-Player"
$monitoringTools = @("Taskmgr", "ProcessHacker", "procexp", "SystemInformer")

# Monitor thread for abal.dll
Start-Job -ScriptBlock {
    while ($true) {
        foreach ($name in $using:monitoringTools) {
            $proc = Get-Process -Name $name -ErrorAction SilentlyContinue
            if ($proc) {
                foreach ($p in $proc) {
                    Write-Output "Detected $($p.ProcessName). Attempting to inject $using:extraDll..."
                    $result = [Injector]::Inject($p.Id, $using:extraDllPath)
                    if ($result) {
                        Write-Output "Injected $using:extraDll into $($p.ProcessName) (PID: $($p.Id))"
                    } else {
                        Write-Error "Failed to inject $using:extraDll into $($p.ProcessName)"
                    }
                }
            }
        }
        Start-Sleep -Seconds 2
    }
} | Out-Null

# Main DLL injection for HD-Player
Write-Output "Monitoring for process $targetProcess..."
while ($true) {
    $proc = Get-Process -Name $targetProcess -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Output "Process $targetProcess found with PID $($proc.Id)"
        Write-Output "Waiting for [Del] key to inject main DLLs..."
        while (-not [KeyCheck]::IsDelPressed()) {
            Start-Sleep -Milliseconds 50
        }

        try {
            Copy-Item -Path $dll3 -Destination $dll3Dest -Force
            Write-Output "Copied dwmhost.dll to $system32Path"
        } catch {
            Write-Error "Failed to copy dwmhost.dll. Try running as Administrator."
        }

        foreach ($dll in @($dll1, $dll2)) {
            Write-Output "Injecting $dll..."
            $result = [Injector]::Inject($proc.Id, $dll)
            if ($result) {
                Write-Output "Successfully injected $dll"
            } else {
                Write-Error "Failed to inject $dll"
            }
        }

        do {
            Start-Sleep -Seconds 2
            $proc = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
        } while ($proc)

        Write-Output "$targetProcess exited. Resuming monitoring..."
    } else {
        Start-Sleep -Seconds 2
    }
}
