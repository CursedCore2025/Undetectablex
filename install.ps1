
# ---- [ Start imgui.ini Monitor Loop as a background job ] ----
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

Write-Output "Monitoring for process $processName..."

while ($true) {
    $proc = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Output "Process $processName found with PID $($proc.Id)"
        Write-Output "Waiting for [Del] key to inject DLLs..."

        while (-not [KeyCheck]::IsDelPressed()) {
            Start-Sleep -Milliseconds 50
        }

        Write-Output "[Del] pressed. Proceeding with DLL injection..."

        try {
            Copy-Item -Path (Join-Path $dllFolder $dll3) -Destination $destDll3Path -Force
            Write-Output "Copied $dll3 to $system32Path"
        } catch {
            Write-Error "Failed to copy $dll3 to $system32Path. Run PowerShell as Administrator."
            exit 1
        }

        $dll1Path = Join-Path $dllFolder $dll1
        $dll2Path = Join-Path $dllFolder $dll2

        foreach ($dll in @($dll1Path, $dll2Path)) {
            Write-Output "Injecting $dll into process $processName (PID: $($proc.Id))..."
            $success = [Injector]::Inject($proc.Id, $dll)
            if ($success) {
                Write-Output "Successfully injected $dll"
            } else {
                Write-Error "Failed to inject $dll"
            }
        }

        do {
            Start-Sleep -Seconds 2
            $proc = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
        } while ($proc)

        Write-Output "$processName exited. Resuming monitoring..."
    } else {
        Start-Sleep -Seconds 2
    }
}
