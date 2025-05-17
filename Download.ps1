# Silent DLL downloader from Catbox + copy to SysWOW64
# Run as Administrator

$dlls = @(
    @{ Name = "file1.dll"; Url = "https://files.catbox.moe/abc123.dll" },
    @{ Name = "file2.dll"; Url = "https://files.catbox.moe/def456.dll" },
    @{ Name = "file3.dll"; Url = "https://files.catbox.moe/ghi789.dll" }
)

$temp = "$env:TEMP\CatboxDLLs"
New-Item -ItemType Directory -Path $temp -Force | Out-Null

foreach ($dll in $dlls) {
    $outPath = Join-Path $temp $dll.Name
    Invoke-WebRequest -Uri $dll.Url -OutFile $outPath -UseBasicParsing
}

foreach ($dll in $dlls) {
    Copy-Item -Path (Join-Path $temp $dll.Name) -Destination "C:\Windows\SysWOW64\$($dll.Name)" -Force
}

[System.Windows.MessageBox]::Show("All DLLs downloaded and installed successfully.", "Done", "OK", "Information")
