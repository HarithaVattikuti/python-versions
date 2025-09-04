[String] $Architecture = "{{__ARCHITECTURE__}}"
[String] $HardwareArchitecture = "{{__HARDWARE_ARCHITECTURE__}}"
[String] $Version = "{{__VERSION__}}"
[String] $PythonExecName = "{{__PYTHON_EXEC_NAME__}}"

function Get-RegistryVersionFilter {
    param(
        [Parameter(Mandatory)][String] $Architecture,
        [Parameter(Mandatory)][Int32] $MajorVersion,
        [Parameter(Mandatory)][Int32] $MinorVersion
    )

    $archFilter = if ($Architecture -eq 'x86') { "32-bit" } else { "64-bit" }
    "Python $MajorVersion.$MinorVersion.*($archFilter)"
}

function Remove-RegistryEntries {
    param(
        [Parameter(Mandatory)][String] $Architecture,
        [Parameter(Mandatory)][Int32] $MajorVersion,
        [Parameter(Mandatory)][Int32] $MinorVersion
    )

    $versionFilter = Get-RegistryVersionFilter -Architecture $Architecture -MajorVersion $MajorVersion -MinorVersion $MinorVersion

    $regPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products"
    if (Test-Path -Path Registry::$regPath) {
        $regKeys = Get-ChildItem -Path Registry::$regPath -Recurse | Where-Object Property -Ccontains DisplayName
        foreach ($key in $regKeys) {
            if ($key.getValue("DisplayName") -match $versionFilter) {
                Remove-Item -Path $key.PSParentPath -Recurse -Force -Verbose
            }
        }
    }

    $regPath = "HKEY_CLASSES_ROOT\Installer\Products"
    if (Test-Path -Path Registry::$regPath) {
        Get-ChildItem -Path Registry::$regPath | Where-Object { $_.GetValue("ProductName") -match $versionFilter } | ForEach-Object {
            Remove-Item Registry::$_ -Recurse -Force -Verbose
        }
    }

    $uninstallRegistrySections = @(
        "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall",  # current user, x64
        "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall", # all users, x64
        "HKEY_CURRENT_USER\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",  # current user, x86
        "HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"  # all users, x86
    )

    $uninstallRegistrySections | Where-Object { Test-Path -Path Registry::$_ } | ForEach-Object {
        Get-ChildItem -Path Registry::$_ | Where-Object { $_.getValue("DisplayName") -match $versionFilter } | ForEach-Object {
            Remove-Item Registry::$_ -Recurse -Force -Verbose
        }
    }
}

function Get-ExecParams {
    param(
        [Parameter(Mandatory)][Boolean] $IsMSI,
        [Parameter(Mandatory)][Boolean] $IsFreeThreaded,
        [Parameter(Mandatory)][String] $PythonArchPath
    )

    if ($IsMSI) {
        "TARGETDIR=$PythonArchPath ALLUSERS=1"
    } else {
        $Include_freethreaded = if ($IsFreeThreaded) { "Include_freethreaded=1" } else { "" }
        "DefaultAllUsersTargetDir=$PythonArchPath InstallAllUsers=1 $Include_freethreaded"
    }
}

$ToolcacheRoot = $env:AGENT_TOOLSDIRECTORY
if ([string]::IsNullOrEmpty($ToolcacheRoot)) {
    # GitHub images don't have `AGENT_TOOLSDIRECTORY` variable
    $ToolcacheRoot = $env:RUNNER_TOOL_CACHE
}
$PythonToolcachePath = Join-Path -Path $ToolcacheRoot -ChildPath "Python"
$PythonVersionPath = Join-Path -Path $PythonToolcachePath -ChildPath $Version
$PythonArchPath = Join-Path -Path $PythonVersionPath -ChildPath $Architecture

# Clean previous install for the target architecture and version
if (Test-Path $PythonArchPath) {
    Write-Host "Cleaning up previous Python install at $PythonArchPath"
    Remove-Item -Path $PythonArchPath -Recurse -Force
}
# Extra: Remove all possible Python registry uninstall entries (x86/x64/ARM64)
$allPythonUninstallRegKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)
foreach ($regKey in $allPythonUninstallRegKeys) {
    Write-Host "Cleaning up previous Python install at regkey: $regKey "

    if (Test-Path $regKey) {
        Get-ChildItem $regKey | Where-Object {
            try { $_.GetValue("DisplayName") -like "Python*" } catch { $false }
        } | ForEach-Object {
            Write-Host $_.PsPath
            Remove-Item $_.PsPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Remove additional cache and program files directories before install
$dirsToClean = @(
    "C:\Program Files\Python*",
    "C:\Program Files (x86)\Python*",
    "$env:APPDATA\Python*",
    "$env:LOCALAPPDATA\Python*",
    "C:\Users\runneradmin\AppData\Local\Package Cache"
)
foreach ($dir in $dirsToClean) {
    Write-Host "Clean the dir: $dir"
    Get-ChildItem -Path $dir -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

# Extra registry cleanup for Python, in addition to your Remove-RegistryEntries
$pythonRegKeys = @(
    "HKLM:\SOFTWARE\Python",
    "HKCU:\SOFTWARE\Python",
    "HKLM:\SOFTWARE\WOW6432Node\Python",
    "HKCU:\SOFTWARE\WOW6432Node\Python"
)
foreach ($regKey in $pythonRegKeys) {
    try {
        if (Test-Path $regKey) {
            Write-Host "Cleaning registry: $regKey"
            Remove-Item -Path $regKey -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch { Write-Host "Error cleaning registry $regKey: $_" }
}

Write-Host "User: $env:USERNAME"
Write-Host "User Profile: $env:USERPROFILE"
Write-Host "Processor Architecture: $env:PROCESSOR_ARCHITECTURE"
Write-Host "OS Version: $([System.Environment]::OSVersion.Version)"
Write-Host "IsAdmin: $([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"

Write-Host "Recent MSIInstaller Events:"
Get-WinEvent -FilterHashtable @{
    LogName = 'Application'
    ProviderName = 'MsiInstaller'
    StartTime = (Get-Date).AddMinutes(-15)
} | Select-Object -Property TimeCreated, Message | Format-List

# Before install
$packageCache = "C:\ProgramData\Package Cache"
if (Test-Path $packageCache) {
    Write-Host "Cleaning up Package Cache"
    Remove-Item -Path $packageCache -Recurse -Force -ErrorAction SilentlyContinue
}

$IsMSI = $PythonExecName -match "msi"
Write-Host "Is MSI $IsMSI"

$IsFreeThreaded = $Architecture -match "-freethreaded"

$MajorVersion = $Version.Split('.')[0]
$MinorVersion = $Version.Split('.')[1]

Write-Host "Check if Python hostedtoolcache folder exist..."
if (-Not (Test-Path $PythonToolcachePath)) {
    Write-Host "Create Python toolcache folder"
    New-Item -ItemType Directory -Path $PythonToolcachePath | Out-Null
}

Write-Host "Check if current Python version is installed..."
$InstalledVersions = Get-Item "$PythonToolcachePath\$MajorVersion.$MinorVersion.*\$Architecture"

if ($null -ne $InstalledVersions) {
    Write-Host "Python$MajorVersion.$MinorVersion ($Architecture) was found in $PythonToolcachePath..."

    foreach ($InstalledVersion in $InstalledVersions) {
        if (Test-Path -Path $InstalledVersion) {
            Write-Host "Deleting $InstalledVersion..."
            Remove-Item -Path $InstalledVersion -Recurse -Force
            if (Test-Path -Path "$($InstalledVersion.Parent.FullName)/${Architecture}.complete") {
                Remove-Item -Path "$($InstalledVersion.Parent.FullName)/${Architecture}.complete" -Force -Verbose
            }
        }
    }
} else {
    Write-Host "No Python$MajorVersion.$MinorVersion.* found"
}

Write-Host "Remove registry entries for Python ${MajorVersion}.${MinorVersion}(${Architecture})..."
Remove-RegistryEntries -Architecture $Architecture -MajorVersion $MajorVersion -MinorVersion $MinorVersion

Write-Host "Create Python $Version folder in $PythonToolcachePath"
New-Item -ItemType Directory -Path $PythonArchPath -Force | Out-Null

Write-Host "Copy Python binaries to $PythonArchPath"
Copy-Item -Path ./$PythonExecName -Destination $PythonArchPath | Out-Null

Write-Host "Install Python $Version in $PythonToolcachePath..."
$ExecParams = Get-ExecParams -IsMSI $IsMSI -IsFreeThreaded $IsFreeThreaded -PythonArchPath $PythonArchPath

Write-Host "PythonArchPath $PythonArchPath  PythonExecName $PythonExecName ExecParams $ExecParams"

# Check system architecture
$systemArchitecture = (Get-CimInstance -ClassName Win32_ComputerSystem).SystemType
Write-Host "System architecture detected: $systemArchitecture"

# Validate architecture using $env:PROCESSOR_ARCHITECTURE
$processorArchitecture = $env:PROCESSOR_ARCHITECTURE
Write-Host "Processor architecture detected using environment variable: $processorArchitecture"

# Architecture check (abort on mismatch)
if ($systemArchitecture -notmatch "ARM64" -or $processorArchitecture -notmatch "ARM64") {
    Throw "System or processor architecture ($systemArchitecture/$processorArchitecture) does not match installer (ARM64)."
}

try {
    # $installCommand = "cd $PythonArchPath && call $PythonExecName $ExecParams /passive /norestart /log install.log"

    # Add extra MSI logging for deep troubleshooting
    $msiLog = "$PythonArchPath\msi-verbose.log"
    if ($IsMSI) {
        $installCommand = "cd $PythonArchPath && call $PythonExecName $ExecParams /passive /norestart /log install.log /L*V `"$msiLog`""
    } else {
        $installCommand = "cd $PythonArchPath && call $PythonExecName $ExecParams /passive /norestart /log install.log"
    }
    
    Write-Host "Executing command: $installCommand"

    $installOutput = cmd.exe /c $installCommand 2>&1
    Write-Host "Command output:"
    Write-Host $installOutput

    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error happened during Python installation:"
        Write-Host "Command executed: $installCommand"
        Write-Host "Output: $installOutput"
        Write-Host "LastExitCode: $LASTEXITCODE"

        if ($LASTEXITCODE -eq 1603) {
            Write-Host "Fatal error during installation. Check installer logs for more details."
        }

         # Print the contents of install.log
         if (Test-Path "$PythonArchPath\install.log") {
            Write-Host "Contents of install.log:"
            Get-Content "$PythonArchPath\install.log" -Raw
            Write-Host "End of install.log"
        } else {
            Write-Host "install.log file not found."
        }

        Throw "Error happened during Python installation"
    } else {
        Write-Host "Python installation completed successfully."
    }
} catch {
    Write-Host "An exception occurred:"
    Write-Host "Error: $($_.Exception.Message)"
    Write-Host "StackTrace: $($_.Exception.StackTrace)"
    Throw "Python installation failed due to an exception."
}

Write-Host "Installed files in $PythonToolcachePath\$MajorVersion.$MinorVersion"
Get-ChildItem -Path "$PythonToolcachePath\$MajorVersion.$MinorVersion.*" | ForEach-Object {
    Write-Host $_.FullName
}

Write-Host "Installed files in architecture:"
Get-ChildItem -Path "$PythonToolcachePath\$MajorVersion.$MinorVersion.*\$Architecture" | ForEach-Object {
    Write-Host $_.FullName
}

Write-Host "Files in $PythonArchPath"
Get-ChildItem -Path $PythonArchPath | ForEach-Object {
    Write-Host $_.FullName
}

if ($IsFreeThreaded) {
    # Delete python.exe and create a symlink to free-threaded exe
    Remove-Item -Path "$PythonArchPath\python.exe" -Force
    New-Item -Path "$PythonArchPath\python.exe" -ItemType SymbolicLink -Value "$PythonArchPath\python${MajorVersion}.${MinorVersion}t.exe"
}

Write-Host "Create `python3` symlink"
    New-Item -Path "$PythonArchPath\python3.exe" -ItemType SymbolicLink -Value "$PythonArchPath\python.exe"

Write-Host "Install and upgrade Pip"
$Env:PIP_ROOT_USER_ACTION = "ignore"
$PythonExePath = Join-Path -Path $PythonArchPath -ChildPath "python.exe"
cmd.exe /c "$PythonExePath -m ensurepip && $PythonExePath -m pip install --upgrade --force-reinstall pip --no-warn-script-location"
if ($LASTEXITCODE -ne 0) {
    Throw "Error happened during pip installation / upgrade"
}

Write-Host "Create complete file"
New-Item -ItemType File -Path $PythonVersionPath -Name "$Architecture.complete" | Out-Null
