# Create/Update Sentinel Network Assistant desktop shortcut
# Run this script with PowerShell to create the shortcut

$WScriptShell = New-Object -ComObject WScript.Shell
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $DesktopPath "Sentinel Network Assistant.lnk"

# Project paths
$ProjectRoot = "J:\dev\Sentinel"
$IconPath = Join-Path $ProjectRoot "src\sentinel\assets\sentinel.ico"

# Try to find Python in order of preference
$PythonPaths = @(
    (Join-Path $ProjectRoot ".venv\Scripts\pythonw.exe"),
    "C:\Python314\pythonw.exe",
    "C:\Python313\pythonw.exe",
    "C:\Python312\pythonw.exe",
    "C:\Python311\pythonw.exe",
    "C:\Python310\pythonw.exe"
)

$PythonExe = $null
foreach ($path in $PythonPaths) {
    if (Test-Path $path) {
        $PythonExe = $path
        break
    }
}

if (-not $PythonExe) {
    Write-Error "Could not find pythonw.exe. Please ensure Python is installed."
    exit 1
}

# Create shortcut
$Shortcut = $WScriptShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $PythonExe
$Shortcut.Arguments = "-m sentinel.gui.app"
$Shortcut.WorkingDirectory = $ProjectRoot
$Shortcut.Description = "Sentinel Network Assistant - AI-Native Network Management"
$Shortcut.IconLocation = $IconPath

# Save the shortcut
$Shortcut.Save()

Write-Host "Shortcut created/updated at: $ShortcutPath"
Write-Host "Target: $PythonExe -m sentinel.gui.app"
Write-Host "Working Directory: $ProjectRoot"
Write-Host "Icon: $IconPath"
