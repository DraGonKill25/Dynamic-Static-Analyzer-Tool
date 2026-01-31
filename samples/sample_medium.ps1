# Sample script - MEDIUM risk indicators (for testing only)
# Contains network, persistence, and C2 patterns

$config = @{
    ServerUrl = "https://api.example-config.com/settings"
    BackupPath = "C:\Users\Public\Documents\backup"
    CallbackUrl = "https://callback-server.evil.tk/api"
}

# Registry persistence pattern
$regPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"

# C2 / callback pattern (for testing)
$c2_server = "command and control"
$beacon_interval = 60

# Sandbox/VM check (for testing - matches anti_analysis patterns)
$isVM = $env:VIRTUALBOX_GUEST -or (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer -like "*vmware*"

# Network connectivity check
$endpoints = @(
    "http://192.168.1.100:8080/status",
    "https://config.example.org/v1/config",
    "192.168.0.1",
    "http://10.0.0.5:31337"
)

# PowerShell invocation (triggers YARA)
powershell -encodedcommand base64datahere
Invoke-Expression $command
