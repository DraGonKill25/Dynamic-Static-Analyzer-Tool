rule Example_SuspiciousPowerShell {
    meta:
        description = "Example rule - suspicious PowerShell patterns"
        author = "MalwareAnalyzer"
    strings:
        $a = "powershell" nocase
        $b = "-encodedcommand" nocase
        $c = "Invoke-Expression" nocase
    condition:
        2 of ($a, $b, $c)
}
