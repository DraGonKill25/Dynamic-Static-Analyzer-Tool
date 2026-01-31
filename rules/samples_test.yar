rule Sample_BeaconC2 {
    meta:
        description = "C2 beacon pattern"
    strings:
        $a = "beacon" nocase
        $b = "callback" nocase
        $c = "c2=" nocase
    condition:
        1 of ($a, $b, $c)
}

rule Sample_AntiAnalysis {
    meta:
        description = "Anti-analysis indicators"
    strings:
        $a = "sandbox" nocase
        $b = "debugger" nocase
        $c = "virtualbox" nocase
        $d = "vmware" nocase
    condition:
        1 of ($a, $b, $c, $d)
}

rule Sample_Persistence {
    meta:
        description = "Persistence mechanisms"
    strings:
        $a = "CurrentVersion\\Run"
        $b = "@reboot"
        $c = "systemd"
    condition:
        1 of ($a, $b, $c)
}

rule Sample_EncodedCommand {
    meta:
        description = "Encoded command pattern"
    strings:
        $a = "-encodedcommand" nocase
        $b = "Invoke-Expression" nocase
    condition:
        1 of ($a, $b)
}

rule Sample_SuspiciousPath {
    meta:
        description = "Suspicious path"
    strings:
        $a = "C:\\Windows\\Temp\\"
        $b = "/opt/malware"
    condition:
        1 of ($a, $b)
}
