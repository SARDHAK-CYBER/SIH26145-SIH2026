rule EICAR_Test_File
{
    meta:
        description = "Detects the standard EICAR antivirus test string. This is NOT malware -- it's a publicly documented, intentionally harmless test signature published by EICAR specifically so scanner pipelines can be verified safely."
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
        severity = "info"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}
