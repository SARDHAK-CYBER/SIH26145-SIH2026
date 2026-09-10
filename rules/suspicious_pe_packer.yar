rule Suspicious_PE_Common_Packer_Sections
{
    meta:
        description = "Flags PE files containing section names commonly associated with runtime packers. This is a heuristic, not a definitive malware signature -- legitimate packed software will also match. Treat matches as leads, not verdicts."
        severity = "medium"

    strings:
        $mz = { 4D 5A }
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx_sig = "UPX!" ascii
        $aspack = ".aspack" ascii
        $petite = ".petite" ascii

    condition:
        $mz at 0 and any of ($upx0, $upx1, $upx_sig, $aspack, $petite)
}

// Starting point only. For real threat-intel-grade coverage, pull rules
// from established open-source repositories rather than hand-authoring
// malware-family signatures from scratch -- e.g. the Yara-Rules project
// (github.com/Yara-Rules/rules) or Florian Roth's signature-base
// (github.com/Neo23x0/signature-base). Drop any .yar files from those
// into this rules/ directory and eng08_yara_scan.py will load them
// automatically.
