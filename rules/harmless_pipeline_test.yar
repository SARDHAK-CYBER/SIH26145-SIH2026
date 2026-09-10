rule StealthTap_Pipeline_Test
{
    meta:
        description = "Harmless marker string used only to verify the YARA scan pipeline end-to-end. No security significance -- will never trigger antivirus."

    strings:
        $marker = "STEALTHTAP_YARA_PIPELINE_TEST_OK_2026"

    condition:
        $marker
}
