rule Sentinel_Test_Artifact
{
    meta:
        description = "Harmless validation rule for Sentinel YARA pipeline"
        purpose = "test-only"
    strings:
        $marker = "SENTINEL_YARA_TEST_MARKER"
    condition:
        $marker
}
