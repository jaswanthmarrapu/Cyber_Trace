from typing import Optional, List, Dict, Any
from app.forensic.ip_analyzer import (
    investigate_single_ip,
    extract_ips_from_log_content,
    analyze_ip_log_metrics,
    validate_ipv4,
    classify_ip_scope
)

def investigate_ip_address(
    ip_str: str,
    enable_public_intel: bool = True,
    intel_api_key: Optional[str] = None
) -> Dict[str, Any]:
    """Execute complete IP investigation with observed vs reputation separation."""
    return investigate_single_ip(
        ip_str=ip_str,
        enable_public_intel=enable_public_intel,
        intel_api_key=intel_api_key
    )

def extract_and_analyze_ips_from_log(content_text: str) -> Dict[str, Any]:
    """Extract all IPs from uploaded log text, validate, and compute connection/failure metrics."""
    extracted_ips = extract_ips_from_log_content(content_text)
    metrics_by_ip = analyze_ip_log_metrics(content_text)
    return {
        "total_unique_ips": len(extracted_ips),
        "extracted_ips": extracted_ips,
        "metrics": metrics_by_ip
    }
