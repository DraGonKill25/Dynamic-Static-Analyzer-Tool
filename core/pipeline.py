#! Conditional analysis pipeline

import configparser


def load_pipeline_config(config_path: str) -> dict:
    """Loads pipeline configuration."""
    config = configparser.ConfigParser()
    config.read(config_path)
    pipeline = {"vt_threshold": 1, "enable_whois": False}
    if "PIPELINE" in config:
        pipeline["vt_threshold"] = config["PIPELINE"].getint("vt_threshold", 1)
        pipeline["enable_whois"] = config["PIPELINE"].getboolean("enable_whois", False)
    return pipeline


def should_run_full_analysis(vt_positives: int, pipeline_config: dict) -> bool:
    """If VirusTotal > X detections → run full analysis."""
    return vt_positives >= pipeline_config.get("vt_threshold", 1)


def should_enrich_whois(has_urls_or_ips: bool, pipeline_config: dict) -> bool:
    """If URLs/IPs present and option enabled → WHOIS enrichment."""
    return has_urls_or_ips and pipeline_config.get("enable_whois", False)
