import math
from typing import List
from backend.app.models.models import DetectionRule

def calculate_risk_score(
    rules_triggered: List[DetectionRule],
    anomaly_score: float = 0.0,
    host_importance: float = 1.0,
    event_count: int = 1
) -> int:
    """
    Calculates a dynamic risk score from 0 to 100.
    Based on:
      - Triggered Rules Severity (Critical=45, High=30, Warning=15, Info=5)
      - Anomaly Boost (outlier scoring up to +20 points)
      - Event Frequency (log-based volume booster)
      - Asset Importance (multiplier for critical servers)
    """
    severity_weights = {
        "CRITICAL": 45,
        "HIGH": 30,
        "WARNING": 15,
        "INFO": 5
    }
    
    if not rules_triggered:
        # Defaults if only raw anomaly is checked
        base_score = 10
    else:
        # Sum of unique rules triggered to avoid double-counting same rule duplicates
        unique_rules = {r.id: r for r in rules_triggered if r}
        base_score = sum(severity_weights.get(r.severity.upper(), 5) for r in unique_rules.values())
        
    # Anomaly boost (0.0 to 1.0 -> 0 to 20 points)
    anomaly_boost = max(0.0, min(1.0, anomaly_score)) * 20
    
    # Event volume frequency boost (log-scale)
    frequency_boost = math.log2(event_count + 1) * 2.5
    
    # Apply asset multiplier
    raw_score = (base_score + anomaly_boost + frequency_boost) * host_importance
    
    # Cap between 0 and 100
    risk_score = int(max(0, min(100, raw_score)))
    return risk_score
