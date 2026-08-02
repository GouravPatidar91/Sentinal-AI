import datetime
import math
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from backend.app.models.models import LogEntry

# Try importing sklearn. Fall back to statistical heuristics if unavailable.
HAS_SKLEARN = False
try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    import pandas as pd
    HAS_SKLEARN = True
except ImportError:
    pass

class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.is_trained = False
        self.last_trained_at = None

    def _extract_features(self, logs: List[LogEntry]) -> Tuple[Any, Any]:
        """
        Extracts features from a list of LogEntry models.
        Features:
          1. hour_of_day (0-23)
          2. log_severity_weight (INFO=0, WARNING=1, ERROR=2, CRITICAL=3)
          3. message_length
          4. is_weekend (0 or 1)
        """
        if not HAS_SKLEARN:
            return None, None
            
        features = []
        for log in logs:
            hr = log.timestamp.hour + log.timestamp.minute / 60.0
            sev = {"INFO": 0, "WARNING": 1, "ERROR": 2, "CRITICAL": 3}.get(log.severity.upper(), 0)
            msg_len = len(log.message)
            is_wknd = 1.0 if log.timestamp.weekday() >= 5 else 0.0
            
            features.append([hr, sev, msg_len, is_wknd])
            
        return np.array(features), len(logs)

    def train_model(self, db: Session) -> bool:
        """
        Trains the Isolation Forest model on historical log entries.
        """
        if not HAS_SKLEARN:
            return False
            
        try:
            # Query last 1000 logs
            logs = db.query(LogEntry).order_by(LogEntry.timestamp.desc()).limit(1000).all()
            if len(logs) < 30:
                # Insufficient data to train Isolation Forest
                self.is_trained = False
                return False
                
            X, count = self._extract_features(logs)
            
            # Fit Isolation Forest
            # contamination specifies the expected proportion of outliers
            self.model = IsolationForest(contamination=0.05, random_state=42)
            self.model.fit(X)
            self.is_trained = True
            self.last_trained_at = datetime.datetime.utcnow()
            return True
        except Exception as e:
            print(f"Error training anomaly detection model: {e}")
            self.is_trained = False
            return False

    def predict_anomaly(self, db: Session, log: LogEntry) -> float:
        """
        Predicts if a log entry is anomalous and returns a score from 0.0 to 1.0.
        0.0 = completely normal, 1.0 = highly anomalous.
        """
        # ----------------------------------------------------
        # Fallback 1: If sklearn is missing or not trained, use heuristic statistical rules
        # ----------------------------------------------------
        if not HAS_SKLEARN or not self.is_trained:
            return self._calculate_heuristic_anomaly(db, log)
            
        # ----------------------------------------------------
        # Isolation Forest Prediction
        # ----------------------------------------------------
        try:
            # Extract features for single log
            hr = log.timestamp.hour + log.timestamp.minute / 60.0
            sev = {"INFO": 0, "WARNING": 1, "ERROR": 2, "CRITICAL": 3}.get(log.severity.upper(), 0)
            msg_len = len(log.message)
            is_wknd = 1.0 if log.timestamp.weekday() >= 5 else 0.0
            
            X_test = np.array([[hr, sev, msg_len, is_wknd]])
            
            # score_samples returns negative anomaly scores (lower means more anomalous)
            # Typically range is [-0.8, -0.3]
            raw_score = self.model.score_samples(X_test)[0]
            
            # Map score to [0.0, 1.0] where 1.0 is anomaly
            # Decision boundary for isolation forest is around -0.5 (closer to -1.0 means anomalous)
            anomaly_score = max(0.0, min(1.0, (0.5 - raw_score) * 2.0))
            
            # Boost score based on statistical anomaly heuristics for validation
            heuristic_score = self._calculate_heuristic_anomaly(db, log)
            combined_score = (anomaly_score * 0.7) + (heuristic_score * 0.3)
            
            return round(combined_score, 4)
            
        except Exception as e:
            print(f"Error executing Isolation Forest prediction: {e}. Falling back to heuristics.")
            return self._calculate_heuristic_anomaly(db, log)

    def _calculate_heuristic_anomaly(self, db: Session, log: LogEntry) -> float:
        """
        Statistical heuristic outlier engine.
        Returns a value between 0.0 and 1.0 based on common SOC anomaly indicators.
        """
        score = 0.0
        
        # 1. Unusual Working Hours (11 PM to 5 AM)
        hour = log.timestamp.hour
        if 23 <= hour or hour <= 5:
            score += 0.3
            
        # 2. Weekend logins
        if log.timestamp.weekday() >= 5:
            score += 0.15
            
        # 3. High logon frequency check (brute force indicator)
        if log.username:
            recent_user_logs = db.query(LogEntry).filter(
                LogEntry.timestamp >= (datetime.datetime.utcnow() - datetime.timedelta(minutes=5)),
                LogEntry.username == log.username
            ).count()
            if recent_user_logs > 15:
                score += 0.4
            elif recent_user_logs > 5:
                score += 0.2
                
        # 4. Outlier traffic volume (Exfiltration)
        if "LEN=" in log.raw_log:
            try:
                # extract LEN value
                match = re.search(r"LEN=(\d+)", log.raw_log)
                if match:
                    packet_len = int(match.group(1))
                    if packet_len > 1400:
                        score += 0.35
                    elif packet_len > 800:
                        score += 0.15
            except Exception:
                pass
                
        # 5. Impossible traversal check
        if log.src_ip and log.username:
            # Find the previous log for this user from a different IP in the last 15 mins
            time_limit = datetime.datetime.utcnow() - datetime.timedelta(minutes=15)
            prev_log = db.query(LogEntry).filter(
                LogEntry.timestamp >= time_limit,
                LogEntry.username == log.username,
                LogEntry.src_ip != None,
                LogEntry.src_ip != log.src_ip
            ).first()
            if prev_log:
                score += 0.5  # Impossible physical travel indicator!
                
        # Limit score between 0.0 and 0.95 (AI investigation handles critical triggers)
        return min(0.95, score)

# Global instance of AnomalyDetector
anomaly_detector = AnomalyDetector()
