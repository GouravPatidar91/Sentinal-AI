import datetime
import math
import re
from typing import List, Dict, Any, Tuple, Optional
from sqlalchemy.orm import Session
from backend.app.models.models import LogEntry

# Try importing scikit-learn / numpy
HAS_SKLEARN = False
try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    HAS_SKLEARN = True
except ImportError:
    pass

class UserBaselineProfile:
    """
    Stores baseline behavioral profiles per user / host.
    """
    def __init__(self):
        self.user_ips: Dict[str, set] = {}
        self.user_avg_hour: Dict[str, float] = {}
        self.user_log_counts: Dict[str, int] = {}
        self.user_avg_payload_len: Dict[str, float] = {}

    def update(self, username: str, ip: Optional[str], hour: float, payload_len: int):
        if not username:
            return
        if username not in self.user_ips:
            self.user_ips[username] = set()
            self.user_avg_hour[username] = hour
            self.user_log_counts[username] = 1
            self.user_avg_payload_len[username] = float(payload_len)
        else:
            if ip and ip not in ["-", "127.0.0.1", "::1"]:
                self.user_ips[username].add(ip)
            count = self.user_log_counts[username]
            self.user_avg_hour[username] = (self.user_avg_hour[username] * count + hour) / (count + 1)
            self.user_avg_payload_len[username] = (self.user_avg_payload_len[username] * count + payload_len) / (count + 1)
            self.user_log_counts[username] += 1


class AnomalyDetector:
    """
    Unsupervised Machine Learning Anomaly Detection Engine.
    Combines Isolation Forest, User Baseline Modeling, Impossible Travel Detection,
    and Data Exfiltration Volume Analysis.
    """
    def __init__(self):
        self.model = None
        self.is_trained = False
        self.last_trained_at = None
        self.baseline = UserBaselineProfile()

    def _extract_features(self, logs: List[LogEntry]) -> Tuple[Any, int]:
        """
        Extracts multi-dimensional features for Isolation Forest model:
          1. hour_of_day (0-23.99)
          2. severity_weight (INFO=0, WARNING=1, ERROR=2, CRITICAL=3)
          3. message_length
          4. is_weekend (0 or 1)
          5. payload_length
        """
        if not HAS_SKLEARN:
            return None, 0
            
        features = []
        for log in logs:
            hr = log.timestamp.hour + log.timestamp.minute / 60.0
            sev = {"INFO": 0, "WARNING": 1, "ERROR": 2, "CRITICAL": 3}.get(log.severity.upper(), 0)
            msg_len = len(log.message)
            is_wknd = 1.0 if log.timestamp.weekday() >= 5 else 0.0
            payload_len = len(log.raw_log)
            
            features.append([hr, sev, msg_len, is_wknd, payload_len])
            
        return np.array(features), len(logs)

    def train_model(self, db: Session) -> bool:
        """
        Trains the Isolation Forest unsupervised model on historical logs and builds user baselines.
        """
        try:
            logs = db.query(LogEntry).order_by(LogEntry.timestamp.desc()).limit(1000).all()
            
            # Populate baseline user profiles
            for log in logs:
                if log.username:
                    hr = log.timestamp.hour + log.timestamp.minute / 60.0
                    self.baseline.update(log.username, log.src_ip, hr, len(log.raw_log))

            if not HAS_SKLEARN or len(logs) < 20:
                self.is_trained = False
                return False
                
            X, count = self._extract_features(logs)
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
        Predicts an anomaly score between 0.0 (completely normal) and 1.0 (highly anomalous).
        """
        ml_score = 0.0
        
        # 1. Isolation Forest Unsupervised Model
        if HAS_SKLEARN and self.is_trained:
            try:
                hr = log.timestamp.hour + log.timestamp.minute / 60.0
                sev = {"INFO": 0, "WARNING": 1, "ERROR": 2, "CRITICAL": 3}.get(log.severity.upper(), 0)
                msg_len = len(log.message)
                is_wknd = 1.0 if log.timestamp.weekday() >= 5 else 0.0
                payload_len = len(log.raw_log)
                
                X_test = np.array([[hr, sev, msg_len, is_wknd, payload_len]])
                raw_score = self.model.score_samples(X_test)[0]
                # Map score to [0.0, 1.0]
                ml_score = max(0.0, min(1.0, (0.5 - raw_score) * 2.0))
            except Exception as e:
                print(f"Isolation Forest inference error: {e}")
                ml_score = 0.0

        # 2. Heuristic Behavioral Analysis (Impossible Travel, Exfiltration, Off-hours)
        behavioral_score = self._evaluate_behavioral_anomalies(db, log)

        # Update user baseline profile dynamically
        if log.username:
            hr = log.timestamp.hour + log.timestamp.minute / 60.0
            self.baseline.update(log.username, log.src_ip, hr, len(log.raw_log))

        # Blend ML model score and Behavioral baseline score
        if ml_score > 0:
            final_score = (ml_score * 0.5) + (behavioral_score * 0.5)
        else:
            final_score = behavioral_score

        return round(min(0.99, max(0.0, final_score)), 4)

    def _evaluate_behavioral_anomalies(self, db: Session, log: LogEntry) -> float:
        score = 0.0
        
        # A. Impossible Travel Detection
        if log.src_ip and log.username and log.src_ip not in ["-", "127.0.0.1", "::1"]:
            time_window = datetime.datetime.utcnow() - datetime.timedelta(minutes=30)
            prev_log = db.query(LogEntry).filter(
                LogEntry.timestamp >= time_window,
                LogEntry.username == log.username,
                LogEntry.src_ip != None,
                LogEntry.src_ip != "-",
                LogEntry.src_ip != "127.0.0.1",
                LogEntry.src_ip != log.src_ip
            ).first()
            if prev_log:
                # Rapid login location jump (Impossible Physical Travel)
                score += 0.55

        # B. Data Exfiltration Volume Outlier
        raw_text = log.raw_log or ""
        msg_text = log.message or ""
        len_match = re.search(r"LEN=(\d+)", raw_text)
        if len_match:
            bytes_sent = int(len_match.group(1))
            if bytes_sent > 1400:
                score += 0.40
            elif bytes_sent > 900:
                score += 0.20
        elif len(raw_text) > 800 or len(msg_text) > 500:
            score += 0.25

        # C. User Baseline Hour Deviation
        if log.username and log.username in self.baseline.user_avg_hour:
            current_hr = log.timestamp.hour + log.timestamp.minute / 60.0
            avg_hr = self.baseline.user_avg_hour[log.username]
            diff = abs(current_hr - avg_hr)
            if diff > 6.0:  # Logged in > 6 hours away from normal pattern
                score += 0.30

        # D. Off-Hours & Weekend Activity
        hour = log.timestamp.hour
        if 23 <= hour or hour <= 5:
            score += 0.25
        if log.timestamp.weekday() >= 5:
            score += 0.15

        # E. High Frequency Brute Force / Spraying Indicator
        if log.username:
            recent_count = db.query(LogEntry).filter(
                LogEntry.timestamp >= (datetime.datetime.utcnow() - datetime.timedelta(minutes=5)),
                LogEntry.username == log.username
            ).count()
            if recent_count > 15:
                score += 0.35
            elif recent_count > 5:
                score += 0.15

        return score


# Global instance of AnomalyDetector
anomaly_detector = AnomalyDetector()
