
from collections import defaultdict
from datetime import datetime
from statistics import mean, pstdev

from src.bot_detection.data.loader import load_access_logs


# Configuration
HIGH_REQUEST_RATE = 1.0
LOW_INTERVAL_VARIATION = 0.1


def extract_features(logs):
    """
    Extract behavioral features for each IP address.
    """

    sessions = defaultdict(list)

    for log in logs:
        ip = log["ip"]
        timestamp = datetime.fromisoformat(log["timestamp"])

        sessions[ip].append({
            "timestamp": timestamp,
            "user_agent": log["user_agent"],
            "url": log["url"],
            "method": log["method"],
            "status_code": int(log["status_code"])
        })

    features = {}

    for ip, requests in sessions.items():
        requests.sort(key=lambda request: request["timestamp"])

        timestamps = [
            request["timestamp"] for request in requests
        ]

        intervals = []

        for i in range(1, len(timestamps)):
            difference = (
                timestamps[i] - timestamps[i - 1]
            ).total_seconds()

            intervals.append(difference)

        duration = (
            timestamps[-1] - timestamps[0]
        ).total_seconds()

        request_count = len(requests)

        request_rate = (
            request_count / duration if duration > 0 else 0
        )

        interval_variation = (
            pstdev(intervals) if len(intervals) > 1 else 0
        )

        user_agents = {
            request["user_agent"] for request in requests
        }

        suspicious_user_agents = [
            "python-requests",
            "scrapy",
            "curl",
            "httpx",
            "wget"
        ]

        automated_agent = any(
            agent.lower().find(pattern) != -1
            for agent in user_agents
            for pattern in suspicious_user_agents
        )

        unique_urls = len({
            request["url"] for request in requests
        })

        error_count = sum(
            request["status_code"] >= 400
            for request in requests
        )

        features[ip] = {
            "request_count": request_count,
            "request_rate": request_rate,
            "interval_variation": interval_variation,
            "automated_agent": automated_agent,
            "unique_urls": unique_urls,
            "error_rate": error_count / request_count
        }

    return features


def calculate_risk(features):
    """
    Calculate a heuristic bot risk score from 0 to 100.
    """

    score = 0
    reasons = []

    if features["request_rate"] >= HIGH_REQUEST_RATE:
        score += 30
        reasons.append("High request rate")

    if (
        features["interval_variation"] <= LOW_INTERVAL_VARIATION
        and features["request_count"] >= 3
    ):
        score += 25
        reasons.append("Highly regular request intervals")

    if features["automated_agent"]:
        score += 30
        reasons.append("Automation-related User-Agent")

    if features["error_rate"] > 0.5:
        score += 15
        reasons.append("High HTTP error rate")

    score = min(score, 100)

    if score >= 60:
        classification = "BOT"
    elif score >= 30:
        classification = "SUSPICIOUS"
    else:
        classification = "HUMAN"

    return score, classification, reasons


def main():
    logs = load_access_logs(
        "data/samples/sample_access_logs.csv"
    )

    if not logs:
        print("No HTTP logs found.")
        return

    required_columns = {
        "ip", "timestamp", "user_agent", "url", "method", "status_code"
    }

    missing_columns = required_columns - set(logs[0].keys())

    if missing_columns:
        print(f"Missing CSV columns: {missing_columns}")
        return

    features_by_ip = extract_features(logs)

    print("\n========== BOT DETECTION REPORT ==========\n")

    for ip, features in features_by_ip.items():
        score, classification, reasons = calculate_risk(features)

        print(f"IP ADDRESS: {ip}")
        print(f"CLASSIFICATION: {classification}")
        print(f"RISK SCORE: {score}/100")
        print(f"REQUEST COUNT: {features['request_count']}")
        print(f"REQUEST RATE: {features['request_rate']:.2f} req/sec")
        print(
            f"INTERVAL VARIATION: "
            f"{features['interval_variation']:.4f}"
        )
        print(f"UNIQUE URLS: {features['unique_urls']}")
        print(f"ERROR RATE: {features['error_rate']:.2%}")

        if reasons:
            print("DETECTION REASONS:")
            for reason in reasons:
                print(f"  - {reason}")
        else:
            print("DETECTION REASONS: No suspicious signals")

        print("-" * 45)


if __name__ == "__main__":
    main()
