import boto3
import os
import json
import logging
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from typing import List, Dict, Any

# Constants
KINESIS_BATCH_SIZE = 500
LOG_STREAM_NAME = "log_stream"
LAMBDA_FUNCTION_NAME = "TriggerLambdaFunction"
GUARDDUTY_DETECTOR_PREFIX = "gd-"
WAF_ACL_PREFIX = "webacl-"

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class AWSIntrusionDetection:
    def __init__(self, region: str = "us-east-1"):
        """Initialize AWS services for security monitoring."""
        self.session = boto3.Session(region_name=region)
        self.services = {
            "logs": self.session.client("logs"),
            "securityhub": self.session.client("securityhub"),
            "kinesis": self.session.client("kinesis"),
            "lambda": self.session.client("lambda"),
            "wafv2": self.session.client("wafv2"),
            "stepfunctions": self.session.client("stepfunctions"),
        }

    def detect_anomalies(self, logs: List[Dict[str, Any]]) -> pd.Series:
        """
        Analyze logs and detect unusual activity using Isolation Forest.

        Args:
            logs: List of log entries.

        Returns:
            Series of anomaly predictions (-1 for anomalies, 1 for normal).
        """
        try:
            df = pd.DataFrame(logs).fillna({"bytes_sent": 0, "packet_count": 0})
            df["protocol_encoded"] = LabelEncoder().fit_transform(df["protocol"])

            model = IsolationForest(contamination=0.05, random_state=42)
            df["anomaly"] = model.fit_predict(df[["bytes_sent", "packet_count", "protocol_encoded"]])

            return df["anomaly"]
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
            raise

    def alert_lambda(self, message: str) -> None:
        """
        Trigger AWS Lambda when a threat is detected.

        Args:
            message: Message to send to the Lambda function.
        """
        try:
            self.services["lambda"].invoke(
                FunctionName=LAMBDA_FUNCTION_NAME,
                InvocationType="Event",
                Payload=json.dumps({"message": message}),
            )
            logger.info(f"Alert sent to Lambda: {message}")
        except Exception as e:
            logger.error(f"Error invoking Lambda: {e}")
            raise

    def send_logs_to_kinesis(self, file: str, stream_name: str) -> None:
        """
        Stream logs to AWS Kinesis in batches.

        Args:
            file: Path to the log file.
            stream_name: Name of the Kinesis stream.
        """
        try:
            with open(file, "r") as f:
                logs = [{"Data": json.dumps({"log": log.strip()}), "PartitionKey": "log"} for log in f]

            for i in range(0, len(logs), KINESIS_BATCH_SIZE):
                self.services["kinesis"].put_records(
                    StreamName=stream_name,
                    Records=logs[i : i + KINESIS_BATCH_SIZE],
                )
            logger.info(f"Logs sent to Kinesis stream: {stream_name}")
        except Exception as e:
            logger.error(f"Error sending logs to Kinesis: {e}")
            raise

    def run(self, detector_id: str, web_acl_id: str, log_file: str) -> None:
        """
        Orchestrate the security pipeline: detect threats, alert, and log activity.

        Args:
            detector_id: AWS GuardDuty Detector ID.
            web_acl_id: AWS WAF ACL ID.
            log_file: Path to the log file.
        """
        try:
            # Validate IDs
            if not (detector_id.startswith(GUARDDUTY_DETECTOR_PREFIX) and web_acl_id.startswith(WAF_ACL_PREFIX)):
                raise ValueError("Invalid AWS GuardDuty or WAF ID!")

            # Example logs (replace with real log data)
            logs = [
                {"src_ip": "192.168.0.1", "dest_ip": "192.168.0.2", "protocol": "TCP", "bytes_sent": 1000, "packet_count": 50}
            ]
            anomalies = self.detect_anomalies(logs)

            if (anomalies == -1).sum() > 0:
                self.alert_lambda("Potential security threat detected!")

            self.send_logs_to_kinesis(log_file, LOG_STREAM_NAME)
        except Exception as e:
            logger.error(f"Error running security pipeline: {e}")
            raise

if __name__ == "__main__":
    # Retrieve IDs from environment variables
    detector_id = os.getenv("GUARDDUTY_DETECTOR_ID")
    web_acl_id = os.getenv("WAF_ACL_ID")

    if not detector_id or not web_acl_id:
        raise ValueError("Missing AWS GuardDuty or WAF ACL ID!")

    # Initialize and run the system
    system = AWSIntrusionDetection()
    system.run(detector_id, web_acl_id, "logfile.txt")