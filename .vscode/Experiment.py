import boto3
import logging
import pandas as pd
import os
import json
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from typing import List, Dict, Any

# Constants
KINESIS_BATCH_SIZE = 500
LOG_STREAM_NAME = "log_stream"
LAMBDA_FUNCTION_NAME = "TriggerLambdaFunction"
LOG_FILE = "findings.log"  # File to store findings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),  # Write logs to a file
        logging.StreamHandler()         # Print logs to the terminal
    ]
)
logger = logging.getLogger(__name__)

class AWSIntrusionDetection:
    def __init__(self, aws_access_key_id: str, aws_secret_access_key: str, region: str = "us-east-1"):
        """
        Initialize AWS services for security monitoring.

        Args:
            aws_access_key_id: AWS Access Key ID.
            aws_secret_access_key: AWS Secret Access Key.
            region: AWS region (default: us-east-1).
        """
        self.session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region
        )
        self.services = {
            "logs": self.session.client("logs"),
            "securityhub": self.session.client("securityhub"),
            "kinesis": self.session.client("kinesis"),
            "lambda": self.session.client("lambda"),
            "wafv2": self.session.client("wafv2"),
            "stepfunctions": self.session.client("stepfunctions"),
        }

    def create_kinesis_stream(self, stream_name: str, shard_count: int = 1) -> None:
        """
        Create a Kinesis stream if it doesn't already exist.

        Args:
            stream_name: Name of the Kinesis stream.
            shard_count: Number of shards for the stream (default: 1).
        """
        try:
            # Check if the stream already exists
            existing_streams = self.services["kinesis"].list_streams()["StreamNames"]
            if stream_name not in existing_streams:
                self.services["kinesis"].create_stream(
                    StreamName=stream_name,
                    ShardCount=shard_count
                )
                logger.info(f"Created Kinesis stream: {stream_name}")
            else:
                logger.info(f"Kinesis stream already exists: {stream_name}")
        except Exception as e:
            logger.error(f"Error creating Kinesis stream: {e}")
            raise

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
            # Check if the file exists
            if not os.path.exists(file):
                raise FileNotFoundError(f"Log file not found: {file}")

            with open(file, "r") as f:
                logs = [{"Data": json.dumps({"log": log.strip()}), "PartitionKey": "log"} for log in f]

            for i in range(0, len(logs), KINESIS_BATCH_SIZE):
                self.services["kinesis"].put_records(
                    StreamName=stream_name,
                    Records=logs[i : i + KINESIS_BATCH_SIZE],
                )
            logger.info(f"Logs sent to Kinesis stream: {stream_name}")
        except FileNotFoundError as e:
            logger.error(f"Error: {e}")
            raise
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
            if not detector_id:
                raise ValueError("GuardDuty Detector ID is required!")
            if not web_acl_id:
                raise ValueError("Web ACL ID is required!")

            # Create the Kinesis stream if it doesn't exist
            self.create_kinesis_stream(LOG_STREAM_NAME)

            # Example logs (replace with real log data)
            logs = [
                {"src_ip": "192.168.0.1", "dest_ip": "192.168.0.2", "protocol": "TCP", "bytes_sent": 1000, "packet_count": 50}
            ]
            anomalies = self.detect_anomalies(logs)

            # Log findings to terminal and file
            for index, row in logs.iterrows():
                if anomalies[index] == -1:
                    finding = f"Anomaly detected: {row}"
                    logger.info(finding)  # Log to terminal and file

            if (anomalies == -1).sum() > 0:
                self.alert_lambda("Potential security threat detected!")

            self.send_logs_to_kinesis(log_file, LOG_STREAM_NAME)
        except Exception as e:
            logger.error(f"Error running security pipeline: {e}")
            raise

if __name__ == "__main__":
    # Request user input for AWS credentials
    aws_access_key_id = input("Enter AWS Access Key ID: ")
    aws_secret_access_key = input("Enter AWS Secret Access Key: ")

    # Request user input for IDs
    detector_id = input("Enter GuardDuty Detector ID: ")
    web_acl_id = input("Enter Web ACL ID: ")

    # Validate input
    if not aws_access_key_id or not aws_secret_access_key:
        raise ValueError("AWS Access Key ID and Secret Access Key are required!")
    if not detector_id or not web_acl_id:
        raise ValueError("GuardDuty Detector ID and Web ACL ID are required!")

    # Initialize and run the system
    system = AWSIntrusionDetection(aws_access_key_id, aws_secret_access_key)
    system.run(detector_id, web_acl_id, "logfile.txt")