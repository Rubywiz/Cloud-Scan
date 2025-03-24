#!/usr/bin/env python3

import boto3
import logging
import pandas as pd
import json
import socket
import threading
import nmap
import os
import argparse
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from typing import List, Dict, Any, Optional
from datetime import datetime

# Constants
KINESIS_BATCH_SIZE = 500
LOG_STREAM_NAME = "log_stream"
LAMBDA_FUNCTION_NAME = "TriggerLambdaFunction"
LOG_FILE = "findings.log"
DEFAULT_HONEYPOT_PORT = 8088  # Changed from 8080 to less common port
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB max log size
LOG_BACKUP_COUNT = 3

# Configure logging with rotation
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=LOG_BACKUP_COUNT
        ),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class Honeypot:
    def __init__(self, host: str = "0.0.0.0", port: int = DEFAULT_HONEYPOT_PORT):
        self.host = host
        self.port = port
        self.log_file = "honeypot.log"
        self.running = False

    def start(self):
        """Start the honeypot with proper error handling and timeouts."""
        self.running = True
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.settimeout(5.0)  # Add timeout for socket operations
                server_socket.bind((self.host, self.port))
                server_socket.listen(5)
                logger.info(f"Honeypot started on {self.host}:{self.port}")

                while self.running:
                    try:
                        client_socket, client_address = server_socket.accept()
                        logger.info(f"Connection from {client_address}")
                        with open(self.log_file, "a") as f:
                            f.write(f"{datetime.now()} - Connection from {client_address}\n")
                        client_socket.close()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logger.error(f"Connection handling error: {e}")
                        continue

        except Exception as e:
            logger.error(f"Honeypot error: {e}")
            raise
        finally:
            self.running = False

    def stop(self):
        """Gracefully stop the honeypot."""
        self.running = False

def start_honeypot(port: int = DEFAULT_HONEYPOT_PORT) -> threading.Thread:
    """Start honeypot in a daemon thread with specified port."""
    honeypot = Honeypot(port=port)
    honeypot_thread = threading.Thread(target=honeypot.start)
    honeypot_thread.daemon = True
    honeypot_thread.start()
    return honeypot_thread

def validate_ip(target: str) -> bool:
    """Validate IP address or CIDR range."""
    parts = target.split('/')
    if len(parts) == 2:
        try:
            prefix = int(parts[1])
            if not 0 <= prefix <= 32:
                return False
        except ValueError:
            return False

    octets = parts[0].split('.')
    if len(octets) != 4:
        return False
    
    try:
        return all(0 <= int(octet) <= 255 for octet in octets)
    except ValueError:
        return False

def scan_network(target: str, timeout: int = 300) -> dict:
    """Scan target with timeout and validation."""
    if not validate_ip(target):
        raise ValueError(f"Invalid target: {target}")

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments="-sV --max-rtt-timeout 500ms", timeout=timeout)
        return nm.analyse_nmap_xml_scan()
    except nmap.PortScannerError as e:
        logger.error(f"Nmap error: {e}")
        raise
    except Exception as e:
        logger.error(f"Scanning error: {e}")
        raise

class AWSIntrusionDetection:
    def __init__(self, aws_access_key_id: str, aws_secret_access_key: str, region: str = "us-east-1"):
        """Initialize with rate limiting and connection pooling."""
        self.session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region
        )
        
        config = Config(
            connect_timeout=5,
            read_timeout=60,
            retries={'max_attempts': 3},
            max_pool_connections=50
        )
        
        self.services = {
            "logs": self.session.client("logs", config=config),
            "securityhub": self.session.client("securityhub", config=config),
            "kinesis": self.session.client("kinesis", config=config),
            "lambda": self.session.client("lambda", config=config),
        }

    def detect_anomalies(self, logs: List[Dict[str, Any]]) -> pd.Series:
        """Optimized anomaly detection with feature engineering."""
        try:
            df = pd.DataFrame(logs).fillna({"bytes_sent": 0, "packet_count": 0})
            
            # Feature engineering
            df["protocol_encoded"] = LabelEncoder().fit_transform(df["protocol"])
            df["hour"] = pd.to_datetime(df["timestamp"]).dt.hour
            
            # Model training with sampling if large dataset
            sample_size = min(10000, len(df))
            model = IsolationForest(
                contamination=0.05,
                random_state=42,
                n_estimators=100,
                max_samples=sample_size
            )
            
            features = ["bytes_sent", "packet_count", "protocol_encoded", "hour"]
            df["anomaly"] = model.fit_predict(df[features])
            
            return df["anomaly"]
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            raise

def main():
    """Main execution with argument parsing."""
    parser = argparse.ArgumentParser(description="Cloud Security Monitoring System")
    parser.add_argument("--port", type=int, default=DEFAULT_HONEYPOT_PORT, help="Honeypot port")
    parser.add_argument("--target", required=True, help="Network target to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("--log-file", default="logfile.txt", help="Path to log file")
    args = parser.parse_args()

    # Get AWS credentials from environment
    aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    detector_id = os.getenv("GUARD_DUTY_ID")
    web_acl_id = os.getenv("WEB_ACL_ID")

    if not all([aws_access_key_id, aws_secret_access_key]):
        logger.error("AWS credentials not set in environment")
        return

    try:
        # Start services
        honeypot_thread = start_honeypot(args.port)
        logger.info("Started honeypot service")

        # Initialize AWS system
        aws_system = AWSIntrusionDetection(aws_access_key_id, aws_secret_access_key)
        
        # Run network scan in separate thread
        def scan_and_analyze():
            scan_results = scan_network(args.target)
            findings = detect_intrusions(scan_results)
            save_findings(findings)
        
        scan_thread = threading.Thread(target=scan_and_analyze)
        scan_thread.start()

        # Main processing
        aws_system.run(detector_id, web_acl_id, args.log_file)
        
        # Wait for threads
        scan_thread.join()
        honeypot_thread.join()

    except KeyboardInterrupt:
        logger.info("Shutting down gracefully...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        return

if __name__ == "__main__":
    main()
