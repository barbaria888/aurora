import os
import sys
import json
from unittest.mock import MagicMock, patch

os.environ["FLASK_ENV"] = "development"
os.environ["DEV_SECURITYHUB_API_KEY"] = "super-secret"

# We must add server to pythonpath
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "server"))

from flask import Flask
from routes.aws.securityhub_routes import securityhub_bp
from routes.aws.tasks import process_securityhub_finding

app = Flask(__name__)
app.register_blueprint(securityhub_bp, url_prefix="/aws/securityhub")

@patch("routes.aws.securityhub_routes.db_pool")
@patch("routes.aws.securityhub_routes.process_securityhub_finding.delay")
def test_route(mock_delay, mock_db_pool):
    print("--- TESTING ROUTE LOGIC ---")
    
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_db_pool.get_admin_connection.return_value.__enter__.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
    
    # Simulate DB returning empty for API key so it relies on DEV_SECURITYHUB_API_KEY
    mock_cursor.fetchone.return_value = None
    
    with app.test_client() as client:
        payload = {
            "source": "aws.securityhub",
            "detail": {
                "findings": [{"Id": "TEST-1234", "Title": "Malware Found", "Severity": {"Label": "CRITICAL"}}]
            }
        }
        resp = client.post(
            "/aws/securityhub/webhook/TEST-ORG",
            json=payload,
            headers={"x-api-key": "super-secret"}
        )
        print(f"Status Code: {resp.status_code}")
        print(f"Response: {resp.json}")
        
        if mock_delay.called:
            print("SUCCESS: Background task was correctly enqueued!")
        else:
            print("FAILURE: Background task was NOT enqueued.")

@patch("routes.aws.tasks.db_pool")
def test_task(mock_db_pool):
    print("\n--- TESTING TASK UPSERT LOGIC ---")
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_db_pool.get_admin_connection.return_value.__enter__.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
    
    payload = {
        "detail": {
            "findings": [{"Id": "TEST-1234", "Title": "Malware Found", "Severity": {"Label": "CRITICAL"}}]
        }
    }
    
    process_securityhub_finding(payload, "TEST-ORG")
    
    # Get the executed query
    if mock_cursor.execute.called:
        query, args = mock_cursor.execute.call_args[0]
        print("SUCCESS: DB Query was executed. Query preview:")
        print(query.strip()[:150] + "...")
        print("Args:", args)
    else:
        print("FAILURE: cursor.execute was never called.")

if __name__ == "__main__":
    test_route()
    test_task()
