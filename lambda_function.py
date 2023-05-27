import os
import requests
import xmltodict
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
import time

# Constants
SLACK_MAIN_CHANNEL = "slackMainChannel"
SLACK_BACKUP_CHANNEL = "slackBackupChannel"
QUALYS_API_URL = "qualysApiUrl"
REGION_NAME = ""  # Update with the appropriate region name
SECRET_NAME = ""  # Update with the appropriate secret name

def get_environment_variable(key):
    """
    Retrieve the value of an environment variable.
    """
    return str(os.environ.get(key))

def get_secret_value(secret_name, region_name):
    """
    Retrieve the value of a secret from AWS Secrets Manager.
    """
    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager', region_name=region_name)

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        secret = get_secret_value_response['SecretString']
        return secret
    except ClientError as e:
        raise e

def xml_to_json(response_text):
    """
    Convert XML response to JSON format.
    """
    data_dict = xmltodict.parse(response_text)
    json_data = json.dumps(data_dict)
    data = json.loads(json_data)
    return data

def get_auth_token():
    """
    Retrieve the authentication token from AWS Secrets Manager.
    """
    secret_name = get_environment_variable(SECRET_NAME)
    region_name = get_environment_variable(REGION_NAME)
    return get_secret_value(secret_name, region_name)

def make_api_request(url, method="GET", headers=None, data=None):
    """
    Make an API request to the specified URL.
    """
    response = requests.request(method, url, headers=headers, data=data)
    response.raise_for_status()
    return response

def format_date(date):
    """
    Format a date string.
    """
    return datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")

def create_message_json(alert_title, alert_name, alert_host_name, alert_ip, alert_details_text):
    """
    Create a Slack message JSON payload.
    """
    message = {
        "text": f"New Alert on Qualys Continuous Monitoring ({alert_title})",
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Alert Title:* {alert_title}"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Alert Name:* {alert_name}"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Hostname:* {alert_host_name}"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*IP(s):* {alert_ip}"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Alert Details:* \n\t{alert_details_text}"}}
        ]
    }
    return json.dumps(message)

def send_slack_message(url, payload):
    """
    Send a Slack message with the payload to the specified URL.
    """
    headers = {"Content-Type": "application/json"}
    response = make_api_request(url, method="POST", headers=headers, data=payload)
    response.raise_for_status()
    print("An Alert Sent to Slack Channel!")
    print(url)

def list_all_alerts(api_url, auth_token):
    """
    List all Qualys CM alerts and parse the results.
    """
    url = f"{api_url}/qps/rest/1.0/search/cm/alert/"
    headers = {"Authorization": auth_token}
    response = make_api_request(url, headers=headers)
    data = xml_to_json(response.text)
    alerts = data["ServiceResponse"]["data"]["Alert"]
    print("ALL ALERTS:")
    for i, alert in enumerate(alerts, start=1):
        alert_id = alert["id"]
        alert_source = alert["source"]
        alert_event_type = alert["eventType"]
        alert_host_name = alert["hostname"]
        alert_date = format_date(alert["alertDate"])
        alert_ip = alert["ipAddress"]
        alert_details = alert["alertInfo"]
        alert_details_text = "\n\t".join([f"- '{key}': {alert_details[key]}" for key in alert_details.keys()])
        alert_details_text = f"{i}. {alert_id} | {alert_source} | {alert_event_type} | {alert_host_name} | {alert_date} | {alert_ip} | \n\t{alert_details_text}"
        print(alert_details_text)

def get_alert_details(api_url, auth_token, alert_id):
    """
    Get Qualys CM alert details with the given alert ID.
    """
    url = f"{api_url}/qps/rest/1.0/get/cm/alert/{alert_id}"
    headers = {"Authorization": auth_token}
    response = make_api_request(url, headers=headers)
    data = xml_to_json(response.text)
    return data

def get_new_alert_ids(api_url, auth_token, hours=1):
    """
    Get new alerts within the specified number of hours.
    """
    url = f"{api_url}/qps/rest/1.0/search/cm/alert/"
    headers = {"Authorization": auth_token}
    response = make_api_request(url, method="POST", headers=headers)
    data = xml_to_json(response.text)
    alerts = data["ServiceResponse"]["data"]["Alert"]
    one_hour_before_date = datetime.now() - timedelta(hours=hours)
    new_alert_ids = []
    for alert in alerts:
        alert_date = datetime.strptime(alert["alertDate"], "%Y-%m-%dT%H:%M:%SZ")
        if alert_date >= one_hour_before_date:
            new_alert_ids.append(alert["id"])
    return new_alert_ids

def process_alert(api_url, auth_token, alert_id):
    """
    Process a single alert.
    """
    alert_details = get_alert_details(api_url, auth_token, alert_id)
    alert_title = alert_details["ServiceResponse"]["data"]["Alert"]["profile"]["title"]
    alert_name = alert_details["ServiceResponse"]["data"]["Alert"]["eventType"]
    alert_host_name = alert_details["ServiceResponse"]["data"]["Alert"].get("hostname", "")
    alert_ip = alert_details["ServiceResponse"]["data"]["Alert"]["ipAddress"]
    alert_info = alert_details["ServiceResponse"]["data"]["Alert"]["alertInfo"]
    alert_details_text = "\n\t".join([f"- '{key}': {alert_info[key]}" for key in alert_info.keys()])
    payload = create_message_json(alert_title, alert_name, alert_host_name, alert_ip, alert_details_text)
    send_slack_message(get_environment_variable(SLACK_MAIN_CHANNEL), payload)
    time.sleep(10)
    send_slack_message(get_environment_variable(SLACK_BACKUP_CHANNEL), payload)
    return f"{alert_id} | {alert_title} | {alert_name} | {alert_ip} | {alert_details_text}"

def process_alerts(api_url, auth_token):
    """
    Process all new alerts.
    """
    new_alert_ids = get_new_alert_ids(api_url, auth_token)
    total_alert_count = len(new_alert_ids)

    if new_alert_ids:
        print("NEW ALERTS!")
        unique_alerts = set()

        for alert_id in new_alert_ids:
            alert_details_text = process_alert(api_url, auth_token, alert_id)
            unique_alerts.add(alert_details_text)

        print(f"{total_alert_count} TOTAL NEW ALERTS!")
        print(f"{len(unique_alerts)} UNIQUE ALERTS!")
        return new_alert_ids

    else:
        print("NO NEW ALERTS!")

def lambda_handler(event, context):
    """
    The entry point for AWS Lambda execution.
    """
    api_url = get_environment_variable(QUALYS_API_URL)
    auth_token = get_auth_token()

    try:
        new_alerts = process_alerts(api_url, auth_token)
        return {
            "statusCode": 200,
            "body": json.dumps("Success! Message sent to Slack channel!")
        }
    except TypeError:
        return {
            "statusCode": 200,
            "body": json.dumps("No New Alerts!")
        }
    except Exception as e:
        return {
            "statusCode": 400,
            "body": json.dumps(f"Error! {str(e)}")
        }