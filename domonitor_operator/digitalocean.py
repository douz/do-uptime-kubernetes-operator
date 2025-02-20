import os
import logging
from pydo import Client

# DigitalOcean client
DO_API_TOKEN = os.environ.get("DIGITALOCEAN_TOKEN").strip()
client = Client(token=DO_API_TOKEN)

# ------------------------------------------------------------------------------
# Helper functions: Create Uptime Monitor payload and Alert payload
# ------------------------------------------------------------------------------
# Create Uptime Monitor payload
def create_monitor_payload(url: str, monitor_name: str) -> dict:
    """Create Uptime Monitor Payload"""

    payload = {
        "name": monitor_name,
        "type": "https",
        "target": f"https://{url}",
        "regions": ["us_east", "us_west", "eu_west", "se_asia"],
        "enabled": True
    }

    return payload

# Create alert payload
def create_alert_payload(alert_type: str, monitor_id: str, email_alert: bool, slack_alert: bool,
                         email: str, slack_webhook: str, slack_channel: str, **kwargs) -> dict:
    """Create alert payload for a DigitalOcean Uptime Monitor"""

    payload = {
        "name": f"{monitor_id}-{alert_type}-alert",
        "type": alert_type,
        "notifications": {}
    }

    if email_alert and email:
        payload["notifications"]["email"] = [email]
    
    if slack_alert and slack_webhook and slack_channel:
        payload["notifications"]["slack"] = [
            {
                "channel": slack_channel,
                "url": slack_webhook
            }
        ]

    payload.update(kwargs)
    return payload

# ------------------------------------------------------------------------------
# DigitalOcean Uptime Monitor and Alerts handlers - Functions to create, update
# and delete Uptime Monitors and Alerts
# ------------------------------------------------------------------------------
# Create a new DigitalOcean Uptime Monitor
def create_do_monitor(url: str, monitor_name: str) -> str:
    """Create a New DigitalOcean Uptime Monitor"""

    payload = create_monitor_payload(url, monitor_name)

    try:
        monitor = client.uptime.create_check(body=payload)
        monitor_id = monitor["check"]["id"]
        logging.info(f"Created DO Uptime Monitor: {monitor_name} ({url}) ID: {monitor_id}")
        return monitor_id
    except Exception as e:
        logging.error(f"Failed to create DO Uptime Monitor: {monitor_name} ({url}) - {e}")
        return None

# Update an existing DigitalOcean Uptime Monitor   
def update_do_monitor(url: str, monitor_name: str, monitor_id: str):
    """Update an Existing DigitalOcean Uptime Monitor"""
    
    payload = create_monitor_payload(url, monitor_name)

    try:
        client.uptime.update_check(check_id=monitor_id, body=payload)
        logging.info(f"Updated DO Uptime Monitor: {url} ID: {monitor_id}")
    except Exception as e:
        logging.error(f"Failed to update DO Uptime Monitor: {url} - {e}")

# Delete an existing DigitalOcean Uptime Monitor
def delete_do_monitor(monitor_id: str):
    """Delete an Existing DigitalOcean Uptime Monitor"""

    try:
        client.uptime.delete_check(check_id=monitor_id)
        logging.info(f"Deleted DO Uptime Monitor ID: {monitor_id}")
    except Exception as e:
        logging.error(f"Failed to delete DO Uptime Monitor ID: {monitor_id} - {e}")

# Create uptime alert for a DigitalOcean Uptime Monitor
def create_do_uptime_alert(monitor_id: str, email_alert: bool = False, slack_alert: bool = False,
                           email: str = None, slack_webhook: str = None, slack_channel: str = None) -> str:
    """Create Uptime Alert for a DigitalOcean Uptime Monitor"""

    payload = create_alert_payload(
        "down",
        monitor_id,
        email_alert,
        slack_alert,
        email,
        slack_webhook,
        slack_channel,
        period="2m"
    )

    try:
        alert = client.uptime.create_alert(check_id=monitor_id, body=payload)
        logging.info(f"Created DO Uptime Alert for Monitor ID: {monitor_id}")
        return alert["alert"]["id"]
    except Exception as e:
        logging.error(f"Failed to create DO Uptime Alert for Monitor ID: {monitor_id} - {e}")
        return None

# Update an existing uptime alert for a DigitalOcean Uptime Monitor
def update_do_uptime_alert(monitor_id: str, alert_id: str, email_alert: bool = False, slack_alert: bool = False,
                           email: str = None, slack_webhook: str = None, slack_channel: str = None):
    """Update Uptime Alert for a DigitalOcean Uptime Monitor"""

    payload = create_alert_payload(
        "down",
        monitor_id,
        email_alert,
        slack_alert,
        email,
        slack_webhook,
        slack_channel,
        period="2m"
    )

    try:
        client.uptime.update_alert(check_id=monitor_id, alert_id=alert_id, body=payload)
        logging.info(f"Updated DO Uptime Alert for Monitor ID: {monitor_id}")
    except Exception as e:
        logging.error(f"Failed to update DO Uptime Alert for Monitor ID: {monitor_id} - {e}")

# Create a latency alert for a DigitalOcean Uptime Monitor
def create_do_latency_alert(monitor_id: str, email_alert: bool = False, slack_alert: bool = False,
                            email: str = None, slack_webhook: str = None, slack_channel: str = None,
                            latency_threshold: int = 0, latency_period: str = "2m") -> str:
    """Create Latency Alert for a DigitalOcean Uptime Monitor"""

    payload = create_alert_payload(
        "latency",
        monitor_id,
        email_alert,
        slack_alert,
        email, slack_webhook,
        slack_channel,
        threshold=latency_threshold,
        comparison="greater_than",
        period=latency_period
    )

    try:
        alert = client.uptime.create_alert(check_id=monitor_id, body=payload)
        logging.info(f"Created DO Latency Alert for Monitor ID: {monitor_id}")
        return alert["alert"]["id"]
    except Exception as e:
        logging.error(f"Failed to create DO Latency Alert for Monitor ID: {monitor_id} - {e}")
        return None
    
# Update an existing latency alert for a DigitalOcean Uptime Monitor
def update_do_latency_alert(monitor_id: str, alert_id: str, email_alert: bool = False, slack_alert: bool = False,
                            email: str = None, slack_webhook: str = None, slack_channel: str = None,
                            latency_threshold: int = 0, latency_period: str = "2m"):
    """Update Latency Alert for a DigitalOcean Uptime Monitor"""

    payload = create_alert_payload(
        "latency",
        monitor_id,
        email_alert,
        slack_alert,
        email,
        slack_webhook,
        slack_channel,
        threshold=latency_threshold,
        comparison="greater_than",
        period=latency_period
    )

    try:
        client.uptime.update_alert(check_id=monitor_id, alert_id=alert_id, body=payload)
        logging.info(f"Updated DO Latency Alert for Monitor ID: {monitor_id}")
    except Exception as e:
        logging.error(f"Failed to update DO Latency Alert for Monitor ID: {monitor_id} - {e}")

# Create an SSL expiration alert for a DigitalOcean Uptime Monitor
def create_do_ssl_alert(monitor_id: str, email_alert: bool = False, slack_alert: bool = False,
                        email: str = None, slack_webhook: str = None, slack_channel: str = None,
                        days_left: int = 30) -> str:
    """Create SSL Expiration Alert for a DigitalOcean Uptime Monitor"""

    payload = create_alert_payload(
        "ssl_expiry",
        monitor_id,
        email_alert,
        slack_alert,
        email,
        slack_webhook,
        slack_channel,
        threshold=days_left,
        comparison="less_than",
        period="2m"
    )

    try:
        alert = client.uptime.create_alert(check_id=monitor_id, body=payload)
        logging.info(f"Created DO SSL Expiration Alert for Monitor ID: {monitor_id}")
        return alert["alert"]["id"]
    except Exception as e:
        logging.error(f"Failed to create DO SSL Expiration Alert for Monitor ID: {monitor_id} - {e}")
        return None
    
# Update an existing SSL expiration alert for a DigitalOcean Uptime Monitor
def update_do_ssl_alert(monitor_id: str, alert_id: str, email_alert: bool = False, slack_alert: bool = False,
                        email: str = None, slack_webhook: str = None, slack_channel: str = None,
                        days_left: int = 30):
    """Update SSL Expiration Alert for a DigitalOcean Uptime Monitor"""

    payload = create_alert_payload(
        "ssl_expiry",
        monitor_id,
        email_alert,
        slack_alert,
        email,
        slack_webhook,
        slack_channel,
        threshold=days_left,
        comparison="less_than",
        period="2m"
    )

    try:
        client.uptime.update_alert(check_id=monitor_id, alert_id=alert_id, body=payload)
        logging.info(f"Updated DO SSL Expiration Alert for Monitor ID: {monitor_id}")
    except Exception as e:
        logging.error(f"Failed to update DO SSL Expiration Alert for Monitor ID: {monitor_id} - {e}")

# Function to delete an alert for a DigitalOcean Uptime Monitor
def delete_do_alert(monitor_id: str, alert_id: str, alert_type: str):
    """Delete an Alert for a DigitalOcean Uptime Monitor"""

    try:
        client.uptime.delete_alert(check_id=monitor_id, alert_id=alert_id)
        logging.info(f"Deleted DO {alert_type} Alert ID: {alert_id}")
    except Exception as e:
        logging.error(f"Failed to delete DO {alert_type} Alert ID: {alert_id} - {e}")
