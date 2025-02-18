import kopf
import logging
import kubernetes
from kubernetes.dynamic import DynamicClient
from digitalocean import create_do_monitor, update_do_monitor, delete_do_monitor, create_do_uptime_alert, update_do_uptime_alert, create_do_latency_alert, update_do_latency_alert, create_do_ssl_alert, update_do_ssl_alert

# Load Kubernetes configuration (inside cluster or local kubeconfig)
try:
    kubernetes.config.load_incluster_config()
except kubernetes.config.ConfigException:
    kubernetes.config.load_kube_config()

# Kubernetes client
k8s_client = kubernetes.client.ApiClient()
dyn_client = DynamicClient(k8s_client)

# DoMonitor Custom Resource API
do_monitor_api = dyn_client.resources.get(api_version="douz.com/v1", kind="DoMonitor")

# Function to retrieve the DoMonitor Custom Resource
def get_do_monitor_cr(name: str, namespace: str):
    """Retrieve the DoMonitor Custom Resource"""

    try:
        cr = do_monitor_api.get(name=name, namespace=namespace)
        monitor_id = cr.spec.get("monitorID")
        alerts = cr.spec.get("alerts")
        uptime_alert_id = alerts.get("uptimeAlertID")
        latency_alerts = alerts.get("latency")
        latency_alert_id = latency_alerts.get("alertID") if latency_alerts else None
        ssl_expire_alerts = alerts.get("sslExpiry")
        ssl_alert_id = ssl_expire_alerts.get("alertID") if ssl_expire_alerts else None

        return monitor_id, uptime_alert_id, latency_alert_id, ssl_alert_id
    except kubernetes.client.exceptions.ApiException as e:
        logging.error(f"Failed to retrieve DoMonitor: {name} ({namespace})")
        logging.error(e)
        return None, None, None, None

# Function to validate if the douz.com/do-monitor-* annotations are correctly set
def validate_do_monitor_annotations(do_monitor_annotations: dict, cr_name: str, namespace: str):
    """Validate if the douz.com/do-monitor-* annotations are correctly set"""

    email = do_monitor_annotations.get("douz.com/do-monitor-email")
    slack_webhook = do_monitor_annotations.get("douz.com/do-monitor-slack-webhook")
    slack_channel = do_monitor_annotations.get("douz.com/do-monitor-slack-channel")
    latency_threshold = do_monitor_annotations.get("douz.com/do-monitor-latency-threshold")
    latency_period = do_monitor_annotations.get("douz.com/do-monitor-latency-period")
    ssl_expiry = do_monitor_annotations.get("douz.com/do-monitor-ssl-expiry")

    email_alert = bool(email)
    slack_alert = bool(slack_webhook and slack_channel)

    if not email and not slack_webhook:
        logging.error(f"Email or Slack Webhook is missing for DoMonitor: {cr_name} ({namespace})")
        return None

    if slack_webhook and not slack_channel:
        logging.error(f"Slack Channel is missing for DoMonitor: {cr_name} ({namespace})")
        return None

    if latency_threshold and not latency_period:
        logging.error(f"Latency Period is missing for DoMonitor: {cr_name} ({namespace})")
        return None

    latency_threshold = int(latency_threshold) if latency_threshold else None
    ssl_expiry = int(ssl_expiry) if ssl_expiry else None

    return email, email_alert, slack_webhook, slack_channel, slack_alert, latency_threshold, latency_period, ssl_expiry

# Function to create or update DoMonitor Custom Resource
def create_or_update_do_monitor_cr(name: str, namespace: str, monitor_id: str, ingress_name: str, host: str, uptime_alert_id: str, email: str,
                                   slack_webhook: str, slack_channel: str, latency_alert_id: str, latency_threshold: int, ssl_alert_id: str, ssl_expiry_days_left: int, latency_period: str = "2m"):
    """Create or Update the DoMonitor Custom Resource"""

    payload = {
        "apiVersion": "douz.com/v1",
        "kind": "DoMonitor",
        "metadata": {
            "name": name,
            "namespace": namespace
        },
        "spec": {
            "monitorID": monitor_id,
            "ingressName": ingress_name,
            "host": host,
            "alerts": {
                "uptimeAlertID": uptime_alert_id,
            }
        }
    }

    if not email and not slack_webhook:
        logging.error(f"Email or Slack Webhook is missing for DoMonitor: {name} ({namespace})")
        return
    elif email:
        payload["spec"]["alerts"]["email"] = email

    if slack_webhook and not slack_channel:
        logging.error(f"Slack Channel is missing for DoMonitor: {name} ({namespace})")
        return
    else:
        payload["spec"]["alerts"]["slack"] = {
            "url": slack_webhook,
            "channel": slack_channel
        }

    if latency_alert_id:
        payload["spec"]["alerts"]["latency"] = {
            "alertID": latency_alert_id,
            "threshold": latency_threshold,
            "period": latency_period
        }
    
    if ssl_alert_id:
        payload["spec"]["alerts"]["sslExpiry"] = {
            "alertID": ssl_alert_id,
            "threshold": ssl_expiry_days_left
        }

    try:
        do_monitor_api.get(name=name, namespace=namespace)
        do_monitor_api.patch(name=name, namespace=namespace, body=payload, content_type='application/merge-patch+json')
        logging.info(f"Updated DoMonitor: {name} ({namespace})")
    except kubernetes.client.exceptions.ApiException as e:
        if e.status == 404:
            do_monitor_api.create(body=payload)
            logging.info(f"Created DoMonitor: {name} ({namespace})")
        else:
            logging.error(f"Failed to update DoMonitor: {name} ({namespace})")
            logging.error(e)

# Function to delete DoMonitor custom resource
def delete_do_monitor_cr(name: str, namespace: str):
    """Delete the DoMonitor Custom Resource"""

    try:
        do_monitor_api.delete(name=name, namespace=namespace)
        logging.info(f"Deleted DoMonitor: {name} ({namespace})")
    except kubernetes.client.exceptions.ApiException as e:
        logging.error(f"Failed to delete DoMonitor: {name} ({namespace})")
        logging.error(e)

# Function to trigger when an Ingress object is created with the annotation douz.com/do-monitor
# set to True. This function will create a new DigitalOcean Uptime Monitor and an uptime alert
# with the Ingress URL.
# If the Ingress object has the douz.com/do-monitor-latency-threshold and douz.com/do-monitor-latency-period;
# it will also create a latency alert for the DigitalOcean Uptime Monitor.
# If the Ingress object has the douz.com/do-monitor-ssl-expiry; it will also create an SSL expiration alert
@kopf.on.create("networking.k8s.io", "v1", "ingresses",
                annotations={"douz.com/do-monitor": "true"})
def ingress_created(spec, annotations, name, namespace, **kwargs):
    """Triggered when an Ingress is created"""

    cr_name = f"{name}-{namespace}-domonitor"
    do_monitor_annotations = {annotation: value for annotation, value in annotations.items() if annotation.startswith("douz.com/do-monitor-")}

    validation_result = validate_do_monitor_annotations(do_monitor_annotations, cr_name, namespace)
    if validation_result is None:
        return

    email, email_alert, slack_webhook, slack_channel, slack_alert, latency_threshold, latency_period, ssl_expiry = validation_result

    for rule in spec["rules"]:
        monitor_url = rule["host"]
        monitor_id = create_do_monitor(url=monitor_url, monitor_name=cr_name)
        uptime_alert_id = create_do_uptime_alert(monitor_id=monitor_id, email_alert=email_alert, email=email, slack_alert=slack_alert,
                                                 slack_webhook=slack_webhook, slack_channel=slack_channel)
        latency_alert_id = None
        ssl_alert_id = None
        
        if latency_threshold:
            latency_alert_id = create_do_latency_alert(monitor_id=monitor_id, latency_threshold=latency_threshold, latency_period=latency_period,
                                                       email_alert=email_alert, email=email, slack_alert=slack_alert, slack_webhook=slack_webhook,
                                                       slack_channel=slack_channel)
        if ssl_expiry:
            ssl_alert_id = create_do_ssl_alert(monitor_id=monitor_id, email_alert=email_alert, email=email, slack_alert=slack_alert,
                                               slack_webhook=slack_webhook, slack_channel=slack_channel, days_left=ssl_expiry)

        create_or_update_do_monitor_cr(name=cr_name, namespace=namespace, monitor_id=monitor_id, ingress_name=name, host=monitor_url, uptime_alert_id=uptime_alert_id,
                                       email=email, slack_webhook=slack_webhook, slack_channel=slack_channel, latency_alert_id=latency_alert_id, latency_threshold=latency_threshold,
                                       latency_period=latency_period, ssl_alert_id=ssl_alert_id, ssl_expiry_days_left=ssl_expiry)

# Function to trigger when an Ingress object is updated with the annotation douz.com/do-monitor
# set to True. This function will update the existing DigitalOcean Uptime Monitor and its alerts.
@kopf.on.update("networking.k8s.io", "v1", "ingresses",
                annotations={"douz.com/do-monitor": "true"})
def ingress_updated(spec, annotations, name, namespace, **kwargs):
    """Triggered when an Ingress is updated"""

    cr_name = f"{name}-{namespace}-domonitor"
    do_monitor_annotations = {annotation: value for annotation, value in annotations.items() if annotation.startswith("douz.com/do-monitor-")}

    validation_result = validate_do_monitor_annotations(do_monitor_annotations, cr_name, namespace)
    if validation_result is None:
        return

    email, email_alert, slack_webhook, slack_channel, slack_alert, latency_threshold, latency_period, ssl_expiry = validation_result

    for rule in spec["rules"]:
        monitor_url = rule["host"]
        monitor_id, uptime_alert_id, latency_alert_id, ssl_alert_id = get_do_monitor_cr(name=cr_name, namespace=namespace)
        update_do_monitor(url=monitor_url, monitor_name=cr_name, monitor_id=monitor_id)
        update_do_uptime_alert(monitor_id=monitor_id, alert_id=uptime_alert_id, email_alert=email_alert, email=email, slack_alert=slack_alert,
                               slack_webhook=slack_webhook, slack_channel=slack_channel)
        if latency_threshold:
            update_do_latency_alert(monitor_id=monitor_id, alert_id=latency_alert_id, email_alert=email_alert, email=email, slack_alert=slack_alert,
                                    slack_webhook=slack_webhook, slack_channel=slack_channel, latency_threshold=latency_threshold, latency_period=latency_period)
        if ssl_expiry:
            update_do_ssl_alert(monitor_id=monitor_id, alert_id=ssl_alert_id, email_alert=email_alert, email=email, slack_alert=slack_alert,
                                slack_webhook=slack_webhook, slack_channel=slack_channel, days_left=ssl_expiry)

        create_or_update_do_monitor_cr(name=cr_name, namespace=namespace, monitor_id=monitor_id, ingress_name=name, host=monitor_url, uptime_alert_id=uptime_alert_id,
                                       email=email, slack_webhook=slack_webhook, slack_channel=slack_channel, latency_alert_id=latency_alert_id, latency_threshold=latency_threshold,
                                       latency_period=latency_period, ssl_alert_id=ssl_alert_id, ssl_expiry_days_left=ssl_expiry)

# Function to trigger when an Ingress object is deleted with the annotation douz.com/do-monitor
# set to True. This function will delete the existing DigitalOcean Uptime Monitor and its alerts.
@kopf.on.delete("networking.k8s.io", "v1", "ingresses",
                annotations={"douz.com/do-monitor": "true"})
def ingress_deleted(name, namespace, **kwargs):
    """Triggered when an Ingress is deleted"""

    cr_name = f"{name}-{namespace}-domonitor"
    monitor_id, _, _, _ = get_do_monitor_cr(name=cr_name, namespace=namespace)

    if monitor_id:
        delete_do_monitor_cr(name=cr_name, namespace=namespace)
        delete_do_monitor(monitor_id)
