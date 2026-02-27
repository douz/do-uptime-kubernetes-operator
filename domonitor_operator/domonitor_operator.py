import kopf
import logging
import re
import kubernetes
from kubernetes.dynamic import DynamicClient
try:
    from .digitalocean import (
        create_do_monitor,
        update_do_monitor,
        delete_do_monitor,
        create_do_uptime_alert,
        update_do_uptime_alert,
        create_do_latency_alert,
        update_do_latency_alert,
        create_do_ssl_alert,
        update_do_ssl_alert
    )
except ImportError:
    from digitalocean import (
        create_do_monitor,
        update_do_monitor,
        delete_do_monitor,
        create_do_uptime_alert,
        update_do_uptime_alert,
        create_do_latency_alert,
        update_do_latency_alert,
        create_do_ssl_alert,
        update_do_ssl_alert
    )

def initialize_do_monitor_api():
    """Initialize dynamic CR API client with a graceful fallback for local test environments."""
    try:
        kubernetes.config.load_incluster_config()
    except kubernetes.config.ConfigException:
        try:
            kubernetes.config.load_kube_config()
        except kubernetes.config.ConfigException:
            logging.warning("Kubernetes config not available; DoMonitor API client not initialized yet.")
            return None

    k8s_client = kubernetes.client.ApiClient()
    dyn_client = DynamicClient(k8s_client)
    return dyn_client.resources.get(api_version="douz.io/v1", kind="DoMonitor")


# DoMonitor Custom Resource API
do_monitor_api = initialize_do_monitor_api()

# ------------------------------------------------------------------------------
# Helper function: Validate Ingress annotations
# ------------------------------------------------------------------------------
def parse_int_annotation(value: str, field_name: str, cr_name: str, namespace: str):
    """Parse an integer annotation with clear error logging."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        logging.error(f"Invalid {field_name} value for DoMonitor: {cr_name} ({namespace})")
        return None


def validate_do_monitor_annotations(do_monitor_annotations: dict, cr_name: str, namespace: str) -> dict:
    """Validate the douz.io/do-monitor-* annotations for an Ingress resource."""

    email = do_monitor_annotations.get("douz.io/do-monitor-email")
    slack_webhook = do_monitor_annotations.get("douz.io/do-monitor-slack-webhook")
    slack_channel = do_monitor_annotations.get("douz.io/do-monitor-slack-channel")
    latency_threshold = do_monitor_annotations.get("douz.io/do-monitor-latency-threshold")
    latency_period = do_monitor_annotations.get("douz.io/do-monitor-latency-period")
    ssl_expiry_period = do_monitor_annotations.get("douz.io/do-monitor-ssl-expiry")

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

    latency_threshold_int = parse_int_annotation(latency_threshold, "latency threshold", cr_name, namespace)
    if latency_threshold and latency_threshold_int is None:
        return None

    ssl_expiry_period_int = parse_int_annotation(ssl_expiry_period, "ssl expiry period", cr_name, namespace)
    if ssl_expiry_period and ssl_expiry_period_int is None:
        return None

    return {
        "email": email,
        "email_alert": email_alert,
        "slack_webhook": slack_webhook,
        "slack_channel": slack_channel,
        "slack_alert": slack_alert,
        "latency_threshold": latency_threshold_int,
        "latency_period": latency_period or "2m",
        "ssl_expiry_period": ssl_expiry_period_int,
    }

# ------------------------------------------------------------------------------
# Helper functions: CRUD for the DoMonitor CR (source of truth)
# ------------------------------------------------------------------------------
# Function to create or update the DoMonitor CR
def build_cr_name(ingress_name: str, namespace: str, host: str) -> str:
    """Build a stable DNS-safe CR name per host."""
    safe_host = re.sub(r"[^a-z0-9-]+", "-", host.lower()).strip("-")
    safe_host = safe_host or "host"
    return f"{ingress_name}-{namespace}-{safe_host}-domonitor"


def extract_ingress_hosts(spec: dict) -> list:
    """Extract unique hosts from ingress rules."""
    hosts = []
    rules = (spec or {}).get("rules", [])
    for rule in rules:
        host = rule.get("host")
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def list_domonitor_crs_for_ingress(namespace: str, ingress_name: str) -> list:
    """List CR names associated with one ingress using labels."""
    if do_monitor_api is None:
        logging.error("DoMonitor API client is not initialized.")
        return []
    try:
        cr_list = do_monitor_api.get(namespace=namespace)
    except kubernetes.client.exceptions.ApiException as e:
        logging.error(f"Failed to list DoMonitor CRs for ingress {ingress_name} ({namespace})")
        logging.error(e)
        return []

    results = []
    for item in getattr(cr_list, "items", []):
        metadata = getattr(item, "metadata", {})
        labels = metadata.get("labels", {}) if isinstance(metadata, dict) else getattr(metadata, "labels", {}) or {}
        if labels.get("douz.io/ingress-name") == ingress_name:
            name = metadata.get("name") if isinstance(metadata, dict) else getattr(metadata, "name", None)
            if name:
                results.append(name)
    return results


def create_or_update_do_monitor_cr(cr_name: str, namespace: str, ingress_name: str, host: str, spec_data: dict):
    """
    Create or update the DoMonitor Custom Resource with relevant fields from the
    Ingress annotations or other sources.

    The CR is the single source of truth, and separate handlers will watch and
    reconcile the CR to the actual DigitalOcean resources.
    """
    payload = {
        "apiVersion": "douz.io/v1",
        "kind": "DoMonitor",
        "metadata": {
            "name": cr_name,
            "namespace": namespace,
            "labels": {
                "douz.io/managed-by": "do-monitor-operator",
                "douz.io/ingress-name": ingress_name,
            },
        },
        "spec": {
            "ingressName": ingress_name,
            "host": host,
            # Store annotation / config data needed by the CR handlers
            "config": {
                "email": spec_data["email"],
                "emailAlert": spec_data["email_alert"],
                "slackWebhook": spec_data["slack_webhook"],
                "slackChannel": spec_data["slack_channel"],
                "slackAlert": spec_data["slack_alert"],
                "latencyThreshold": spec_data["latency_threshold"],
                "latencyPeriod": spec_data["latency_period"],
                "sslExpiryPeriod": spec_data["ssl_expiry_period"],
            }
        }
    }

    # Attempt an update; if not found, create
    if do_monitor_api is None:
        logging.error("DoMonitor API client is not initialized.")
        return
    try:
        do_monitor_api.get(name=cr_name, namespace=namespace)
        # Merge patch - just replace the relevant fields
        do_monitor_api.patch(
            name=cr_name,
            namespace=namespace,
            body=payload,
            content_type="application/merge-patch+json"
        )
        logging.info(f"Updated DoMonitor CR: {cr_name} ({namespace})")
    except kubernetes.client.exceptions.ApiException as e:
        if e.status == 404:
            # Create new CR
            do_monitor_api.create(body=payload)
            logging.info(f"Created DoMonitor CR: {cr_name} ({namespace})")
        else:
            logging.error(f"Failed to create/update DoMonitor CR: {cr_name} ({namespace})")
            logging.error(e)

# Function to delete the DoMonitor CR
def delete_do_monitor_cr(cr_name: str, namespace: str):
    """Delete the DoMonitor Custom Resource when the Ingress is deleted."""
    if do_monitor_api is None:
        logging.error("DoMonitor API client is not initialized.")
        return
    try:
        do_monitor_api.delete(name=cr_name, namespace=namespace)
        logging.info(f"Deleted DoMonitor CR: {cr_name} ({namespace})")
    except kubernetes.client.exceptions.ApiException as e:
        if e.status == 404:
            return
        logging.error(f"Failed to delete DoMonitor CR: {cr_name} ({namespace})")
        logging.error(e)


def reconcile_ingress_to_crs(spec: dict, annotations: dict, ingress_name: str, namespace: str):
    """Reconcile per-host DoMonitor CRs from ingress state."""
    hosts = extract_ingress_hosts(spec)
    if not hosts:
        logging.info(f"Ingress has no hosts; cleaning up DoMonitor CRs for {ingress_name} ({namespace})")
        for existing_cr in list_domonitor_crs_for_ingress(namespace, ingress_name):
            delete_do_monitor_cr(existing_cr, namespace)
        return

    desired_cr_names = set()
    for host in hosts:
        cr_name = build_cr_name(ingress_name, namespace, host)
        do_monitor_annotations = {
            annotation: value
            for annotation, value in (annotations or {}).items()
            if annotation.startswith("douz.io/do-monitor-")
        }
        spec_data = validate_do_monitor_annotations(do_monitor_annotations, cr_name, namespace)
        if spec_data is None:
            return
        create_or_update_do_monitor_cr(
            cr_name=cr_name,
            namespace=namespace,
            ingress_name=ingress_name,
            host=host,
            spec_data=spec_data
        )
        desired_cr_names.add(cr_name)

    for existing_cr in list_domonitor_crs_for_ingress(namespace, ingress_name):
        if existing_cr not in desired_cr_names:
            delete_do_monitor_cr(existing_cr, namespace)

# ------------------------------------------------------------------------------
# Ingress handlers - Functions to create, update, and delete the CR based on
# Ingress events
# ------------------------------------------------------------------------------
# Create
@kopf.on.create("networking.k8s.io", "v1", "ingresses",
                annotations={"douz.io/do-monitor": "true"})
def ingress_created(spec, annotations, name, namespace, **kwargs):
    """
    When an Ingress is created with douz.io/do-monitor: true,
    create or update a DoMonitor CR. The CRD handler will handle DO resources.
    """
    reconcile_ingress_to_crs(spec, annotations, name, namespace)

# Update
@kopf.on.update("networking.k8s.io", "v1", "ingresses")
def ingress_updated(spec, annotations, name, namespace, **kwargs):
    """
    When an Ingress is updated with douz.io/do-monitor: true,
    update the DoMonitor CR accordingly.
    """
    if (annotations or {}).get("douz.io/do-monitor") == "true":
        reconcile_ingress_to_crs(spec, annotations, name, namespace)
        return

    for existing_cr in list_domonitor_crs_for_ingress(namespace, name):
        delete_do_monitor_cr(existing_cr, namespace)

# Delete
@kopf.on.delete("networking.k8s.io", "v1", "ingresses")
def ingress_deleted(name, namespace, **kwargs):
    """
    When an annotated Ingress is deleted, delete the corresponding DoMonitor CR.
    The CR Handler will remove the DO monitor & alerts.
    """
    for existing_cr in list_domonitor_crs_for_ingress(namespace, name):
        delete_do_monitor_cr(existing_cr, namespace)

# ------------------------------------------------------------------------------
# Helper functions: Validate spec, extract ids from DoMonitor CR spec and patch CR
# ------------------------------------------------------------------------------
# Validate spec
def validate_do_monitor_spec(spec: dict, cr_name: str, namespace: str) -> dict:
    """Validate the DoMonitor CR spec for required fields."""

    host = spec.get("host")
    if not host:
        logging.error(f"Host URL is missing for DoMonitor: {cr_name} ({namespace})")
        return None

    config = spec.get("config", {})
    email = config.get("email")
    slack_webhook = config.get("slackWebhook")
    slack_channel = config.get("slackChannel")
    email_alert = config.get("emailAlert")
    slack_alert = config.get("slackAlert")
    latency_threshold = config.get("latencyThreshold")
    latency_period = config.get("latencyPeriod")

    if not email and not slack_webhook:
        logging.error(f"Email or Slack Webhook is missing for DoMonitor: {cr_name} ({namespace})")
        return None

    if slack_webhook and not slack_channel:
        logging.error(f"Slack Channel is missing for DoMonitor: {cr_name} ({namespace})")
        return None
    
    if latency_threshold and not latency_period:
        logging.error(f"Latency Period is missing for DoMonitor: {cr_name} ({namespace})")
        return None

    return {
        "host": host,
        "email": email,
        "email_alert": email_alert,
        "slack_webhook": slack_webhook,
        "slack_channel": slack_channel,
        "slack_alert": slack_alert,
        "latency_threshold": latency_threshold,
        "latency_period": latency_period,
        "ssl_expiry_period": config.get("sslExpiryPeriod")
    }

# Extract IDs from the CR
def extract_current_ids(cr) -> dict:
    """Extract any existing DO resource IDs from the CR spec."""

    spec = cr.spec
    alerts = spec.get("alerts", {})
    return {
        "monitor_id": spec.get("monitorID", None),
        "uptime_alert_id": alerts.get("uptimeAlertID", None),
        "latency_alert_id": alerts.get("latencyAlertID", None),
        "ssl_alert_id": alerts.get("sslExpiryAlertID", None)
    }

# Patch CR (Update)
def patch_domonitor_status(name, namespace, patch_body: dict):
    """Utility to patch the DoMonitor CR (e.g., store DO monitor IDs)."""
    if do_monitor_api is None:
        logging.error("DoMonitor API client is not initialized.")
        return
    try:
        do_monitor_api.patch(
            name=name,
            namespace=namespace,
            body=patch_body,
            content_type="application/merge-patch+json"
        )
    except kubernetes.client.exceptions.ApiException as e:
        logging.error(f"Failed to patch DoMonitor CR: {name} ({namespace})")
        logging.error(e)

# ------------------------------------------------------------------------------
# CRD handlers - Functions to create, update, and delete the DigitalOcean 
# resources based on CR events
# ------------------------------------------------------------------------------
# Function to create the DO monitor and alerts
@kopf.on.create("douz.io", "v1", "domonitors")
def domonitor_created(body, spec, name, namespace, **kwargs):
    """When a new DoMonitor CR is created, create DO resources."""

    # Extract config data from .spec.config and validate
    spec_config = validate_do_monitor_spec(spec, name, namespace)
    if spec_config is None:
        return

    # Create DO monitor
    do_monitor_id = create_do_monitor(url=spec_config.get("host"), monitor_name=name)
    if not do_monitor_id:
        return

    # Create alerts (if applicable)
    uptime_alert_id = None
    if spec_config.get("email_alert") or spec_config.get("slack_alert"):
        uptime_alert_id = create_do_uptime_alert(
            monitor_id=do_monitor_id,
            email_alert=spec_config["email_alert"],
            email=spec_config["email"],
            slack_alert=spec_config["slack_alert"],
            slack_webhook=spec_config["slack_webhook"],
            slack_channel=spec_config["slack_channel"]
        )

    latency_alert_id = None
    if spec_config.get("latency_threshold"):
        latency_alert_id = create_do_latency_alert(
            monitor_id=do_monitor_id,
            latency_threshold=spec_config["latency_threshold"],
            latency_period=spec_config["latency_period"],
            email_alert=spec_config["email_alert"],
            email=spec_config["email"],
            slack_alert=spec_config["slack_alert"],
            slack_webhook=spec_config["slack_webhook"],
            slack_channel=spec_config["slack_channel"]
        )

    ssl_alert_id = None
    if spec_config.get("ssl_expiry_period"):
        ssl_alert_id = create_do_ssl_alert(
            monitor_id=do_monitor_id,
            email_alert=spec_config["email_alert"],
            email=spec_config["email"],
            slack_alert=spec_config["slack_alert"],
            slack_webhook=spec_config["slack_webhook"],
            slack_channel=spec_config["slack_channel"],
            days_left=spec_config["ssl_expiry_period"]
        )

    # Patch the CR to store the newly created DO resource IDs
    patch_body = {
        "spec": {
            "monitorID": do_monitor_id,
            "alerts": {
                "uptimeAlertID": uptime_alert_id,
                "latencyAlertID": latency_alert_id,
                "sslExpiryAlertID": ssl_alert_id,
            }
        }
    }
    patch_domonitor_status(name, namespace, patch_body)

# Function to update the DO monitor and alerts
@kopf.on.update("douz.io", "v1", "domonitors")
def domonitor_updated(body, spec, name, namespace, **kwargs):
    """
    When the DoMonitor CR is updated, update the DO resources
    (monitor + alerts) to reflect any changes in spec.config.
    """

    # Extract config data from .spec.config and validate
    spec_config = validate_do_monitor_spec(spec, name, namespace)
    if spec_config is None:
        return

    # Extract existing DO resource IDs from the CR
    current_ids = extract_current_ids(body)

    monitor_id = current_ids["monitor_id"]
    if monitor_id:
        update_do_monitor(
            monitor_id=monitor_id,
            url=spec_config["host"],
            monitor_name=name
        )
    else:
        monitor_id = create_do_monitor(url=spec_config["host"], monitor_name=name)
        if not monitor_id:
            return
        patch_domonitor_status(name, namespace, {"spec": {"monitorID": monitor_id}})

    # Update or create alerts
    patch_cr = False
    patch_payload = {}

    if (spec_config.get("email_alert") or spec_config.get("slack_alert")) and current_ids["uptime_alert_id"]:
        update_do_uptime_alert(
            monitor_id=monitor_id,
            alert_id=current_ids["uptime_alert_id"],
            email_alert=spec_config["email_alert"],
            email=spec_config["email"],
            slack_alert=spec_config["slack_alert"],
            slack_webhook=spec_config["slack_webhook"],
            slack_channel=spec_config["slack_channel"]
        )
    elif spec_config.get("email_alert") or spec_config.get("slack_alert"):
        uptime_alert_id = create_do_uptime_alert(
            monitor_id=monitor_id,
            email_alert=spec_config["email_alert"],
            email=spec_config["email"],
            slack_alert=spec_config["slack_alert"],
            slack_webhook=spec_config["slack_webhook"],
            slack_channel=spec_config["slack_channel"]
        )
        patch_cr = True
        patch_payload["spec"] = patch_payload.get("spec", {})
        patch_payload["spec"]["alerts"] = patch_payload["spec"].get("alerts", {})
        patch_payload["spec"]["alerts"]["uptimeAlertID"] = uptime_alert_id
    else:
        logging.info("No changes to Uptime Alert")

    if spec_config.get("latency_threshold") and spec_config.get("latency_period") and current_ids["latency_alert_id"]:
        update_do_latency_alert(
            monitor_id=monitor_id,
            alert_id=current_ids["latency_alert_id"],
            email_alert=spec_config["email_alert"],
            email=spec_config["email"],
            slack_alert=spec_config["slack_alert"],
            slack_webhook=spec_config["slack_webhook"],
            slack_channel=spec_config["slack_channel"],
            latency_threshold=spec_config["latency_threshold"],
            latency_period=spec_config["latency_period"]
        )
    elif spec_config.get("latency_threshold") and spec_config.get("latency_period"):
        latency_alert_id = create_do_latency_alert(
            monitor_id=monitor_id,
            latency_threshold=spec_config["latency_threshold"],
            latency_period=spec_config["latency_period"],
            email_alert=spec_config["email_alert"],
            email=spec_config["email"],
            slack_alert=spec_config["slack_alert"],
            slack_webhook=spec_config["slack_webhook"],
            slack_channel=spec_config["slack_channel"]
        )
        patch_cr = True
        patch_payload["spec"] = patch_payload.get("spec", {})
        patch_payload["spec"]["alerts"] = patch_payload["spec"].get("alerts", {})
        patch_payload["spec"]["alerts"]["latencyAlertID"] = latency_alert_id
    else:
        logging.info("No changes to Latency Alert")

    if spec_config.get("ssl_expiry_period") and current_ids["ssl_alert_id"]:
        update_do_ssl_alert(
            monitor_id=monitor_id,
            alert_id=current_ids["ssl_alert_id"],
            email_alert=spec_config["email_alert"],
            email=spec_config["email"],
            slack_alert=spec_config["slack_alert"],
            slack_webhook=spec_config["slack_webhook"],
            slack_channel=spec_config["slack_channel"],
            days_left=spec_config["ssl_expiry_period"]
        )
    elif spec_config.get("ssl_expiry_period"):
        ssl_alert_id = create_do_ssl_alert(
            monitor_id=monitor_id,
            email_alert=spec_config["email_alert"],
            email=spec_config["email"],
            slack_alert=spec_config["slack_alert"],
            slack_webhook=spec_config["slack_webhook"],
            slack_channel=spec_config["slack_channel"],
            days_left=spec_config["ssl_expiry_period"]
        )
        patch_cr = True
        patch_payload["spec"] = patch_payload.get("spec", {})
        patch_payload["spec"]["alerts"] = patch_payload["spec"].get("alerts", {})
        patch_payload["spec"]["alerts"]["sslExpiryAlertID"] = ssl_alert_id
    else:
        logging.info("No changes to SSL Alert")

    # Patch the CR if any new alerts were created
    if patch_cr:
        patch_domonitor_status(name, namespace, patch_payload)

# function to delete the DO monitor and alerts
@kopf.on.delete("douz.io", "v1", "domonitors")
def domonitor_deleted(body, name, namespace, **kwargs):
    """
    When the DoMonitor CR is deleted, remove the associated
    DO resources (monitor + alerts).
    """

    current_ids = extract_current_ids(body)
    monitor_id = current_ids["monitor_id"]
    if monitor_id:
        delete_do_monitor(monitor_id)
        logging.info(f"DigitalOcean monitor and alerts deleted for CR: {name} ({namespace})")
