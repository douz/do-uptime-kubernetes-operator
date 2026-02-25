import importlib
import logging
import os
import sys
import types
import unittest
from unittest.mock import patch


class _ApiException(Exception):
    def __init__(self, status=None):
        super().__init__(f"status={status}")
        self.status = status


def _install_test_stubs():
    # kopf decorator stubs
    kopf = types.ModuleType("kopf")

    def _decorator(*args, **kwargs):
        def _wrap(fn):
            return fn
        return _wrap

    kopf.on = types.SimpleNamespace(create=_decorator, update=_decorator, delete=_decorator)
    sys.modules["kopf"] = kopf

    # kubernetes stubs
    kubernetes = types.ModuleType("kubernetes")

    class _ConfigException(Exception):
        pass

    kubernetes.config = types.SimpleNamespace(
        ConfigException=_ConfigException,
        load_incluster_config=lambda: (_ for _ in ()).throw(_ConfigException()),
        load_kube_config=lambda: (_ for _ in ()).throw(_ConfigException()),
    )
    kubernetes.client = types.SimpleNamespace(
        ApiClient=lambda: object(),
        exceptions=types.SimpleNamespace(ApiException=_ApiException),
    )
    sys.modules["kubernetes"] = kubernetes

    dynamic = types.ModuleType("kubernetes.dynamic")

    class _DynamicClient:
        def __init__(self, *args, **kwargs):
            self.resources = types.SimpleNamespace(get=lambda **kwargs: None)

    dynamic.DynamicClient = _DynamicClient
    sys.modules["kubernetes.dynamic"] = dynamic

    # pydo client stub
    pydo = types.ModuleType("pydo")

    class _Client:
        def __init__(self, token=None):
            self.token = token
            self.uptime = types.SimpleNamespace()

    pydo.Client = _Client
    sys.modules["pydo"] = pydo


_install_test_stubs()
logging.disable(logging.CRITICAL)
os.environ.pop("DIGITALOCEAN_TOKEN", None)
op = importlib.import_module("domonitor_operator.domonitor_operator")


def _valid_annotations():
    return {
        "douz.com/do-monitor": "true",
        "douz.com/do-monitor-email": "alerts@example.com",
    }


def _spec_with_hosts(*hosts):
    return {"rules": [{"host": host} for host in hosts]}


class OperatorReconcileTests(unittest.TestCase):
    def test_validate_do_monitor_annotations_rejects_invalid_integers(self):
        annotations = {
            "douz.com/do-monitor-email": "alerts@example.com",
            "douz.com/do-monitor-latency-threshold": "not-an-int",
            "douz.com/do-monitor-latency-period": "2m",
        }

        result = op.validate_do_monitor_annotations(annotations, "cr", "default")

        self.assertIsNone(result)

    def test_reconcile_ingress_creates_per_host_and_deletes_stale(self):
        created = []
        deleted = []

        with patch.object(
            op,
            "create_or_update_do_monitor_cr",
            side_effect=lambda cr_name, namespace, ingress_name, host, spec_data: created.append((cr_name, host)),
        ), patch.object(
            op,
            "list_domonitor_crs_for_ingress",
            side_effect=lambda namespace, ingress_name: [
                op.build_cr_name("ing", "default", "a.example.com"),
                "stale-cr",
            ],
        ), patch.object(
            op,
            "delete_do_monitor_cr",
            side_effect=lambda cr_name, namespace: deleted.append(cr_name),
        ):
            op.reconcile_ingress_to_crs(
                spec=_spec_with_hosts("a.example.com", "b.example.com"),
                annotations=_valid_annotations(),
                ingress_name="ing",
                namespace="default",
            )

        self.assertEqual(
            created,
            [
                (op.build_cr_name("ing", "default", "a.example.com"), "a.example.com"),
                (op.build_cr_name("ing", "default", "b.example.com"), "b.example.com"),
            ],
        )
        self.assertEqual(deleted, ["stale-cr"])

    def test_ingress_updated_without_annotation_deletes_existing_crs(self):
        deleted = []

        with patch.object(op, "list_domonitor_crs_for_ingress", return_value=["cr1", "cr2"]), patch.object(
            op,
            "delete_do_monitor_cr",
            side_effect=lambda cr_name, namespace: deleted.append((cr_name, namespace)),
        ):
            op.ingress_updated(spec={}, annotations={}, name="ing", namespace="default")

        self.assertEqual(deleted, [("cr1", "default"), ("cr2", "default")])

    def test_domonitor_updated_creates_monitor_when_monitor_id_missing(self):
        created_alert_monitor_ids = []
        patch_calls = []

        with patch.object(
            op,
            "validate_do_monitor_spec",
            return_value={
                "host": "example.com",
                "email": "alerts@example.com",
                "email_alert": True,
                "slack_webhook": None,
                "slack_channel": None,
                "slack_alert": False,
                "latency_threshold": None,
                "latency_period": "2m",
                "ssl_expiry_period": None,
            },
        ), patch.object(
            op,
            "extract_current_ids",
            return_value={
                "monitor_id": None,
                "uptime_alert_id": None,
                "latency_alert_id": None,
                "ssl_alert_id": None,
            },
        ), patch.object(
            op,
            "create_do_monitor",
            return_value="monitor-123",
        ), patch.object(
            op,
            "create_do_uptime_alert",
            side_effect=lambda monitor_id, **kwargs: created_alert_monitor_ids.append(monitor_id) or "uptime-alert-123",
        ), patch.object(
            op,
            "create_do_latency_alert",
            return_value=None,
        ), patch.object(
            op,
            "create_do_ssl_alert",
            return_value=None,
        ), patch.object(
            op,
            "update_do_monitor",
            side_effect=AssertionError("update should not be called"),
        ), patch.object(
            op,
            "patch_domonitor_status",
            side_effect=lambda name, namespace, patch_body: patch_calls.append(patch_body),
        ):
            op.domonitor_updated(
                body=types.SimpleNamespace(spec={}),
                spec={},
                name="cr1",
                namespace="default",
            )

        self.assertEqual(created_alert_monitor_ids, ["monitor-123"])
        self.assertEqual(patch_calls[0], {"spec": {"monitorID": "monitor-123"}})
        self.assertEqual(patch_calls[1], {"spec": {"alerts": {"uptimeAlertID": "uptime-alert-123"}}})


if __name__ == "__main__":
    unittest.main()
