import os
import time
from opensearchpy import OpenSearch
from src.alert_schema import Alert

class OpenSearchStorage:
    def __init__(self, host=None, port=None, index_name="stealthtap-alerts"):
        self.index_name = index_name
        # FIX: host/port were hardcoded to "localhost", which only works if
        # this code runs directly on the Docker host hitting compose's
        # published ports. If this ever runs *inside* its own container on
        # the compose network, "localhost" resolves to that container's own
        # loopback, not the opensearch service. Now overridable via env vars,
        # with the same compose-friendly defaults streaming_engine.py uses.
        host = host or os.environ.get("OPENSEARCH_HOST", "localhost")
        port = port or int(os.environ.get("OPENSEARCH_PORT", "9200"))

        # FIX: password was hardcoded as a literal string in source, while
        # docker-compose.yml deliberately forces a real value via .env with
        # no default (`:?set a real password...`). A hardcoded literal here
        # could silently drift from whatever .env actually contains, and
        # committing a credential in source is bad practice regardless.
        password = os.environ.get("OPENSEARCH_ADMIN_PASSWORD")
        if not password:
            raise RuntimeError(
                "OPENSEARCH_ADMIN_PASSWORD is not set. Use the same value "
                "your .env file supplies to docker-compose.yml -- there is "
                "intentionally no default."
            )

        self.client = OpenSearch(
            hosts=[{"host": host, "port": port}],
            http_compress=True,
            http_auth=("admin", password),
            use_ssl=True,
            verify_certs=False,  # TODO: still disabled -- fine for dev, but the
            ssl_show_warn=False  # PRD's "clustered with TLS" claim implies real
                                  # cert verification eventually.
        )
        self._wait_for_connection()
        self._ensure_index()

    def _wait_for_connection(self, retries=10, delay=3):
        for attempt in range(retries):
            try:
                if self.client.ping():
                    return
            except Exception:
                pass
            print(f"[*] Waiting for OpenSearch to accept connections (attempt {attempt + 1}/{retries})...")
            time.sleep(delay)
        raise ConnectionError("Could not connect to OpenSearch cluster.")

    def _ensure_index(self):
        if not self.client.indices.exists(index=self.index_name):
            body = {
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "alert_id": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "threat_class": {"type": "keyword"},
                        "confidence_score": {"type": "float"}
                    }
                }
            }
            self.client.indices.create(index=self.index_name, body=body)

    def index_alert(self, alert: Alert):
        data = alert.model_dump(mode="json")
        if "property_timestamp" in data:
            data["@timestamp"] = data.pop("property_timestamp")
        self.client.index(
            index=self.index_name,
            body=data,
            id=alert.alert_id
        )
