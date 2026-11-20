
import socket
import json
import uuid
import time
import threading
import queue

from datetime import datetime, timezone


class EventSender:

    def __init__(
        self,
        host="127.0.0.1",
        port=9000,
        timeout=2.0,
        max_retries=2
    ):

        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_retries = max_retries

        self.event_queue = queue.Queue(maxsize=1000)

        self.worker = threading.Thread(
            target=self._worker,
            daemon=True
        )

        self.worker.start()

    def _prepare_event(self, event):

        action = event.get("action", event.get("event_type"))

        timestamp = event.get("timestamp_utc")

        if not timestamp and isinstance(event.get("timestamp"), str):
            timestamp = event["timestamp"]

        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat(
                timespec="milliseconds"
            ).replace("+00:00", "Z")

        prepared = {
            "event_id": event.get("event_id", f"evt-{uuid.uuid4().hex}"),
            "timestamp_utc": timestamp,
            "action": action,
            "src_ip": event.get("src_ip"),
            "reason": event.get("reason")
        }

        for field in ("dst_ip", "dst_port", "response_ms", "cookie"):

            if field in event:
                prepared[field] = event[field]

        return prepared

    def send_event(self, event):

        try:

            prepared = self._prepare_event(event)

            if (
                prepared["action"] not in ("DENY", "BLOCK", "RECOVER")
                or not prepared["src_ip"]
                or not prepared["reason"]
            ):
                print("[EVENT SENDER] Invalid event")
                return False

            self.event_queue.put_nowait(prepared)

            return True

        except queue.Full:

            print("[EVENT SENDER] Queue full; event dropped")
            return False

        except (AttributeError, TypeError):

            print("[EVENT SENDER] Invalid event format")
            return False

    def _deliver(self, event):

        message = json.dumps(event) + "\n"

        for attempt in range(self.max_retries + 1):

            try:

                with socket.create_connection(
                    (self.host, self.port),
                    timeout=self.timeout
                ) as client:

                    client.settimeout(self.timeout)

                    with client.makefile("r", encoding="utf-8") as reader:

                        client.sendall(message.encode("utf-8"))

                        response = reader.readline()

                        if not response:
                            raise ConnectionError("No logger acknowledgement")

                        acknowledgement = json.loads(response)

                        if (
                            acknowledgement.get("status") == "ok"
                            and acknowledgement.get("event_id") == event["event_id"]
                        ):
                            print(
                                f"[EVENT SENDER] Delivered: "
                                f"{event['action']} | {event['event_id']}"
                            )
                            return True

                        raise ConnectionError("Invalid logger acknowledgement")

            except (OSError, ValueError, json.JSONDecodeError) as error:

                print(
                    f"[EVENT SENDER] Attempt {attempt + 1} failed: {error}"
                )

                if attempt < self.max_retries:
                    time.sleep(0.5)

        print("[EVENT SENDER] Event delivery failed")

        return False

    def _worker(self):

        while True:

            event = self.event_queue.get()

            try:
                if event is None:
                    return

                self._deliver(event)

            finally:
                self.event_queue.task_done()

    def flush(self):
        self.event_queue.join()

    def close(self):

        self.event_queue.put(None)
        self.worker.join(timeout=5)
