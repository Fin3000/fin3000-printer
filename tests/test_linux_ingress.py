"""Product transport tests: private pipes/socketpairs, never a host printer."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest
from uuid import uuid4

spec = importlib.util.spec_from_file_location("fin3000_product_ingress", Path(__file__).resolve().parents[1] / "platforms/linux/ingress.py")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class IngressTests(unittest.TestCase):
    def setUp(self):
        self.generation = str(uuid4())
        self.installation = module.Installation(os.getuid(), "synthetic", self.generation, "synthetic", "/no-host-socket", 0, 0)
        self.pdf = b"%PDF-synthetic-only"
        self.description = {"version": 2, "generation": self.generation, "nativeJobUuid": str(uuid4()), "jobId": 12,
                            "title": "Änderung", "size": len(self.pdf), "sha256": hashlib.sha256(self.pdf).hexdigest()}

    def test_metadata_rejects_duplicate_keys_and_identity_size_or_control_drift(self):
        self.assertEqual(module.metadata(json.dumps(self.description).encode(), self.installation), self.description)
        for change in ({"generation": str(uuid4())}, {"nativeJobUuid": "invalid"}, {"size": True}, {"size": module.LIMIT + 1},
                       {"size": 4}, {"jobId": -1}, {"title": "bad\u202evalue"}, {"destination": "foreign"}):
            with self.subTest(change=change), self.assertRaises(module.IngressError):
                module.metadata(json.dumps({**self.description, **change}).encode(), self.installation)
        with self.assertRaises(module.IngressError):
            module.strict_json(b'{"size":1,"size":2}')

    def test_real_non_root_socket_peer_is_denied(self):
        first, second = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with first, second, self.assertRaises(module.IngressError):
            module.verify_peer(first)

    def test_real_seqpacket_boundary_truncation_is_not_silently_accepted(self):
        first, second = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with first, second:
            second.send(b"oversized")
            with self.assertRaises(module.IngressError):
                module.packet(first, 3)

    def test_pdf_is_exact_size_and_digest(self):
        first, second = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with first, second:
            second.send(self.pdf[:7]); second.send(self.pdf[7:])
            self.assertEqual(module.read_pdf(first, self.description), self.pdf)
            second.send(self.pdf)
            with self.assertRaises(module.IngressError):
                module.read_pdf(first, {**self.description, "sha256": "0" * 64})

    def handoff(self, ack):
        incoming, parent_write = os.pipe()
        parent_read, outgoing = os.pipe()
        evidence = []
        def parent():
            deadline = time.monotonic() + 5
            length = struct.unpack("!I", module.pipe_read(parent_read, 4, deadline))[0]
            header = module.strict_json(module.pipe_read(parent_read, length, deadline))
            data = module.pipe_read(parent_read, header["size"], deadline)
            evidence.append((header, data))
            reply = json.dumps(ack).encode()
            module.pipe_write(parent_write, struct.pack("!I", len(reply)) + reply, deadline)
        worker = threading.Thread(target=parent)
        worker.start()
        try:
            result = module.handoff(incoming, outgoing, self.description, self.pdf)
        finally:
            worker.join(timeout=6)
            for fd in (incoming, parent_write, parent_read, outgoing):
                os.close(fd)
        return result, evidence

    def test_local_ack_only_after_parent_has_received_exact_frame_and_durable_operation_id(self):
        operation = str(uuid4())
        result, evidence = self.handoff({"nativeJobUuid": self.description["nativeJobUuid"], "accepted": True, "operationId": operation})
        self.assertEqual(result, operation)
        self.assertEqual(evidence[0][0], {"type": "job", **self.description})
        self.assertEqual(evidence[0][1], self.pdf)

    def test_rejected_or_wrong_identity_ack_never_means_local_handoff(self):
        for ack in ({"nativeJobUuid": self.description["nativeJobUuid"], "accepted": False, "code": "QUEUE_FULL"},
                    {"nativeJobUuid": str(uuid4()), "accepted": True, "operationId": str(uuid4())},
                    {"nativeJobUuid": self.description["nativeJobUuid"], "accepted": True, "operationId": "invalid"}):
            with self.subTest(ack=ack), self.assertRaises(module.IngressError):
                self.handoff(ack)

    def test_private_pipe_eof_is_not_an_empty_success(self):
        incoming, outgoing = os.pipe()
        os.close(outgoing)
        try:
            with self.assertRaises(module.IngressError):
                module.pipe_read(incoming, 4, time.monotonic() + 1)
        finally:
            os.close(incoming)

    def test_actual_node_spawn_stdio_is_an_authenticated_parent_socketpair(self):
        source = Path(__file__).resolve().parents[1] / "platforms/linux/ingress.py"
        python = f'import runpy,json; m=runpy.run_path({str(source)!r}); print(json.dumps([m["private_channel"](i) for i in (0,1,3)]))'
        javascript = ('import {spawn} from "node:child_process"; const child=spawn("/usr/bin/python3",'
                      + json.dumps(["-B", "-I", "-c", python])
                      + ',{stdio:["pipe","pipe","ignore","pipe"]}); child.stdout.pipe(process.stdout); child.on("exit",c=>process.exitCode=c); child.stdin.end();')
        result = subprocess.run(["node", "--input-type=module", "-e", javascript], capture_output=True, check=True, timeout=5)
        self.assertEqual(json.loads(result.stdout), [True, True, True])


if __name__ == "__main__":
    unittest.main()
