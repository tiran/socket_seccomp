import socket_seccomp

import socket
import unittest


class TestSocketSeccomp(unittest.TestCase):
    def test_00_connections_ok(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM):
            pass
        with socket.create_connection(("www.python.org", 443)):
            pass

    def test_01_load_seccomp(self):
        socket_seccomp.block_socket()

    def test_02_unix_ok(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM):
            pass

    def test_02_socket_eperm(self):
        with self.assertRaises(PermissionError):
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with self.assertRaises(PermissionError):
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with self.assertRaises(PermissionError):
            socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        with self.assertRaises(PermissionError):
            socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

    def test_02_conn_blocked(self):
        with self.assertRaises(OSError):
            socket.create_connection(("www.python.org", 443))


if __name__ == "__main__":
    unittest.main()
