
import unittest

from security.policy import PolicyEngine


class FakeClock:

    def __init__(self):
        self.current_time = 0.0

    def __call__(self):
        return self.current_time

    def advance(self, seconds):
        self.current_time += seconds


def create_traffic(src_port=45000, dst_port=5001):

    return {
        "src_ip": "10.0.0.2",
        "dst_ip": "10.0.0.10",
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": "TCP",
        "tcp_flags": "SYN"
    }


class TestPolicyEngine(unittest.TestCase):

    def setUp(self):
        self.clock = FakeClock()
        self.policy = PolicyEngine(
            mode="dynamic",
            clock=self.clock
        )

    def test_authorized_port(self):

        traffic = create_traffic(dst_port=5000)

        result = self.policy.evaluate(traffic)

        self.assertEqual(result["action"], "ALLOW")

    def test_benchmark_port(self):

        traffic = create_traffic(dst_port=5201)

        result = self.policy.evaluate(traffic)

        self.assertEqual(result["action"], "ALLOW")

    def test_unauthorized_port(self):

        result = self.policy.evaluate(create_traffic())

        self.assertEqual(result["action"], "DENY")

    def test_third_distinct_attempt_blocks(self):

        self.assertEqual(
            self.policy.evaluate(create_traffic(45000))["action"],
            "DENY"
        )

        self.assertEqual(
            self.policy.evaluate(create_traffic(45001))["action"],
            "DENY"
        )

        self.assertEqual(
            self.policy.evaluate(create_traffic(45002))["action"],
            "BLOCK"
        )

    def test_duplicate_attempt_is_ignored(self):

        self.policy.evaluate(create_traffic(45000))

        result = self.policy.evaluate(create_traffic(45000))

        self.assertEqual(result["action"], "DENY")
        self.assertIn("Duplicate", result["reason"])

    def test_old_attempts_expire(self):

        self.policy.evaluate(create_traffic(45000))

        self.clock.advance(11)

        self.policy.evaluate(create_traffic(45001))

        result = self.policy.evaluate(create_traffic(45002))

        self.assertEqual(result["action"], "DENY")

    def test_static_mode_never_blocks(self):

        static_policy = PolicyEngine(
            mode="static",
            clock=self.clock
        )

        for port in (45000, 45001, 45002):
            result = static_policy.evaluate(create_traffic(port))

            self.assertEqual(result["action"], "DENY")

    def test_recovery_with_wrong_cookie(self):

        self.policy.evaluate(create_traffic(45000))
        self.policy.evaluate(create_traffic(45001))
        self.policy.evaluate(create_traffic(45002))

        self.policy.mark_block_installed("10.0.0.2", 123)

        result = self.policy.mark_block_removed("10.0.0.2", 456)

        self.assertFalse(result)

    def test_recovery_with_correct_cookie(self):

        self.policy.evaluate(create_traffic(45000))
        self.policy.evaluate(create_traffic(45001))
        self.policy.evaluate(create_traffic(45002))

        self.policy.mark_block_installed("10.0.0.2", 123)

        result = self.policy.mark_block_removed("10.0.0.2", 123)

        self.assertTrue(result)

    def test_blocked_ip_stays_blocked_until_recovery(self):

        for port in (45000, 45001, 45002):
            self.policy.evaluate(create_traffic(port))

        self.policy.mark_block_installed("10.0.0.2", 123)

        result = self.policy.evaluate(
            create_traffic(45003, dst_port=5000)
        )

        self.assertEqual(result["action"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
