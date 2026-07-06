import unittest

from tron.grid import classify, patrol, has_intrusions

POLICY = {
    "zones": {"iot": "iot", "boh": "boh", "pos": "pos"},
    "flows": [{"src_zone": "boh", "dst_zone": "iot", "port": 1883}],
}


class GridTests(unittest.TestCase):
    def test_sanctioned_flow(self):
        c = {"src_zone": "boh", "dst_zone": "iot", "port": 1883}
        self.assertEqual(classify(POLICY, c)["verdict"], "sanctioned")

    def test_uptier_offlist_is_intrusion(self):
        c = {"src_zone": "iot", "dst_zone": "pos", "port": 443}
        self.assertEqual(classify(POLICY, c)["verdict"], "intrusion")

    def test_downtier_offlist_is_unsanctioned(self):
        c = {"src_zone": "pos", "dst_zone": "boh", "port": 8080}
        self.assertEqual(classify(POLICY, c)["verdict"], "unsanctioned")

    def test_sanctioned_uptier_is_not_intrusion(self):
        pol = {"zones": {"iot": "iot", "pos": "pos"},
               "flows": [{"src_zone": "iot", "dst_zone": "pos", "port": 443}]}
        c = {"src_zone": "iot", "dst_zone": "pos", "port": 443}
        self.assertEqual(classify(pol, c)["verdict"], "sanctioned")

    def test_patrol_flags_intrusions(self):
        conns = [
            {"src_zone": "boh", "dst_zone": "iot", "port": 1883},
            {"src_zone": "iot", "dst_zone": "pos", "port": 443},
        ]
        results = patrol(POLICY, conns)
        self.assertTrue(has_intrusions(results))
        self.assertEqual(results[0]["verdict"], "sanctioned")


if __name__ == "__main__":
    unittest.main()
