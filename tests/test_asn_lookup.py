import csv
import importlib.util
import pathlib
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).resolve().parent.parent / "asn_lookup.py"
SPEC = importlib.util.spec_from_file_location("asn_lookup", MODULE_PATH)
asn_lookup = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(asn_lookup)


class AsnLookupTests(unittest.TestCase):
    def test_parse_cymru_response(self):
        sample = (
            "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name\n"
            "16509 | 13.235.169.43 | 13.232.0.0/14 | US | arin | 2019-10-01 | AMAZON-02 - Amazon.com, Inc., US\n"
        )
        rows = asn_lookup.parse_cymru_response(sample)
        self.assertIn("13.235.169.43", rows)
        self.assertEqual(rows["13.235.169.43"]["ASN"], "16509")
        self.assertEqual(rows["13.235.169.43"]["RIR"], "arin")

    def test_build_cymru_query(self):
        query = asn_lookup.build_cymru_query(["1.1.1.1", "8.8.8.8"])
        self.assertIn("begin\nverbose", query)
        self.assertIn("1.1.1.1", query)
        self.assertTrue(query.endswith("end\n"))

    def test_load_ips_skips_invalid(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write("1.1.1.1\nnot-an-ip\n#comment\n8.8.8.8\n")
            path = tf.name
        ips = asn_lookup.load_ips(path)
        self.assertEqual(ips, ["1.1.1.1", "8.8.8.8"])

    def test_write_csv(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv") as tf:
            path = tf.name

        rows = [
            {
                "IP": "1.1.1.1",
                "ASN": "13335",
                "ASN_Org": "CLOUDFLARENET",
                "Authority_Source": asn_lookup.AUTHORITY_SOURCE,
                "BGP_Prefix": "1.1.1.0/24",
                "CC": "AU",
                "RIR": "apnic",
                "Allocated": "2011-08-11",
                "Lookup_Status": "OK",
                "Error": "",
                "Timestamp": "2026-01-01T00:00:00+00:00",
                "Tool_Version": asn_lookup.VERSION,
            }
        ]
        asn_lookup.write_csv(path, rows)

        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
        self.assertTrue(lines[0].startswith("IP,ASN,ASN_Org,Authority_Source"))

        with open(path, newline="", encoding="utf-8") as f:
            reader = list(csv.DictReader(f))

        self.assertEqual(len(reader), 1)
        self.assertEqual(reader[0]["IP"], "1.1.1.1")
        self.assertEqual(reader[0]["Lookup_Status"], "OK")
        self.assertEqual(reader[0]["Authority_Source"], asn_lookup.AUTHORITY_SOURCE)

    def test_non_public_detection(self):
        self.assertTrue(asn_lookup.is_non_public("10.0.0.1"))
        self.assertTrue(asn_lookup.is_non_public("172.16.1.1"))
        self.assertTrue(asn_lookup.is_non_public("192.168.5.5"))
        self.assertFalse(asn_lookup.is_non_public("8.8.8.8"))

if __name__ == "__main__":
    unittest.main()
