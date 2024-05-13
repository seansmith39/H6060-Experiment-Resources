#!/usr/bin/env python3

import os
import unittest
from argparse import Namespace
from unittest.mock import patch
from main.python3 import experiment_1_generate_report


DEFAULT_PRODUCT_NAME = "horusec"
DEFAULT_CSV_REPORT_FILENAME = (
    f"experiment_1_{DEFAULT_PRODUCT_NAME.lower()}_results.csv"
)


class DevNull:
    def __init__(self):
        pass

    def write(self, s):
        pass


@patch("sys.stdout", new=DevNull())
@patch("sys.stderr", new=DevNull())
class TestExperiment1GenerateReport(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestExperiment1GenerateReport, self).__init__(*args, **kwargs)

    def __mock_args(product_name: str) -> Namespace:
        """Mock arguments in argparse.Namespace type

        :argument
            product_name:str -- Name of the product to be mocked in the arguments

        :return
            argparse.Namespace -- Mocked arguments
        """
        return Namespace(product_name=product_name)

    def test_get_mitre_top_25_cwe(self):
        mitre_top_25 = experiment_1_generate_report.get_mitre_top_25_cwe()
        self.assertTrue("CWE-276" in mitre_top_25)

    def test_get_owasp_top_10_cwe(self):
        owasp_top_10 = experiment_1_generate_report.get_owasp_top_10_cwe()
        for key, value in owasp_top_10.items():
            if "CWE-213" in value:
                owasp_cwe_category = key
        self.assertEqual(owasp_cwe_category, "A04 Insecure Design")

    def test_write_csv_report(self):
        product_data = [
            [
                "SCA",
                "Eclipse Steady Scan",
                "Code-centric",
                "CVE-2019-14540",
                "CWE-502",
                "9.8",
                "CRITICAL",
                "A08 Software and Data Integrity Failures",
                "15",
                "Transitive",
                "com.fasterxml.jackson.core:jackson-databind:2.10.3",
            ]
        ]
        experiment_1_generate_report.write_csv_report(
            DEFAULT_PRODUCT_NAME, product_data
        )
        self.assertTrue(os.path.isfile(DEFAULT_CSV_REPORT_FILENAME))

    def test_main(self):
        args = experiment_1_generate_report.get_args(
            ["--product-name", DEFAULT_PRODUCT_NAME]
        )
        result = experiment_1_generate_report.main(args)
        self.assertEqual(result, None)

    @classmethod
    def tearDownClass(cls):
        if os.path.isfile(DEFAULT_CSV_REPORT_FILENAME):
            os.remove(DEFAULT_CSV_REPORT_FILENAME)


if __name__ == "__main__":
    unittest.main()
