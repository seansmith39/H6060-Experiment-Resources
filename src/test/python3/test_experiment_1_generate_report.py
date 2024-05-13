#!/usr/bin/env python3

import os
import unittest
import json as JSON
from argparse import Namespace
from unittest.mock import patch
from main.python3 import experiment_1_generate_report


TEST_DIRECTORY_RESOURCES = (
    os.path.dirname(os.path.realpath(__file__)) + "/resources/"
)
NIST_CVE_ID_RESPONSE = TEST_DIRECTORY_RESOURCES + "nist-cve-information.json"

DEFAULT_PRODUCT_NAME = "horusec"
DEFAULT_CSV_REPORT_FILENAME = (
    f"experiment_1_{DEFAULT_PRODUCT_NAME.lower()}_results.csv"
)
NVD_API_KEY = "11111111-2222-3333-4444-555555555555"
NIST_CVE_ID = "CVE-2019-14540"


def mocked_response(token: str, url: str):
    class MockResponse:
        def __init__(self, file, status_code):
            self.file = file
            try:
                with open(self.file, "r") as f:
                    self.text = f.read()
            except Exception:
                self.text = file

            self.status_code = status_code

        def status_code(self):
            return self.status_code

        def ok(self):
            return self.ok

        def json(self):
            return JSON.loads(self.text)

    if NIST_CVE_ID in url:
        return MockResponse(NIST_CVE_ID_RESPONSE, None)
    else:
        return None


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

    def __mock_args(nvd_api_key: str, product_name: str) -> Namespace:
        """Mock arguments in argparse.Namespace type

        :parameter
            nvd_api_key:str -- NVD API Key to be mocked in the arguments
            product_name:str -- Name of the product to be mocked in the arguments

        :return
            argparse.Namespace -- Mocked arguments
        """
        return Namespace(nvd_api_key=nvd_api_key, product_name=product_name)

    def test_get_mitre_top_25_cwe(self):
        mitre_top_25 = experiment_1_generate_report.get_mitre_top_25_cwe()
        self.assertTrue("CWE-276" in mitre_top_25)

    def test_get_owasp_top_10_cwe(self):
        owasp_top_10 = experiment_1_generate_report.get_owasp_top_10_cwe()
        for key, value in owasp_top_10.items():
            if "CWE-213" in value:
                owasp_cwe_category = key
        self.assertEqual(owasp_cwe_category, "A04 Insecure Design")

    @patch(
        "main.python3.experiment_1_generate_report.get_cve_information_from_nvd",
        side_effect=mocked_response,
    )
    def test_get_cve_information_from_nvd(self, mock_response):
        with open(NIST_CVE_ID_RESPONSE, "r") as f:
            expected_cve_information = JSON.load(f)
        nist_cve_response = (
            experiment_1_generate_report.get_cve_information_from_nvd(
                NVD_API_KEY, NIST_CVE_ID
            )
        )
        self.assertEqual(
            JSON.loads(nist_cve_response.text), expected_cve_information
        )

    def test_get_cve_id_year(self):
        cve_year = experiment_1_generate_report.get_cve_id_year(NIST_CVE_ID)
        self.assertEqual(cve_year, 2019)

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
            [
                "--nvd-api-key",
                NVD_API_KEY,
                "--product-name",
                DEFAULT_PRODUCT_NAME,
            ]
        )
        result = experiment_1_generate_report.main(args)
        self.assertEqual(result, None)

    @classmethod
    def tearDownClass(cls):
        if os.path.isfile(DEFAULT_CSV_REPORT_FILENAME):
            os.remove(DEFAULT_CSV_REPORT_FILENAME)


if __name__ == "__main__":
    unittest.main()
