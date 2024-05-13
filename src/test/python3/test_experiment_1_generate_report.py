#!/usr/bin/env python3

import os
import re
import sys
import logging
import unittest
import json as JSON
from argparse import Namespace
from unittest.mock import patch
from main.python3 import experiment_1_generate_report


TEST_DIRECTORY_RESOURCES = (
    os.path.dirname(os.path.realpath(__file__)) + "/resources/"
)
NIST_CVE_ID_RESPONSE = TEST_DIRECTORY_RESOURCES + "nist-cve-information.json"
OPENCVE_CWE_RESPONSE = TEST_DIRECTORY_RESOURCES + "opencve-cwe.json"
HORUSEC_JSON_REPORT = TEST_DIRECTORY_RESOURCES + "horusec-report.json"

DEFAULT_PRODUCT_NAME = "horusec"
DEFAULT_CSV_REPORT_FILENAME = (
    f"experiment_1_{DEFAULT_PRODUCT_NAME.lower()}_results.csv"
)
NVD_API_KEY = "11111111-2222-3333-4444-555555555555"
OPENCVE_USERNAME = "username"
OPENCVE_PASSWORD = "password"
NIST_CVE_ID = "CVE-2019-14540"
HORUSEC_CWE_ID = "CWE-798"


def mocked_response(*args, **kwargs):
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

    if NIST_CVE_ID in args[1]:
        return MockResponse(NIST_CVE_ID_RESPONSE, 200)
    elif HORUSEC_CWE_ID in args[2]:
        return MockResponse(OPENCVE_CWE_RESPONSE, 200)
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

    @classmethod
    def setUpClass(cls):
        experiment_1_generate_report.log = logging.getLogger()
        experiment_1_generate_report.log.setLevel(logging.INFO)
        with open(os.devnull, "w") as f:
            sys.stdout = f

    def __mock_args(
        nvd_api_key: str, product_name: str, input_report_filename: str
    ) -> Namespace:
        """Mock arguments in argparse.Namespace type

        :parameter
            nvd_api_key:str -- NVD API Key to be mocked in the arguments
            product_name:str -- Name of the product to be mocked in the arguments
            input_report_filename:str -- Name of the security tool report to parse data from

        :return
            argparse.Namespace -- Mocked arguments
        """
        return Namespace(
            nvd_api_key=nvd_api_key,
            product_name=product_name,
            input_report_filename=input_report_filename,
        )

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

    @patch(
        "main.python3.experiment_1_generate_report.get_opencve_cwe_details",
        side_effect=mocked_response,
    )
    def test_get_opencve_cwe_details(self, mock_response):
        with open(OPENCVE_CWE_RESPONSE, "r") as f:
            expected_opencve_information = JSON.load(f)
        response = experiment_1_generate_report.get_opencve_cwe_details(
            OPENCVE_USERNAME, OPENCVE_PASSWORD, HORUSEC_CWE_ID
        )
        self.assertEqual(
            response.json()["name"], expected_opencve_information["name"]
        )
        self.assertEqual(
            response.json()["description"],
            expected_opencve_information["description"],
        )

    def test_get_cve_id_year(self):
        cve_year = experiment_1_generate_report.get_cve_id_year(NIST_CVE_ID)
        self.assertEqual(cve_year, 2019)
        cve_year = experiment_1_generate_report.get_cve_id_year("TEST")
        self.assertEqual(cve_year, None)

    def test_get_cwe_pattern(self):
        cwe_pattern = experiment_1_generate_report.get_cwe_pattern()
        cwe_id = "CWE-502"
        match = re.search(cwe_pattern, cwe_id)
        self.assertEqual(match.group(0), cwe_id)

    @patch(
        "main.python3.experiment_1_generate_report.get_opencve_cwe_details",
        side_effect=mocked_response,
    )
    def test_parse_horusec_data(self, mock_response):
        csv_rows = experiment_1_generate_report.parse_horusec_data(
            OPENCVE_USERNAME, OPENCVE_PASSWORD, HORUSEC_JSON_REPORT
        )
        self.assertTrue(len(csv_rows) > 0)
        self.assertEqual(csv_rows[0][0], "SAST")
        self.assertEqual(csv_rows[0][1], "HorusecEngine")
        self.assertEqual(csv_rows[0][2], "Syntax-based")
        self.assertEqual(csv_rows[0][3], "N/A")
        self.assertEqual(csv_rows[0][4], HORUSEC_CWE_ID)
        self.assertEqual(csv_rows[0][5], "Use of Hard-coded Credentials")
        self.assertEqual(
            csv_rows[0][6],
            "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
        )
        self.assertEqual(csv_rows[0][7], "N/A")
        self.assertEqual(csv_rows[0][8], "CRITICAL")
        self.assertEqual(csv_rows[0][9], "MEDIUM")
        self.assertEqual(
            csv_rows[0][10], "A07 Identification and Authentication Failures"
        )
        self.assertEqual(csv_rows[0][11], "18")
        self.assertEqual(csv_rows[0][12], "N/A")
        self.assertEqual(csv_rows[0][13], "N/A")
        self.assertEqual(csv_rows[0][14], "HS-LEAKS-26")
        self.assertEqual(csv_rows[0][15], "Leaks")

    def test_write_csv_report(self):
        product_data = [
            [
                "SCA",
                "Eclipse Steady Scan",
                "Code-centric",
                NIST_CVE_ID,
                "CWE-502",
                "9.8",
                "CRITICAL",
                "MEDIUM",
                "A08 Software and Data Integrity Failures",
                "15",
                "Transitive",
                "com.fasterxml.jackson.core:jackson-databind:2.10.3",
                "HS-LEAKS-26",
                "LEAKS",
            ]
        ]
        experiment_1_generate_report.write_csv_report(
            DEFAULT_PRODUCT_NAME, product_data
        )
        self.assertTrue(os.path.isfile(DEFAULT_CSV_REPORT_FILENAME))

    @patch(
        "main.python3.experiment_1_generate_report.get_opencve_cwe_details",
        side_effect=mocked_response,
    )
    def test_main(self, mock_response):
        args = experiment_1_generate_report.get_args(
            [
                "--nvd-api-key",
                NVD_API_KEY,
                "--opencve-username",
                OPENCVE_USERNAME,
                "--opencve-password",
                OPENCVE_PASSWORD,
                "--product-name",
                DEFAULT_PRODUCT_NAME,
                "--input-report-filename",
                HORUSEC_JSON_REPORT,
            ]
        )
        result = experiment_1_generate_report.main(args)
        self.assertEqual(result, None)

    @classmethod
    def tearDownClass(cls):
        sys.stdout = sys.__stdout__
        if os.path.isfile(DEFAULT_CSV_REPORT_FILENAME):
            os.remove(DEFAULT_CSV_REPORT_FILENAME)


if __name__ == "__main__":
    unittest.main()
