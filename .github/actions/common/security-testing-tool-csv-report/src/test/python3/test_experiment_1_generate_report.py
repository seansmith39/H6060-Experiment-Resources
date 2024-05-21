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
RESPONSE_NVDCVE = TEST_DIRECTORY_RESOURCES + "response-nvdcve.json"
RESPONSE_OPENCVE = TEST_DIRECTORY_RESOURCES + "response-opencve.json"
REPORT_HORUSEC = TEST_DIRECTORY_RESOURCES + "report-sast-horusec.json"
REPORT_INSIDER = TEST_DIRECTORY_RESOURCES + "report-sast-insider.json"
REPORT_OWASP_DEPENDENCY_CHECK = (
    TEST_DIRECTORY_RESOURCES + "report-sca-owasp-dependency-check.json"
)

DEFAULT_CSV_REPORT_FILENAME = "experiment_1_results.csv"
NVD_API_KEY = "11111111-2222-3333-4444-555555555555"
OPENCVE_USERNAME = "username"
OPENCVE_PASSWORD = "password"
CVE_ID_NVD = "CVE-2016-2510"
CWE_ID_HORUSEC = "CWE-798"
CWE_ID_INSIDER = "CWE-330"
CWE_ID_OWASP_DEPENDENCY_CHECK = "CWE-19"


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

    if (
        CWE_ID_HORUSEC in args[2]
        or CWE_ID_INSIDER in args[2]
        or CWE_ID_OWASP_DEPENDENCY_CHECK in args[2]
    ):
        return MockResponse(RESPONSE_OPENCVE, 200)
    else:
        return None


def mocked_nvd_response(*args, **kwargs):
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

    if CVE_ID_NVD in args[1]:
        return MockResponse(RESPONSE_NVDCVE, 200)
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
        nvd_api_key: str,
        product_name: str,
        horusec_report_filename: str,
        insider_report_filename: str,
    ) -> Namespace:
        """Mock arguments in argparse.Namespace type

        :parameter
            nvd_api_key:str -- NVD API Key to be mocked in the arguments
            product_name:str -- Name of the product to be mocked in the arguments
            horusec_report_filename:str -- Name of the Horusec report to parse data from
            insider_report_filename:str -- Name of the Insider report to parse data from

        :return
            argparse.Namespace -- Mocked arguments
        """
        return Namespace(
            nvd_api_key=nvd_api_key,
            product_name=product_name,
            horusec_report_filename=horusec_report_filename,
            insider_report_filename=insider_report_filename,
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
        side_effect=mocked_nvd_response,
    )
    def test_get_cve_information_from_nvd(self, mock_response):
        with open(RESPONSE_NVDCVE, "r") as f:
            expected_cve_information = JSON.load(f)
        nist_cve_response = (
            experiment_1_generate_report.get_cve_information_from_nvd(
                NVD_API_KEY, CVE_ID_NVD
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
        with open(RESPONSE_OPENCVE, "r") as f:
            expected_opencve_information = JSON.load(f)
        response = experiment_1_generate_report.get_opencve_cwe_details(
            OPENCVE_USERNAME, OPENCVE_PASSWORD, CWE_ID_HORUSEC
        )
        self.assertEqual(
            response.json()["name"], expected_opencve_information["name"]
        )
        self.assertEqual(
            response.json()["description"],
            expected_opencve_information["description"],
        )

    def test_get_cve_id_year(self):
        cve_year = experiment_1_generate_report.get_cve_id_year(CVE_ID_NVD)
        self.assertEqual(cve_year, 2016)
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
            OPENCVE_USERNAME, OPENCVE_PASSWORD, REPORT_HORUSEC
        )
        self.assertTrue(len(csv_rows) > 0)
        self.assertEqual(csv_rows[0][0], "SAST")
        self.assertEqual(csv_rows[0][1], "HorusecEngine")
        self.assertEqual(csv_rows[0][2], "Syntax-based")
        self.assertEqual(csv_rows[0][3], "CRITICAL")
        self.assertEqual(csv_rows[0][4], "MEDIUM")
        self.assertEqual(csv_rows[0][31], CWE_ID_HORUSEC)
        self.assertEqual(csv_rows[0][32], "Use of Hard-coded Credentials")
        self.assertEqual(
            csv_rows[0][33],
            "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
        )
        self.assertEqual(
            csv_rows[0][34], "A07 Identification and Authentication Failures"
        )
        self.assertEqual(csv_rows[0][35], "18")
        self.assertEqual(csv_rows[0][38], "HS-LEAKS-26")
        self.assertEqual(csv_rows[0][39], "Leaks")
        self.assertEqual(
            csv_rows[0][40],
            "nio-impl/src/test/java/org/xnio/nio/test/NioSslTcpChannelTestCase.java",
        )

    @patch(
        "main.python3.experiment_1_generate_report.get_opencve_cwe_details",
        side_effect=mocked_response,
    )
    def test_parse_insider_data(self, mock_response):
        csv_rows = experiment_1_generate_report.parse_insider_data(
            OPENCVE_USERNAME, OPENCVE_PASSWORD, REPORT_INSIDER
        )
        self.assertTrue(len(csv_rows) > 0)
        self.assertEqual(csv_rows[0][0], "SAST")
        self.assertEqual(csv_rows[0][1], "Insider")
        self.assertEqual(csv_rows[0][2], "Syntax-based")
        self.assertEqual(csv_rows[0][31], CWE_ID_INSIDER)
        self.assertEqual(csv_rows[0][32], "Use of Hard-coded Credentials")
        self.assertEqual(
            csv_rows[0][33],
            "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
        )
        self.assertEqual(csv_rows[0][34], "A02 Cryptographic Failures")
        self.assertEqual(
            csv_rows[0][40],
            "api/src/main/java/org/xnio/IoUtils.java",
        )

    @patch(
        "main.python3.experiment_1_generate_report.get_opencve_cwe_details",
        side_effect=mocked_response,
    )
    @patch(
        "main.python3.experiment_1_generate_report.get_cve_information_from_nvd",
        side_effect=mocked_nvd_response,
    )
    def test_parse_owasp_dependency_check_data(
        self, mock_response_opencve, mock_response_nvd
    ):
        csv_rows = (
            experiment_1_generate_report.parse_owasp_dependency_check_data(
                NVD_API_KEY,
                OPENCVE_USERNAME,
                OPENCVE_PASSWORD,
                REPORT_OWASP_DEPENDENCY_CHECK,
            )
        )
        self.assertTrue(len(csv_rows) > 0)
        self.assertEqual(csv_rows[0][0], "SCA")
        self.assertEqual(csv_rows[0][1], "OWASP Dependency Check")
        self.assertEqual(csv_rows[0][2], "Metadata-based")
        self.assertEqual(csv_rows[0][3], "HIGH")
        self.assertEqual(csv_rows[0][4], "HIGHEST")
        self.assertEqual(csv_rows[0][5], "CVE-2016-2510")
        self.assertEqual(csv_rows[0][6], "NVD")
        self.assertEqual(csv_rows[0][7], "2016-04-07T20:59:05.567")
        self.assertEqual(csv_rows[0][8], "2020-10-20T22:15:18.483")
        self.assertEqual(csv_rows[0][9], "Modified")
        self.assertEqual(
            csv_rows[0][10],
            "BeanShell (bsh) before 2.0b6, when included on the classpath by an application that uses Java serialization or XStream, allows remote attackers to execute arbitrary code via crafted serialized data, related to XThis.Handler.",
        )
        self.assertEqual(csv_rows[0][11], "3.1")
        self.assertEqual(csv_rows[0][13], 8.1)
        self.assertEqual(csv_rows[0][14], "UNCHANGED")
        self.assertEqual(csv_rows[0][15], "2.2")
        self.assertEqual(csv_rows[0][16], "5.9")
        self.assertEqual(csv_rows[0][17], "NETWORK")
        self.assertEqual(csv_rows[0][18], "HIGH")
        self.assertEqual(csv_rows[0][19], "NONE")
        self.assertEqual(csv_rows[0][20], "NONE")
        self.assertEqual(csv_rows[0][21], "HIGH")
        self.assertEqual(csv_rows[0][22], "HIGH")
        self.assertEqual(csv_rows[0][23], "HIGH")
        self.assertEqual(csv_rows[0][31], CWE_ID_OWASP_DEPENDENCY_CHECK)
        self.assertEqual(csv_rows[0][32], "Use of Hard-coded Credentials")
        self.assertEqual(
            csv_rows[0][33],
            "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
        )
        self.assertEqual(
            csv_rows[0][37], "cpe:2.3:a:beanshell:beanshell:2.0:b4:*:*:*:*:*:*"
        )

    @patch(
        "main.python3.experiment_1_generate_report.get_opencve_cwe_details",
        side_effect=mocked_response,
    )
    @patch(
        "main.python3.experiment_1_generate_report.get_cve_information_from_nvd",
        side_effect=mocked_nvd_response,
    )
    def test_main(self, mock_response_opencve, mock_response_nvd):
        args = experiment_1_generate_report.get_args(
            [
                "--nvd-api-key",
                NVD_API_KEY,
                "--opencve-username",
                OPENCVE_USERNAME,
                "--opencve-password",
                OPENCVE_PASSWORD,
                "--horusec-report-filename",
                REPORT_HORUSEC,
                "--insider-report-filename",
                REPORT_INSIDER,
                "--owasp-dependency-check-filename",
                REPORT_OWASP_DEPENDENCY_CHECK,
            ]
        )
        result = experiment_1_generate_report.main(args)
        self.assertEqual(result, None)

    @classmethod
    def tearDownClass(cls):
        sys.stdout = sys.__stdout__
        # TODO: Uncomment when finished development
        # if os.path.isfile(DEFAULT_CSV_REPORT_FILENAME):
        #     os.remove(DEFAULT_CSV_REPORT_FILENAME)


if __name__ == "__main__":
    unittest.main()
