#!/usr/bin/env python3

import os
import sys
import json as JSON
import logging
import unittest
from argparse import Namespace
from unittest.mock import patch
from main.python3 import sbom_open_source_insights_report


TEST_DIRECTORY_RESOURCES = os.path.dirname(os.path.realpath(__file__)) + "/resources/"

CSV_JAVA_RESULT_FILENAME = "sbom_open_source_insights_java_report.csv"
CSV_JAVASCRIPT_RESULT_FILENAME = "sbom_open_source_insights_javascript_report.csv"
CSV_PYTHON_RESULT_FILENAME = "sbom_open_source_insights_python_report.csv"

CYCLONEDX_SBOM_JAVA_FILENAME = TEST_DIRECTORY_RESOURCES + "sbom/java/cyclonedx_sbom_report.json"
CYCLONEDX_SBOM_JAVA_MISCONFIGURED_FILENAME = (
    TEST_DIRECTORY_RESOURCES + "sbom/java/cyclonedx_sbom_misconfigured_report.json"
)
CYCLONEDX_SBOM_PYTHON_MISCONFIGURED_FILENAME = (
    TEST_DIRECTORY_RESOURCES + "sbom/python/cyclonedx_sbom_misconfigured_report.json"
)
CYCLONEDX_SBOM_JAVASCRIPT_MISCONFIGURED_FILENAME = (
    TEST_DIRECTORY_RESOURCES + "sbom/javascript/cyclonedx_sbom_misconfigured_report.json"
)
CYCLONEDX_SBOM_JAVASCRIPT_FILENAME = TEST_DIRECTORY_RESOURCES + "sbom/javascript/cyclonedx_sbom_report.json"
CYCLONEDX_SBOM_PYTHON_FILENAME = TEST_DIRECTORY_RESOURCES + "sbom/python/cyclonedx_sbom_report.json"

RESPONSE_OSV_API_NO_VULNERABILITIES = TEST_DIRECTORY_RESOURCES + "osv/osv_vulnerability_no_response.json"
RESPONSE_OSV_API_EMPTY_VULNERABILITIES = TEST_DIRECTORY_RESOURCES + "osv/osv_vulnerability_empty_response.json"
RESPONSE_OSV_API_JAVA = TEST_DIRECTORY_RESOURCES + "osv/osv_vulnerability_java_response.json"
RESPONSE_OSV_API_PYTHON = TEST_DIRECTORY_RESOURCES + "osv/osv_vulnerability_python_response.json"
RESPONSE_OSV_API_JAVASCRIPT = TEST_DIRECTORY_RESOURCES + "osv/osv_vulnerability_javascript_response.json"


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

    if "pkg:maven" in str(args[1]):
        return MockResponse(RESPONSE_OSV_API_JAVA, 200)
    elif "pkg:pypi" in str(args[1]):
        return MockResponse(RESPONSE_OSV_API_PYTHON, 200)
    elif "pkg:npm" in str(args[1]):
        return MockResponse(RESPONSE_OSV_API_JAVASCRIPT, 200)
    elif "no_vulns" in str(args[1]):
        return MockResponse(RESPONSE_OSV_API_EMPTY_VULNERABILITIES, 200)
    elif "no_record" in str(args[1]):
        temp_file = open(RESPONSE_OSV_API_NO_VULNERABILITIES, "w")
        temp_file.write("{}")
        temp_file.close()
        return MockResponse(RESPONSE_OSV_API_NO_VULNERABILITIES, 200)
    else:
        return None


class DevNull:
    def __init__(self):
        pass

    def write(self, s):
        pass


@patch("sys.stdout", new=DevNull())
@patch("sys.stderr", new=DevNull())
class TestSbomOpenSourceInsightsReport(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestSbomOpenSourceInsightsReport, self).__init__(*args, **kwargs)

    @classmethod
    def setUpClass(cls):
        sbom_open_source_insights_report.log = logging.getLogger()
        sbom_open_source_insights_report.log.setLevel(logging.INFO)
        with open(os.devnull, "w") as f:
            sys.stdout = f

    def __mock_args(self, programming_language: str, cyclonedx_sbom_filename: str) -> Namespace:
        """Mock arguments in argparse.Namespace type

        :parameter
            programming_language:str -- Programming language of CycloneDX SBOM JSON report
            cyclonedx_sbom_filename:str -- Name of CycloneDX SBOM JSON report to parse

        :return
            argparse.Namespace -- Mocked arguments
        """
        return Namespace(
            programming_language=programming_language,
            cyclonedx_sbom_filename=cyclonedx_sbom_filename,
        )

    @patch(
        "main.python3.sbom_open_source_insights_report.send_post_request",
        side_effect=mocked_response,
    )
    def test_query_osv_api(self, mock_response):
        osv_data = sbom_open_source_insights_report.query_osv_api([], "pkg:pypi/django@5.0", "5.0")
        self.assertTrue(len(osv_data) > 0)
        self.assertEqual(osv_data[0][0], "GHSA-9jmf-237g-qf46")
        self.assertEqual(osv_data[0][1], "Django Path Traversal vulnerability")
        self.assertEqual(osv_data[0][2], "CVE-2024-39330")
        self.assertEqual(osv_data[0][3], "HIGH")
        self.assertEqual(osv_data[0][4], "CWE-22")
        self.assertEqual(osv_data[0][5], "2024-07-10T05:15:12Z")
        self.assertEqual(osv_data[0][6], "https://nvd.nist.gov/vuln/detail/CVE-2024-39330")
        self.assertEqual(osv_data[0][7], "5.0")
        self.assertEqual(osv_data[0][8], "5.0.7")
        self.assertEqual(osv_data[0][9], "N/A")
        self.assertEqual(osv_data[0][10], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        self.assertEqual(osv_data[0][11], "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")

    @patch(
        "main.python3.sbom_open_source_insights_report.send_post_request",
        side_effect=mocked_response,
    )
    def test_query_osv_api_no_vulnerabilities(self, mock_response):
        osv_data = sbom_open_source_insights_report.query_osv_api([], "no_vulns", "1.0")
        self.assertEqual(osv_data, [None])

    @patch(
        "main.python3.sbom_open_source_insights_report.send_post_request",
        side_effect=mocked_response,
    )
    def test_query_osv_api_no_records(self, mock_response):
        osv_data = sbom_open_source_insights_report.query_osv_api([], "no_record", "1.0")
        self.assertEqual(osv_data, [None])

    def test_query_osv_api_no_response(self):
        osv_data = sbom_open_source_insights_report.query_osv_api([], "no_response", "1.0")
        self.assertEqual(osv_data, [None])

    def test_invalid_programming_language(self):
        args = self.__mock_args("invalid", CYCLONEDX_SBOM_PYTHON_FILENAME)
        with self.assertRaises(SystemExit) as cm:
            sbom_open_source_insights_report.main(args)
        self.assertEqual(cm.exception.code, 1)

    def test_get_csv_column_headers_missing_programming_language(self):
        result = sbom_open_source_insights_report.get_csv_column_headers("missing_language")
        default_headers = [
            "OSV Vulnerability ID",
            "OSV Vulnerability Summary",
            "OSV Vulnerability CVE",
            "OSV Vulnerability Severity",
            "OSV Vulnerability CWE IDs",
            "OSV Vulnerability NVD Published Date",
            "OSV Vulnerability Advisory URL",
            "OSV Vulnerability Introduced",
            "OSV Vulnerability Fixed",
            "OSV Vulnerability CVSS V2",
            "OSV Vulnerability CVSS V3",
            "OSV Vulnerability CVSS V4",
        ]

        self.assertEqual(result, "," + ",".join(default_headers) + "\n")

    def test_get_json_value_missing_key(self):
        with open(RESPONSE_OSV_API_JAVA, "r") as f:
            osv_data = JSON.load(f)
        result = sbom_open_source_insights_report.get_json_value(osv_data["vulns"][0], "published", "missing_key")
        self.assertEqual(result, "N/A")

    def test_get_vulnerability_cve(self):
        with open(RESPONSE_OSV_API_JAVA, "r") as f:
            osv_data = JSON.load(f)
        result = sbom_open_source_insights_report.get_vulnerability_cve(osv_data["vulns"][0])
        self.assertEqual(result, "CVE-2024-36401,CVE-2024-36404")

    def test_get_vulnerability_cve_not_found(self):
        with open(RESPONSE_OSV_API_PYTHON, "r") as f:
            osv_data = JSON.load(f)
        result = sbom_open_source_insights_report.get_vulnerability_cve(osv_data["vulns"][1])
        self.assertEqual(result, "N/A")

    def test_get_vulnerability_affected_version_not_found(self):
        with open(RESPONSE_OSV_API_PYTHON, "r") as f:
            osv_data = JSON.load(f)
        result = sbom_open_source_insights_report.get_vulnerability_affected_version(osv_data["vulns"][1], "1.0")
        self.assertEqual(result, ("N/A", "N/A"))

    def test_java_misconfigured_main(self):
        args = sbom_open_source_insights_report.get_args(
            [
                "--programming-language",
                "java",
                "--cyclonedx-sbom-filename",
                CYCLONEDX_SBOM_JAVA_MISCONFIGURED_FILENAME,
            ]
        )
        with self.assertRaises(SystemExit) as cm:
            sbom_open_source_insights_report.main(args)
        self.assertEqual(cm.exception.code, 1)

    def test_python_misconfigured_main(self):
        args = sbom_open_source_insights_report.get_args(
            [
                "--programming-language",
                "python",
                "--cyclonedx-sbom-filename",
                CYCLONEDX_SBOM_PYTHON_MISCONFIGURED_FILENAME,
            ]
        )
        with self.assertRaises(SystemExit) as cm:
            sbom_open_source_insights_report.main(args)
        self.assertEqual(cm.exception.code, 1)

    def test_javascript_misconfigured_main(self):
        args = sbom_open_source_insights_report.get_args(
            [
                "--programming-language",
                "javascript",
                "--cyclonedx-sbom-filename",
                CYCLONEDX_SBOM_JAVASCRIPT_MISCONFIGURED_FILENAME,
            ]
        )
        with self.assertRaises(SystemExit) as cm:
            sbom_open_source_insights_report.main(args)
        self.assertEqual(cm.exception.code, 1)

    @patch(
        "main.python3.sbom_open_source_insights_report.send_post_request",
        side_effect=mocked_response,
    )
    def test_java_main(self, mock_response):
        args = sbom_open_source_insights_report.get_args(
            [
                "--programming-language",
                "java",
                "--cyclonedx-sbom-filename",
                CYCLONEDX_SBOM_JAVA_FILENAME,
            ]
        )
        result = sbom_open_source_insights_report.main(args)
        self.assertEqual(result, None)

    @patch(
        "main.python3.sbom_open_source_insights_report.send_post_request",
        side_effect=mocked_response,
    )
    def test_python_main(self, mock_response):
        args = sbom_open_source_insights_report.get_args(
            [
                "--programming-language",
                "python",
                "--cyclonedx-sbom-filename",
                CYCLONEDX_SBOM_PYTHON_FILENAME,
            ]
        )
        result = sbom_open_source_insights_report.main(args)
        self.assertEqual(result, None)

    @patch(
        "main.python3.sbom_open_source_insights_report.send_post_request",
        side_effect=mocked_response,
    )
    def test_javascript_main(self, mock_response):
        args = sbom_open_source_insights_report.get_args(
            [
                "--programming-language",
                "javascript",
                "--cyclonedx-sbom-filename",
                CYCLONEDX_SBOM_JAVASCRIPT_FILENAME,
            ]
        )
        result = sbom_open_source_insights_report.main(args)
        self.assertEqual(result, None)

    @classmethod
    def tearDownClass(cls):
        sys.stdout = sys.__stdout__
        if os.path.isfile(CSV_JAVA_RESULT_FILENAME):
            os.remove(CSV_JAVA_RESULT_FILENAME)
        if os.path.isfile(CSV_JAVASCRIPT_RESULT_FILENAME):
            os.remove(CSV_JAVASCRIPT_RESULT_FILENAME)
        if os.path.isfile(CSV_PYTHON_RESULT_FILENAME):
            os.remove(CSV_PYTHON_RESULT_FILENAME)
        if os.path.isfile(RESPONSE_OSV_API_NO_VULNERABILITIES):
            os.remove(RESPONSE_OSV_API_NO_VULNERABILITIES)


if __name__ == "__main__":
    unittest.main()
