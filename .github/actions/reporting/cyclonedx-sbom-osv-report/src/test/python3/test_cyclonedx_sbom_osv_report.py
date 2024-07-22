#!/usr/bin/env python3

import os
import sys
import logging
import unittest
import json as JSON
from itertools import repeat
from argparse import Namespace
from unittest.mock import patch
from main.python3 import cyclonedx_sbom_osv_report


TEST_DIRECTORY_RESOURCES = os.path.dirname(os.path.realpath(__file__)) + "/resources/"

CSV_JAVA_RESULT_FILENAME = "cyclonedx_sbom_osv_report_java.csv"
CSV_JAVASCRIPT_RESULT_FILENAME = "cyclonedx_sbom_osv_report_javascript.csv"
CSV_PYTHON_RESULT_FILENAME = "cyclonedx_sbom_osv_report_python.csv"

CSV_JAVA_RESULT_PATH = f"../../main/python3/{CSV_JAVA_RESULT_FILENAME}"
CSV_JAVASCRIPT_RESULT_PATH = f"../../main/python3/{CSV_JAVASCRIPT_RESULT_FILENAME}"
CSV_PYTHON_RESULT_PATH = f"../../main/python3/{CSV_PYTHON_RESULT_FILENAME}"

CYCLONEDX_SBOM_JAVA_FILENAME = TEST_DIRECTORY_RESOURCES + "sbom/java/cyclonedx_sbom_report.json"
CYCLONEDX_SBOM_JAVASCRIPT_FILENAME = TEST_DIRECTORY_RESOURCES + "sbom/javascript/cyclonedx_sbom_report.json"
CYCLONEDX_SBOM_PYTHON_FILENAME = TEST_DIRECTORY_RESOURCES + "sbom/python/cyclonedx_sbom_report.json"

RESPONSE_OSV_API_NO_VULNERABILITIES = TEST_DIRECTORY_RESOURCES + "osv/other/osv_vulnerability_no_response.json"
RESPONSE_OSV_API_EMPTY_VULNERABILITIES = TEST_DIRECTORY_RESOURCES + "osv/other/osv_vulnerability_empty_response.json"
RESPONSE_OSV_API_JAVA = TEST_DIRECTORY_RESOURCES + "osv/java/osv_vulnerability_response.json"
RESPONSE_OSV_API_JAVASCRIPT = TEST_DIRECTORY_RESOURCES + "osv/javascript/osv_vulnerability_response.json"
RESPONSE_OSV_API_PYTHON = TEST_DIRECTORY_RESOURCES + "osv//python/osv_vulnerability_response.json"


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
class TestCycloneDxSbomOsvReport(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestCycloneDxSbomOsvReport, self).__init__(*args, **kwargs)

    @classmethod
    def setUpClass(cls):
        cyclonedx_sbom_osv_report.log = logging.getLogger()
        cyclonedx_sbom_osv_report.log.setLevel(logging.INFO)
        with open(os.devnull, "w") as f:
            sys.stdout = f

    def __mock_args(
        self, programming_language: str, cyclonedx_sbom_filename: str, csv_report_filename: str
    ) -> Namespace:
        """Mock arguments in argparse.Namespace type

        :parameter
            programming_language:str -- Programming language of CycloneDX SBOM JSON report
            cyclonedx_sbom_filename:str -- Name of CycloneDX SBOM JSON report to parse
            csv_report_filename:str -- Name of CSV report to generate

        :return
            argparse.Namespace -- Mocked arguments
        """
        return Namespace(
            programming_language=programming_language,
            cyclonedx_sbom_filename=cyclonedx_sbom_filename,
            csv_report_filename=csv_report_filename,
        )

    @patch(
        "main.python3.cyclonedx_sbom_osv_report.send_post_request",
        side_effect=mocked_response,
    )
    def test_query_osv_api(self, mock_response):
        osv_data = cyclonedx_sbom_osv_report.query_osv_api([], "pkg:pypi/django@5.0", "5.0")
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
        "main.python3.cyclonedx_sbom_osv_report.send_post_request",
        side_effect=mocked_response,
    )
    def test_query_osv_api_no_vulnerabilities(self, mock_response):
        data = []
        data.extend(repeat("N/A", 12))
        osv_data = cyclonedx_sbom_osv_report.query_osv_api([], "no_vulns", "1.0")
        self.assertEqual(osv_data, [data])

    @patch(
        "main.python3.cyclonedx_sbom_osv_report.send_post_request",
        side_effect=mocked_response,
    )
    def test_query_osv_api_no_records(self, mock_response):
        data = []
        data.extend(repeat("N/A", 12))
        osv_data = cyclonedx_sbom_osv_report.query_osv_api([], "no_record", "1.0")
        self.assertEqual(osv_data, [data])

    def test_query_osv_api_no_response(self):
        data = []
        data.extend(repeat("N/A", 12))
        osv_data = cyclonedx_sbom_osv_report.query_osv_api([], "no_response", "1.0")
        self.assertEqual(osv_data, [data])

    def test_invalid_programming_language(self):
        args = self.__mock_args("invalid", CYCLONEDX_SBOM_PYTHON_FILENAME, CSV_JAVA_RESULT_FILENAME)
        with self.assertRaises(SystemExit) as cm:
            cyclonedx_sbom_osv_report.main(args)
        self.assertEqual(cm.exception.code, 1)

    def test_get_json_value_missing_key(self):
        with open(RESPONSE_OSV_API_JAVA, "r") as f:
            osv_data = JSON.load(f)
        result = cyclonedx_sbom_osv_report.get_json_value(osv_data["vulns"][0], "published", "missing_key")
        self.assertEqual(result, "N/A")

    def test_get_vulnerability_cve(self):
        with open(RESPONSE_OSV_API_JAVA, "r") as f:
            osv_data = JSON.load(f)
        result = cyclonedx_sbom_osv_report.get_vulnerability_cve(osv_data["vulns"][0])
        self.assertEqual(result, "CVE-2024-36401,CVE-2024-36404")

    def test_get_vulnerability_cve_not_found(self):
        with open(RESPONSE_OSV_API_PYTHON, "r") as f:
            osv_data = JSON.load(f)
        result = cyclonedx_sbom_osv_report.get_vulnerability_cve(osv_data["vulns"][1])
        self.assertEqual(result, "N/A")

    def test_get_vulnerability_affected_version_not_found(self):
        with open(RESPONSE_OSV_API_PYTHON, "r") as f:
            osv_data = JSON.load(f)
        result = cyclonedx_sbom_osv_report.get_vulnerability_affected_version(osv_data["vulns"][1], "1.0")
        self.assertEqual(result, ("N/A", "N/A"))

    def test_get_vulnerability_affected_not_found(self):
        with open(RESPONSE_OSV_API_EMPTY_VULNERABILITIES, "r") as f:
            osv_data = JSON.load(f)
        result = cyclonedx_sbom_osv_report.get_vulnerability_affected_version(osv_data, "1.0")
        self.assertEqual(result, ("N/A", "N/A"))

    @patch(
        "main.python3.cyclonedx_sbom_osv_report.send_post_request",
        side_effect=mocked_response,
    )
    def test_java_main(self, mock_response):
        args = cyclonedx_sbom_osv_report.get_args(
            [
                "--programming-language",
                "java",
                "--cyclonedx-sbom-filename",
                CYCLONEDX_SBOM_JAVA_FILENAME,
                "--csv-report-filename",
                CSV_JAVA_RESULT_FILENAME,
            ]
        )
        result = cyclonedx_sbom_osv_report.main(args)
        self.assertEqual(result, None)

    @patch(
        "main.python3.cyclonedx_sbom_osv_report.send_post_request",
        side_effect=mocked_response,
    )
    def test_python_main(self, mock_response):
        args = cyclonedx_sbom_osv_report.get_args(
            [
                "--programming-language",
                "python",
                "--cyclonedx-sbom-filename",
                CYCLONEDX_SBOM_PYTHON_FILENAME,
                "--csv-report-filename",
                CSV_PYTHON_RESULT_FILENAME,
            ]
        )
        result = cyclonedx_sbom_osv_report.main(args)
        self.assertEqual(result, None)

    @patch(
        "main.python3.cyclonedx_sbom_osv_report.send_post_request",
        side_effect=mocked_response,
    )
    def test_javascript_main(self, mock_response):
        args = cyclonedx_sbom_osv_report.get_args(
            [
                "--programming-language",
                "javascript",
                "--cyclonedx-sbom-filename",
                CYCLONEDX_SBOM_JAVASCRIPT_FILENAME,
                "--csv-report-filename",
                CSV_JAVASCRIPT_RESULT_FILENAME,
            ]
        )
        result = cyclonedx_sbom_osv_report.main(args)
        self.assertEqual(result, None)

    @classmethod
    def tearDownClass(cls):
        sys.stdout = sys.__stdout__
        if os.path.isfile(CSV_JAVA_RESULT_PATH):
            os.remove(CSV_JAVA_RESULT_PATH)
        if os.path.isfile(CSV_JAVASCRIPT_RESULT_PATH):
            os.remove(CSV_JAVASCRIPT_RESULT_PATH)
        if os.path.isfile(CSV_PYTHON_RESULT_PATH):
            os.remove(CSV_PYTHON_RESULT_PATH)
        if os.path.isfile(RESPONSE_OSV_API_NO_VULNERABILITIES):
            os.remove(RESPONSE_OSV_API_NO_VULNERABILITIES)


if __name__ == "__main__":
    unittest.main()