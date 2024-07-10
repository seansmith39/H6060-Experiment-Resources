#!/usr/bin/env python3

import os
import sys
import logging
import unittest
from argparse import Namespace
from unittest.mock import patch
from main.python3 import sbom_open_source_insights_report


TEST_DIRECTORY_RESOURCES = (
    os.path.dirname(os.path.realpath(__file__)) + "/resources/"
)

CYCLONEDX_SBOM_JAVA_FILENAME = (
    TEST_DIRECTORY_RESOURCES + "java/cyclonedx_sbom_report.json"
)
CYCLONEDX_SBOM_JAVASCRIPT_FILENAME = (
    TEST_DIRECTORY_RESOURCES + "javascript/cyclonedx_sbom_report.json"
)
CYCLONEDX_SBOM_PYTHON_FILENAME = (
    TEST_DIRECTORY_RESOURCES + "python/cyclonedx_sbom_report.json"
)

CSV_JAVA_RESULT_FILENAME = "sbom_open_source_insights_java_report.csv"
CSV_JAVASCRIPT_RESULT_FILENAME = (
    "sbom_open_source_insights_javascript_report.csv"
)
CSV_PYTHON_RESULT_FILENAME = "sbom_open_source_insights_python_report.csv"


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

    def __mock_args(
        self, programming_language: str, cyclonedx_sbom_filename: str
    ) -> Namespace:
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

    def test_parse_python_cyclonedx_sbom_report(self):
        csv_data = sbom_open_source_insights_report.parse_python_cyclonedx_sbom_report(
            CYCLONEDX_SBOM_PYTHON_FILENAME
        )
        self.assertTrue(len(csv_data) > 0)
        self.assertEqual(csv_data[0][0], "CycloneDX")
        self.assertEqual(csv_data[0][1], "1.6")
        self.assertEqual(csv_data[0][2], "Jinja2")
        self.assertEqual(csv_data[0][3], "3.1.4")
        self.assertEqual(csv_data[0][4], "library")
        self.assertEqual(csv_data[0][5], "https://pypi.org/simple/Jinja2/")

    def test_invalid_programming_language(self):
        args = self.__mock_args("invalid", CYCLONEDX_SBOM_PYTHON_FILENAME)
        with self.assertRaises(SystemExit) as cm:
            sbom_open_source_insights_report.main(args)
        self.assertEqual(cm.exception.code, 1)

    def test_main(self):
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

    @classmethod
    def tearDownClass(cls):
        sys.stdout = sys.__stdout__
        if os.path.isfile(CSV_JAVA_RESULT_FILENAME):
            os.remove(CSV_JAVA_RESULT_FILENAME)
        if os.path.isfile(CSV_JAVASCRIPT_RESULT_FILENAME):
            os.remove(CSV_JAVASCRIPT_RESULT_FILENAME)
        if os.path.isfile(CSV_PYTHON_RESULT_FILENAME):
            os.remove(CSV_PYTHON_RESULT_FILENAME)


if __name__ == "__main__":
    unittest.main()
