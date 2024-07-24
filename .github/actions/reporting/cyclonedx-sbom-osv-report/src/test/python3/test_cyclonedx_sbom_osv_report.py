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

# Report filenames
CYCLONEDX_SBOM_REPORT_JAVA = TEST_DIRECTORY_RESOURCES + "sbom/java/cyclonedx-sbom-report.json"
CYCLONEDX_SBOM_REPORT_JAVASCRIPT = TEST_DIRECTORY_RESOURCES + "sbom/javascript/cyclonedx-sbom-report.json"
CYCLONEDX_SBOM_REPORT_PYTHON = TEST_DIRECTORY_RESOURCES + "sbom/python/cyclonedx-sbom-report.json"

# CSV result filenames
CSV_JAVA_RESULT_FILENAME = "cyclonedx_sbom_osv_report_java.csv"
CSV_JAVASCRIPT_RESULT_FILENAME = "cyclonedx_sbom_osv_report_javascript.csv"
CSV_PYTHON_RESULT_FILENAME = "cyclonedx_sbom_osv_report_python.csv"

# CSV result paths
SOURCE_DIRECTORY = "../../main/python3"

# OSV API responses
OSV_RESPONSE_EMTPY = TEST_DIRECTORY_RESOURCES + "osv/other/osv-response-empty.json"
OSV_RESPONSE_NO_CVE = TEST_DIRECTORY_RESOURCES + "osv/other/osv-response-no-cve.json"
OSV_RESPONSE_JAVA = TEST_DIRECTORY_RESOURCES + "osv/java/osv-response.json"
OSV_RESPONSE_JAVASCRIPT = TEST_DIRECTORY_RESOURCES + "osv/javascript/osv-response.json"
OSV_RESPONSE_PYTHON = TEST_DIRECTORY_RESOURCES + "osv/python/osv-response.json"

# GitHub responses
GITHUB_RESPONSE_JAVA = TEST_DIRECTORY_RESOURCES + "github/java/github-response.json"
GITHUB_RESPONSE_JAVASCRIPT = TEST_DIRECTORY_RESOURCES + "github/javascript/github-response.json"
GITHUB_RESPONSE_PYTHON = TEST_DIRECTORY_RESOURCES + "github/python/github-response.json"

# Mocked required arguments
GITHUB_API_URL = "https://api.github.com"
GITHUB_API_TOKEN = "ghp_1234567890"
EXPERIMENT_ID = "1"
EXPERIMENT_PROGRAMMING_LANGUAGE = "java"

# Mocked GitHub arguments
GITHUB_PROJECT_NAME = "project-name"
GITHUB_BRANCH = "main"
GITHUB_COMMIT = "1234567890"
GITHUB_WORKFLOW_NAME = "workflow-name"
GITHUB_WORKFLOW_RUN_ID = "1234567890"
GITHUB_REPOSITORY_JAVA = "org/repository-java"
GITHUB_REPOSITORY_JAVASCRIPT = "org/repository-javascript"
GITHUB_REPOSITORY_PYTHON = "org/repository-python"
GITHUB_REPOSITORY_OTHER = "org/repository-other"
GITHUB_REPOSITORY_MISSING = "org/repository-missing"

REQUIRED_ARGUMENTS = [
    "--github-api-url",
    GITHUB_API_URL,
    "--github-api-token",
    GITHUB_API_TOKEN,
    "--experiment-id",
    EXPERIMENT_ID,
    "--experiment-github-project-name",
    GITHUB_PROJECT_NAME,
    "--experiment-github-branch",
    GITHUB_BRANCH,
    "--experiment-github-commit",
    GITHUB_COMMIT,
    "--experiment-github-workflow-name",
    GITHUB_WORKFLOW_NAME,
    "--experiment-github-workflow-run-id",
    GITHUB_WORKFLOW_RUN_ID,
    "--experiment-programming-language",
    EXPERIMENT_PROGRAMMING_LANGUAGE,
]


def mocked_osv_response(*args, **kwargs):
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
        return MockResponse(OSV_RESPONSE_JAVA, 200)
    elif "pkg:pypi" in str(args[1]):
        return MockResponse(OSV_RESPONSE_PYTHON, 200)
    elif "pkg:npm" in str(args[1]):
        return MockResponse(OSV_RESPONSE_JAVASCRIPT, 200)
    elif "no_cve" in str(args[1]):
        return MockResponse(OSV_RESPONSE_NO_CVE, 200)
    elif "no_record" in str(args[1]):
        return MockResponse("temp.json", 200)
    else:
        return None


def mocked_github_response(*args, **kwargs):
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

    if GITHUB_REPOSITORY_JAVASCRIPT in args[0]:
        return MockResponse(GITHUB_RESPONSE_JAVASCRIPT, 200)
    elif GITHUB_REPOSITORY_JAVA in args[0]:
        return MockResponse(GITHUB_RESPONSE_JAVA, 200)
    elif GITHUB_REPOSITORY_PYTHON in args[0] or GITHUB_REPOSITORY_OTHER in args[0]:
        return MockResponse(GITHUB_RESPONSE_PYTHON, 200)
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
        self,
        github_api_url: str,
        github_api_token: str,
        experiment_id: str,
        experiment_github_project_name: str,
        experiment_github_repository: str,
        experiment_github_branch: str,
        experiment_github_commit: str,
        experiment_github_workflow_name: str,
        experiment_github_workflow_run_id: str,
        experiment_programming_language: str,
        cyclonedx_sbom_filename: str,
        csv_report_filename: str,
    ) -> Namespace:
        """Mock arguments in argparse.Namespace type

        :parameter
            github_api_url:str -- GitHub API URL to be mocked in the arguments
            github_api_token:str -- GitHub API Token to be mocked in the arguments
            experiment_id:str -- Experiment ID to be mocked in the arguments
            experiment_github_project_name:str -- Experiment GitHub project name to be mocked in the arguments
            experiment_github_repository:str -- Experiment GitHub repository to be mocked in the arguments
            experiment_github_branch:str -- Experiment GitHub branch to be mocked in the arguments
            experiment_github_commit:str -- Experiment GitHub commit to be mocked in the arguments
            experiment_github_workflow_name:str -- Experiment GitHub workflow name to be mocked in the arguments
            experiment_github_workflow_run_id:str -- Experiment GitHub workflow run ID to be mocked in the arguments
            experiment_programming_language:str -- Experiment programming language to be mocked in the arguments
            cyclonedx_sbom_filename:str -- Name of CycloneDX SBOM JSON report to parse
            csv_report_filename:str -- Name of CSV report to generate

        :return
            argparse.Namespace -- Mocked arguments
        """
        return Namespace(
            github_api_url=github_api_url,
            github_api_token=github_api_token,
            experiment_id=experiment_id,
            experiment_github_project_name=experiment_github_project_name,
            experiment_github_repository=experiment_github_repository,
            experiment_github_branch=experiment_github_branch,
            experiment_github_commit=experiment_github_commit,
            experiment_github_workflow_name=experiment_github_workflow_name,
            experiment_github_workflow_run_id=experiment_github_workflow_run_id,
            experiment_programming_language=experiment_programming_language,
            cyclonedx_sbom_filename=cyclonedx_sbom_filename,
            csv_report_filename=csv_report_filename,
        )

    def test_get_vulnerability_affected_version_not_found(self):
        with open(OSV_RESPONSE_PYTHON, "r") as f:
            osv_data = JSON.load(f)
        result = cyclonedx_sbom_osv_report.get_vulnerability_affected_version(osv_data["vulns"][1], "1.0")
        self.assertEqual(result, ("Not found", "Not found"))

    def test_get_vulnerability_affected_not_found(self):
        with open(OSV_RESPONSE_EMTPY, "r") as f:
            osv_data = JSON.load(f)
        result = cyclonedx_sbom_osv_report.get_vulnerability_affected_version(osv_data, "1.0")
        self.assertEqual(result, ("Not found", "Not found"))

    @patch(
        "main.python3.cyclonedx_sbom_osv_report.send_github_get_request",
        side_effect=mocked_github_response,
    )
    @patch(
        "main.python3.cyclonedx_sbom_osv_report.send_osv_post_request",
        side_effect=mocked_osv_response,
    )
    def test_query_osv_api_no_records(self, mock_github_response, mock_osv_response):
        temp_file = open("temp.json", "w")
        temp_file.write("{}")
        temp_file.close()

        osv_data = cyclonedx_sbom_osv_report.query_osv_api([], "no_record", "1.0")
        os.remove("temp.json")
        self.assertIsNotNone(osv_data)

    def test_get_json_value_missing_key(self):
        with open(OSV_RESPONSE_JAVA, "r") as f:
            vulnerability_data = JSON.load(f)
        result = cyclonedx_sbom_osv_report.get_json_value(
            vulnerability_data["vulns"][0], "database_specific", "missing_key"
        )
        self.assertEqual(result, "Not found")

    @patch(
        "main.python3.cyclonedx_sbom_osv_report.send_github_get_request",
        side_effect=mocked_github_response,
    )
    def test_main_github_report_not_found(self, mock_github_response):
        args = cyclonedx_sbom_osv_report.get_args(
            REQUIRED_ARGUMENTS
            + [
                "--experiment-github-repository",
                GITHUB_REPOSITORY_MISSING,
                "--cyclonedx-sbom-filename",
                CYCLONEDX_SBOM_REPORT_JAVA,
                "--csv-report-filename",
                CSV_JAVA_RESULT_FILENAME,
            ]
        )
        with self.assertRaises(SystemExit) as cm:
            cyclonedx_sbom_osv_report.main(args)
        self.assertEqual(cm.exception.code, 1)

    @patch(
        "main.python3.cyclonedx_sbom_osv_report.send_github_get_request",
        side_effect=mocked_github_response,
    )
    @patch(
        "main.python3.cyclonedx_sbom_osv_report.send_osv_post_request",
        side_effect=mocked_osv_response,
    )
    def test_main_java(self, mock_github_response, mock_osv_response):
        args = cyclonedx_sbom_osv_report.get_args(
            REQUIRED_ARGUMENTS
            + [
                "--experiment-github-repository",
                GITHUB_REPOSITORY_JAVA,
                "--cyclonedx-sbom-filename",
                CYCLONEDX_SBOM_REPORT_JAVA,
                "--csv-report-filename",
                CSV_JAVA_RESULT_FILENAME,
            ]
        )
        result = cyclonedx_sbom_osv_report.main(args)
        self.assertEqual(result, None)

    @patch(
        "main.python3.cyclonedx_sbom_osv_report.send_github_get_request",
        side_effect=mocked_github_response,
    )
    @patch(
        "main.python3.cyclonedx_sbom_osv_report.send_osv_post_request",
        side_effect=mocked_osv_response,
    )
    def test_main_python(self, mock_github_response, mock_osv_response):
        args = cyclonedx_sbom_osv_report.get_args(
            REQUIRED_ARGUMENTS
            + [
                "--experiment-github-repository",
                GITHUB_REPOSITORY_PYTHON,
                "--cyclonedx-sbom-filename",
                CYCLONEDX_SBOM_REPORT_PYTHON,
                "--csv-report-filename",
                CSV_PYTHON_RESULT_FILENAME,
            ]
        )
        result = cyclonedx_sbom_osv_report.main(args)
        self.assertEqual(result, None)

    @patch(
        "main.python3.cyclonedx_sbom_osv_report.send_github_get_request",
        side_effect=mocked_github_response,
    )
    @patch(
        "main.python3.cyclonedx_sbom_osv_report.send_osv_post_request",
        side_effect=mocked_osv_response,
    )
    def test_main_javascript(self, mock_github_response, mock_osv_response):
        args = cyclonedx_sbom_osv_report.get_args(
            REQUIRED_ARGUMENTS
            + [
                "--experiment-github-repository",
                GITHUB_REPOSITORY_JAVASCRIPT,
                "--cyclonedx-sbom-filename",
                CYCLONEDX_SBOM_REPORT_JAVASCRIPT,
                "--csv-report-filename",
                CSV_JAVASCRIPT_RESULT_FILENAME,
            ]
        )
        result = cyclonedx_sbom_osv_report.main(args)
        self.assertEqual(result, None)

    @classmethod
    def tearDownClass(cls):
        sys.stdout = sys.__stdout__
        for csv_file in os.listdir(f"{SOURCE_DIRECTORY}"):
            if csv_file.endswith(".csv"):
                os.remove(os.path.join(f"{SOURCE_DIRECTORY}", csv_file))


if __name__ == "__main__":
    unittest.main()
