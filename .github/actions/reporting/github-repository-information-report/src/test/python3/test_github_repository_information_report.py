#!/usr/bin/env python3

import os
import sys
import logging
import unittest
import json as JSON
from argparse import Namespace
from unittest.mock import patch
from main.python3 import github_repository_information_report


TEST_DIRECTORY_RESOURCES = os.path.dirname(os.path.realpath(__file__)) + "/resources/"

# Report filenames
GITHUB_REPOSITORY_FORKED_RESPONSE_JAVA = TEST_DIRECTORY_RESOURCES + "github/forked/java/github-repository-response.json"
GITHUB_REPOSITORY_FORKED_RESPONSE_JAVASCRIPT = TEST_DIRECTORY_RESOURCES + "github/forked/javascript/github-repository-response.json"
GITHUB_REPOSITORY_FORKED_RESPONSE_PYTHON = TEST_DIRECTORY_RESOURCES + "github/forked/python/github-repository-response.json"

GITHUB_REPOSITORY_UPSTREAM_RESPONSE_JAVA = TEST_DIRECTORY_RESOURCES + "github/upstream/java/github-repository-response.json"
GITHUB_REPOSITORY_UPSTREAM_RESPONSE_JAVASCRIPT = TEST_DIRECTORY_RESOURCES + "github/upstream/javascript/github-repository-response.json"
GITHUB_REPOSITORY_UPSTREAM_RESPONSE_PYTHON = TEST_DIRECTORY_RESOURCES + "github/upstream/python/github-repository-response.json"

GITHUB_REPOSITORY_UPSTREAM_CONTRIBUTORS_RESPONSE_JAVA = TEST_DIRECTORY_RESOURCES + "github/upstream/java/github-contributors-response.json"
GITHUB_REPOSITORY_UPSTREAM_CONTRIBUTORS_RESPONSE_JAVASCRIPT = (
    TEST_DIRECTORY_RESOURCES + "github/upstream/javascript/github-contributors-response.json"
)
GITHUB_REPOSITORY_UPSTREAM_CONTRIBUTORS_RESPONSE_PYTHON = (
    TEST_DIRECTORY_RESOURCES + "github/upstream/python/github-contributors-response.json"
)

GITHUB_REPOSITORY_UPSTREAM_COMMUNITY_PROFILE_RESPONSE_JAVA = (
    TEST_DIRECTORY_RESOURCES + "github/upstream/java/github-community-profile-response.json"
)
GITHUB_REPOSITORY_UPSTREAM_COMMUNITY_PROFILE_RESPONSE_JAVASCRIPT = (
    TEST_DIRECTORY_RESOURCES + "github/upstream/javascript/github-community-profile-response.json"
)
GITHUB_REPOSITORY_UPSTREAM_COMMUNITY_PROFILE_RESPONSE_PYTHON = (
    TEST_DIRECTORY_RESOURCES + "github/upstream/python/github-community-profile-response.json"
)

GITHUB_REPOSITORY_UPSTREAM_TAGS_RESPONSE_JAVA = TEST_DIRECTORY_RESOURCES + "github/upstream/java/github-tags-response.json"
GITHUB_REPOSITORY_UPSTREAM_TAGS_RESPONSE_JAVASCRIPT = TEST_DIRECTORY_RESOURCES + "github/upstream/javascript/github-tags-response.json"
GITHUB_REPOSITORY_UPSTREAM_TAGS_RESPONSE_PYTHON = TEST_DIRECTORY_RESOURCES + "github/upstream/python/github-tags-response.json"

GITHUB_REPOSITORY_UPSTREAM_INDIVIDUAL_TAG_RESPONSE_JAVA = (
    TEST_DIRECTORY_RESOURCES + "github/upstream/java/github-individual-tag-response.json"
)
GITHUB_REPOSITORY_UPSTREAM_INDIVIDUAL_TAG_RESPONSE_JAVASCRIPT = (
    TEST_DIRECTORY_RESOURCES + "github/upstream/javascript/github-individual-tag-response.json"
)
GITHUB_REPOSITORY_UPSTREAM_INDIVIDUAL_TAG_RESPONSE_PYTHON = (
    TEST_DIRECTORY_RESOURCES + "github/upstream/python/github-individual-tag-response.json"
)

# CSV result filenames
CSV_INFORMATION_JAVA_RESULT_FILENAME = "github_repository_information_report_java.csv"
CSV_INFORMATION_JAVASCRIPT_RESULT_FILENAME = "github_repository_information_report_javascript.csv"
CSV_INFORMATION_PYTHON_RESULT_FILENAME = "github_repository_information_report_python.csv"

CSV_TAG_JAVA_RESULT_FILENAME = "github_repository_tag_report_java.csv"
CSV_TAG_JAVASCRIPT_RESULT_FILENAME = "github_repository_tag_report_javascript.csv"
CSV_TAG_PYTHON_RESULT_FILENAME = "github_repository_tag_report_python.csv"

# CSV result paths
SOURCE_DIRECTORY = "../../main/python3"

# Mocked required arguments
GITHUB_API_URL = "https://api.github.com"
GITHUB_API_TOKEN = "ghp_1234567890"
EXPERIMENT_ID = "1"

# Mocked GitHub arguments
GITHUB_PROJECT_NAME = "project-name"
GITHUB_PACKAGE_MANAGER = "package-manager"
GITHUB_FORKED_REPOSITORY_JAVA = "org/repository-java"
GITHUB_FORKED_REPOSITORY_JAVASCRIPT = "org/repository-javascript"
GITHUB_FORKED_REPOSITORY_PYTHON = "org/repository-python"
GITHUB_UPSTREAM_REPOSITORY_JAVA = "upstream/repository-java"
GITHUB_UPSTREAM_REPOSITORY_JAVASCRIPT = "upstream/repository-javascript"
GITHUB_UPSTREAM_REPOSITORY_PYTHON = "upstream/repository-python"

REQUIRED_ARGUMENTS = [
    "--github-api-url",
    GITHUB_API_URL,
    "--github-api-token",
    GITHUB_API_TOKEN,
    "--experiment-id",
    EXPERIMENT_ID,
    "--experiment-github-project-name",
    GITHUB_PROJECT_NAME,
    "--experiment-github-package-manager",
    GITHUB_PACKAGE_MANAGER,
]


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

    if "private-vulnerability-reporting" in args[0]:
        return MockResponse('{"enabled": true}', 200)
    elif GITHUB_FORKED_REPOSITORY_JAVASCRIPT in args[0]:
        return MockResponse(GITHUB_REPOSITORY_FORKED_RESPONSE_JAVASCRIPT, 200)
    elif GITHUB_FORKED_REPOSITORY_JAVA in args[0]:
        return MockResponse(GITHUB_REPOSITORY_FORKED_RESPONSE_JAVA, 200)
    elif GITHUB_FORKED_REPOSITORY_PYTHON in args[0]:
        return MockResponse(GITHUB_REPOSITORY_FORKED_RESPONSE_PYTHON, 200)
    elif GITHUB_UPSTREAM_REPOSITORY_JAVASCRIPT in args[0]:
        if "contributors" in args[0]:
            return MockResponse(GITHUB_REPOSITORY_UPSTREAM_CONTRIBUTORS_RESPONSE_JAVASCRIPT, 200)
        elif "community/profile" in args[0]:
            return MockResponse(GITHUB_REPOSITORY_UPSTREAM_COMMUNITY_PROFILE_RESPONSE_JAVASCRIPT, 200)
        elif "git/refs/tags" in args[0]:
            return MockResponse(GITHUB_REPOSITORY_UPSTREAM_TAGS_RESPONSE_JAVASCRIPT, 200)
        elif "git/tags" in args[0]:
            return MockResponse(GITHUB_REPOSITORY_UPSTREAM_INDIVIDUAL_TAG_RESPONSE_JAVASCRIPT, 200)
        else:
            return MockResponse(GITHUB_REPOSITORY_UPSTREAM_RESPONSE_JAVASCRIPT, 200)
    elif GITHUB_UPSTREAM_REPOSITORY_JAVA in args[0]:
        if "contributors" in args[0]:
            return MockResponse(GITHUB_REPOSITORY_UPSTREAM_CONTRIBUTORS_RESPONSE_JAVA, 200)
        elif "community/profile" in args[0]:
            return MockResponse(GITHUB_REPOSITORY_UPSTREAM_COMMUNITY_PROFILE_RESPONSE_JAVA, 200)
        elif "git/refs/tags" in args[0]:
            return MockResponse(GITHUB_REPOSITORY_UPSTREAM_TAGS_RESPONSE_JAVA, 200)
        elif "git/tags" in args[0]:
            return MockResponse(GITHUB_REPOSITORY_UPSTREAM_INDIVIDUAL_TAG_RESPONSE_JAVA, 200)
        else:
            return MockResponse(GITHUB_REPOSITORY_UPSTREAM_RESPONSE_JAVA, 200)
    elif GITHUB_UPSTREAM_REPOSITORY_PYTHON in args[0]:
        if "contributors" in args[0]:
            return MockResponse(GITHUB_REPOSITORY_UPSTREAM_CONTRIBUTORS_RESPONSE_PYTHON, 200)
        elif "community/profile" in args[0]:
            return MockResponse(GITHUB_REPOSITORY_UPSTREAM_COMMUNITY_PROFILE_RESPONSE_PYTHON, 200)
        elif "git/refs/tags" in args[0]:
            return MockResponse(GITHUB_REPOSITORY_UPSTREAM_TAGS_RESPONSE_PYTHON, 200)
        elif "git/tags" in args[0]:
            return MockResponse(GITHUB_REPOSITORY_UPSTREAM_INDIVIDUAL_TAG_RESPONSE_PYTHON, 200)
        else:
            return MockResponse(GITHUB_REPOSITORY_UPSTREAM_RESPONSE_PYTHON, 200)
    else:
        return None


class DevNull:
    def __init__(self):
        pass

    def write(self, s):
        pass


@patch("sys.stdout", new=DevNull())
@patch("sys.stderr", new=DevNull())
class TestGitHubRepositoryInformationReport(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestGitHubRepositoryInformationReport, self).__init__(*args, **kwargs)

    @classmethod
    def setUpClass(cls):
        github_repository_information_report.log = logging.getLogger()
        github_repository_information_report.log.setLevel(logging.INFO)
        with open(os.devnull, "w") as f:
            sys.stdout = f

    def __mock_args(
        self,
        github_server_url: str,
        github_api_url: str,
        github_api_token: str,
        experiment_id: str,
        experiment_github_project_name: str,
        experiment_github_package_manager: str,
        experiment_github_repository: str,
        experiment_github_branch: str,
        experiment_github_commit: str,
        experiment_github_workflow_name: str,
        experiment_github_workflow_run_id: str,
        experiment_programming_language: str,
        csv_github_repository_information_report_filename: str,
        csv_github_repository_tag_report_filename: str,
    ) -> Namespace:
        """Mock arguments in argparse.Namespace type

        :parameter
            github_server_url:str -- GitHub server URL to be mocked in the arguments
            github_api_url:str -- GitHub API URL to be mocked in the arguments
            github_api_token:str -- GitHub API Token to be mocked in the arguments
            experiment_id:str -- Experiment ID to be mocked in the arguments
            experiment_github_project_name:str -- Experiment GitHub project name to be mocked in the arguments
            experiment_github_package_manager:str -- Experiment GitHub package manager to be mocked in the arguments
            experiment_github_repository:str -- Experiment GitHub repository to be mocked in the arguments
            experiment_github_branch:str -- Experiment GitHub branch to be mocked in the arguments
            experiment_github_commit:str -- Experiment GitHub commit to be mocked in the arguments
            experiment_github_workflow_name:str -- Experiment GitHub workflow name to be mocked in the arguments
            experiment_github_workflow_run_id:str -- Experiment GitHub workflow run ID to be mocked in the arguments
            experiment_programming_language:str -- Experiment programming language to be mocked in the arguments
            csv_github_repository_information_report_filename:str -- CSV GitHub repository information report filename to be mocked in the arguments
            csv_github_repository_tag_report_filename:str -- CSV GitHub repository tag report filename to be mocked in the arguments

        :return
            argparse.Namespace -- Mocked arguments
        """
        return Namespace(
            github_server_url=github_server_url,
            github_api_url=github_api_url,
            github_api_token=github_api_token,
            experiment_id=experiment_id,
            experiment_github_project_name=experiment_github_project_name,
            experiment_github_package_manager=experiment_github_package_manager,
            experiment_github_repository=experiment_github_repository,
            experiment_github_branch=experiment_github_branch,
            experiment_github_commit=experiment_github_commit,
            experiment_github_workflow_name=experiment_github_workflow_name,
            experiment_github_workflow_run_id=experiment_github_workflow_run_id,
            experiment_programming_language=experiment_programming_language,
            csv_github_repository_information_report_filename=csv_github_repository_information_report_filename,
            csv_github_repository_tag_report_filename=csv_github_repository_tag_report_filename,
        )

    def test_get_json_value_missing_first_key(self):
        with open(GITHUB_REPOSITORY_UPSTREAM_RESPONSE_JAVA, "r") as f:
            data = JSON.load(f)
        result = github_repository_information_report.get_json_value(data, "missing_key")
        self.assertEqual(result, "Not found")

    def test_get_json_value_missing_second_key(self):
        with open(GITHUB_REPOSITORY_UPSTREAM_RESPONSE_JAVA, "r") as f:
            data = JSON.load(f)
        result = github_repository_information_report.get_json_value(data, "license", "missing_key")
        self.assertEqual(result, "Not found")

    def test_get_json_value_missing_first_value(self):
        with open(GITHUB_REPOSITORY_UPSTREAM_RESPONSE_JAVA, "r") as f:
            data = JSON.load(f)
        result = github_repository_information_report.get_json_value(data, "mirror_url")
        self.assertEqual(result, "Not found")

    def test_get_json_value_missing_second_value(self):
        with open(GITHUB_REPOSITORY_UPSTREAM_RESPONSE_JAVA, "r") as f:
            data = JSON.load(f)
        result = github_repository_information_report.get_json_value(data, "license", "url")
        self.assertEqual(result, "Not found")

    def test_get_json_value_missing_initial_key(self):
        with open(GITHUB_REPOSITORY_UPSTREAM_RESPONSE_JAVA, "r") as f:
            data = JSON.load(f)
        result = github_repository_information_report.get_json_value(data, "missing", "url")
        self.assertEqual(result, "Not found")

    def test_write_csv_report_header_category_not_found(self):
        with self.assertRaises(SystemExit) as cm:
            github_repository_information_report.write_csv_report_header("category_not_found", "filename.csv")
        self.assertEqual(cm.exception.code, 1)

    def test_main_repository_no_response(self):
        args = github_repository_information_report.get_args(
            REQUIRED_ARGUMENTS
            + [
                "--experiment-github-repository",
                GITHUB_FORKED_REPOSITORY_JAVA,
                "--csv-github-repository-information-report-filename",
                CSV_INFORMATION_JAVA_RESULT_FILENAME,
                "--csv-github-repository-tag-report-filename",
                CSV_TAG_JAVA_RESULT_FILENAME,
            ]
        )
        with self.assertRaises(SystemExit) as cm:
            github_repository_information_report.main(args)
        self.assertEqual(cm.exception.code, 1)

    @patch(
        "main.python3.github_repository_information_report.send_github_get_request",
        side_effect=mocked_github_response,
    )
    def test_main_java(self, mock_github_response):
        args = github_repository_information_report.get_args(
            REQUIRED_ARGUMENTS
            + [
                "--experiment-github-repository",
                GITHUB_FORKED_REPOSITORY_JAVA,
                "--csv-github-repository-information-report-filename",
                CSV_INFORMATION_JAVA_RESULT_FILENAME,
                "--csv-github-repository-tag-report-filename",
                CSV_TAG_JAVA_RESULT_FILENAME,
            ]
        )
        result = github_repository_information_report.main(args)
        self.assertEqual(result, None)

    @patch(
        "main.python3.github_repository_information_report.send_github_get_request",
        side_effect=mocked_github_response,
    )
    def test_main_javascript(self, mock_github_response):
        args = github_repository_information_report.get_args(
            REQUIRED_ARGUMENTS
            + [
                "--experiment-github-repository",
                GITHUB_FORKED_REPOSITORY_JAVASCRIPT,
                "--csv-github-repository-information-report-filename",
                CSV_INFORMATION_JAVASCRIPT_RESULT_FILENAME,
                "--csv-github-repository-tag-report-filename",
                CSV_TAG_JAVASCRIPT_RESULT_FILENAME,
            ]
        )
        result = github_repository_information_report.main(args)
        self.assertEqual(result, None)

    @patch(
        "main.python3.github_repository_information_report.send_github_get_request",
        side_effect=mocked_github_response,
    )
    def test_main_python(self, mock_github_response):
        args = github_repository_information_report.get_args(
            REQUIRED_ARGUMENTS
            + [
                "--experiment-github-repository",
                GITHUB_FORKED_REPOSITORY_PYTHON,
                "--csv-github-repository-information-report-filename",
                CSV_INFORMATION_PYTHON_RESULT_FILENAME,
                "--csv-github-repository-tag-report-filename",
                CSV_TAG_PYTHON_RESULT_FILENAME,
            ]
        )
        result = github_repository_information_report.main(args)
        self.assertEqual(result, None)

    @classmethod
    def tearDownClass(cls):
        sys.stdout = sys.__stdout__
        for csv_file in os.listdir(f"{SOURCE_DIRECTORY}"):
            if csv_file.endswith(".csv"):
                os.remove(os.path.join(f"{SOURCE_DIRECTORY}", csv_file))


if __name__ == "__main__":
    unittest.main()
