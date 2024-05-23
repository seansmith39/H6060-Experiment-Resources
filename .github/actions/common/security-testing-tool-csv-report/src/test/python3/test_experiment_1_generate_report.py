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
REPORT_SAST_HORUSEC = TEST_DIRECTORY_RESOURCES + "report-sast-horusec.json"
REPORT_SAST_INSIDER = TEST_DIRECTORY_RESOURCES + "report-sast-insider.json"
REPORT_SAST_SEMGREP = TEST_DIRECTORY_RESOURCES + "report-sast-semgrep.json"
REPORT_SAST_SNYK_CODE = TEST_DIRECTORY_RESOURCES + "report-sast-snyk-code.json"
REPORT_SCA_ECLIPSE_STEADY = (
    TEST_DIRECTORY_RESOURCES + "report-sca-eclipse-steady.json"
)
REPORT_SCA_GRYPE = TEST_DIRECTORY_RESOURCES + "report-sca-grype.json"
REPORT_SCA_OWASP_DEPENDENCY_CHECK = (
    TEST_DIRECTORY_RESOURCES + "report-sca-owasp-dependency-check.json"
)
REPORT_SCA_SNYK = TEST_DIRECTORY_RESOURCES + "report-sca-snyk.json"

DEFAULT_CSV_REPORT_FILENAME = "experiment_1_security_testing_tool_results.csv"
NVD_API_KEY = "11111111-2222-3333-4444-555555555555"
OPENCVE_USERNAME = "username"
OPENCVE_PASSWORD = "password"
CVE_ID_NVD = "CVE-2016-2510"
CVE_ID_GRYPE = "CVE-2024-34062"
CVE_ID_ECLIPSE_STEADY = "CVE-2017-18349"
CVE_ID_SNYK = "CVE-2024-4603"
CWE_ID_HORUSEC = "CWE-798"
CWE_ID_INSIDER = "CWE-330"
CWE_ID_SEMGREP = "CWE-327"
CWE_ID_SNYK_CODE = "CWE-22"
CWE_ID_OWASP_DEPENDENCY_CHECK = "CWE-19"
CWE_ID_GRYPE = "CWE-19"
CWE_ID_SNYK = "CWE-400"


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
        or CWE_ID_SEMGREP in args[2]
        or CWE_ID_SNYK in args[2]
        or CWE_ID_SNYK_CODE in args[2]
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

    if (
        CVE_ID_NVD in args[1]
        or CVE_ID_GRYPE in args[1]
        or CVE_ID_ECLIPSE_STEADY in args[1]
        or CVE_ID_SNYK in args[1]
    ):
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
        opencve_username: str,
        opencve_password: str,
        sast_codeql_report_filename: str,
        sast_deepsource_report_filename: str,
        sast_horusec_report_filename: str,
        sast_insider_report_filename: str,
        sast_semgrep_report_filename: str,
        sast_snyk_code_report_filename: str,
        sca_eclipse_steady_report_filename: str,
        sca_grype_report_filename: str,
        sca_owasp_dependency_check_report_filename: str,
        sca_snyk_report_filename: str,
    ) -> Namespace:
        """Mock arguments in argparse.Namespace type

        :parameter
            nvd_api_key:str -- NVD API Key to be mocked in the arguments
            opencve_username:str -- OpenCVE username to be mocked in the arguments
            opencve_password:str -- OpenCVE password to be mocked in the arguments
            sast_codeql_report_filename:str -- Name of the SAST CodeQL report to parse data from
            sast_deepsource_report_filename:str -- Name of the SAST Deepsource report to parse data from
            sast_horusec_report_filename:str -- Name of the SAST Horusec report to parse data from
            sast_insider_report_filename:str -- Name of the SAST Insider report to parse data from
            sast_semgrep_report_filename:str -- Name of the SAST Semgrep report to parse data from
            sast_snyk_code_report_filename:str -- Name of the SAST SNYK-CODE report to parse data from
            sca_eclipse_steady_report_filename:str -- Name of the SCA Eclipse Steady report to parse data from
            sca_grype_report_filename:str -- Name of the SCA Grype report to parse data from
            sca_owasp_dependency_check_report_filename:str -- Name of the SCA OWASP Dependency Check report to parse data from
            sca_snyk_report_filename:str -- Name of the SCA Snyk report to parse data from

        :return
            argparse.Namespace -- Mocked arguments
        """
        return Namespace(
            nvd_api_key=nvd_api_key,
            opencve_username=opencve_username,
            opencve_password=opencve_password,
            sast_codeql_report_filename=sast_codeql_report_filename,
            sast_deepsource_report_filename=sast_deepsource_report_filename,
            sast_horusec_report_filename=sast_horusec_report_filename,
            sast_insider_report_filename=sast_insider_report_filename,
            sast_semgrep_report_filename=sast_semgrep_report_filename,
            sast_snyk_code_report_filename=sast_snyk_code_report_filename,
            sca_eclipse_steady_report_filename=sca_eclipse_steady_report_filename,
            sca_grype_report_filename=sca_grype_report_filename,
            sca_owasp_dependency_check_report_filename=sca_owasp_dependency_check_report_filename,
            sca_snyk_report_filename=sca_snyk_report_filename,
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
            OPENCVE_USERNAME, OPENCVE_PASSWORD, REPORT_SAST_HORUSEC
        )
        self.assertTrue(len(csv_rows) > 0)
        self.assertEqual(csv_rows[0][0], "SAST")
        self.assertEqual(csv_rows[0][1], "HORUSEC")
        self.assertEqual(csv_rows[0][2], "SYNTAX-BASED")
        self.assertEqual(csv_rows[0][3], "CRITICAL")
        self.assertEqual(csv_rows[0][4], "MEDIUM")
        self.assertEqual(csv_rows[0][33], CWE_ID_HORUSEC)
        self.assertEqual(csv_rows[0][34], "Use of Hard-coded Credentials")
        self.assertEqual(
            csv_rows[0][35],
            "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
        )
        self.assertEqual(
            csv_rows[0][38], "A07 Identification and Authentication Failures"
        )
        self.assertEqual(csv_rows[0][39], "18")
        self.assertEqual(csv_rows[0][44], "HS-LEAKS-26")
        self.assertEqual(csv_rows[0][45], "LEAKS")
        self.assertEqual(
            csv_rows[0][46],
            "nio-impl/src/test/java/org/xnio/nio/test/NioSslTcpChannelTestCase.java",
        )

    @patch(
        "main.python3.experiment_1_generate_report.get_opencve_cwe_details",
        side_effect=mocked_response,
    )
    def test_parse_insider_data(self, mock_response):
        csv_rows = experiment_1_generate_report.parse_insider_data(
            OPENCVE_USERNAME, OPENCVE_PASSWORD, REPORT_SAST_INSIDER
        )
        self.assertTrue(len(csv_rows) > 0)
        self.assertEqual(csv_rows[0][0], "SAST")
        self.assertEqual(csv_rows[0][1], "INSIDER")
        self.assertEqual(csv_rows[0][2], "SYNTAX-BASED")
        self.assertEqual(csv_rows[0][33], CWE_ID_INSIDER)
        self.assertEqual(csv_rows[0][34], "Use of Hard-coded Credentials")
        self.assertEqual(
            csv_rows[0][35],
            "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
        )
        self.assertEqual(csv_rows[0][38], "A02 Cryptographic Failures")
        self.assertEqual(
            csv_rows[0][46],
            "api/src/main/java/org/xnio/IoUtils.java",
        )

    @patch(
        "main.python3.experiment_1_generate_report.get_opencve_cwe_details",
        side_effect=mocked_response,
    )
    def test_parse_semgrep_data(self, mock_response):
        csv_rows = experiment_1_generate_report.parse_semgrep_data(
            OPENCVE_USERNAME, OPENCVE_PASSWORD, REPORT_SAST_SEMGREP
        )
        self.assertTrue(len(csv_rows) > 0)
        self.assertEqual(csv_rows[0][0], "SAST")
        self.assertEqual(csv_rows[0][1], "SEMGREP")
        self.assertEqual(csv_rows[0][2], "SEMANTIC-BASED")
        self.assertEqual(csv_rows[0][3], "WARNING")
        self.assertEqual(csv_rows[0][4], "MEDIUM")
        self.assertEqual(csv_rows[0][33], CWE_ID_SEMGREP)
        self.assertEqual(csv_rows[0][34], "Use of Hard-coded Credentials")
        self.assertEqual(
            csv_rows[0][35],
            "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
        )
        self.assertEqual(csv_rows[0][36], "MEDIUM")
        self.assertEqual(csv_rows[0][37], "LOW")
        self.assertEqual(csv_rows[0][38], "A02 Cryptographic Failures")
        self.assertEqual(csv_rows[0][44], "PeU2e2")
        self.assertEqual(csv_rows[0][45], "PYTHON")
        self.assertEqual(
            csv_rows[0][46],
            "clearml/automation/job.py",
        )

    def test_parse_snyk_code_data(self):
        csv_rows = experiment_1_generate_report.parse_snyk_code_data(
            REPORT_SAST_SNYK_CODE
        )
        self.assertTrue(len(csv_rows) > 0)
        self.assertEqual(csv_rows[0][0], "SAST")
        self.assertEqual(csv_rows[0][1], "SNYK CODE")
        self.assertEqual(csv_rows[0][2], "SEMANTIC-BASED")
        self.assertEqual(csv_rows[0][33], CWE_ID_SNYK_CODE)
        self.assertEqual(csv_rows[0][34], "TarSlip")
        self.assertEqual(
            csv_rows[0][35],
            "Arbitrary File Write via Archive Extraction (Tar Slip)",
        )
        self.assertEqual(csv_rows[0][38], "A01 Broken Access Control")
        self.assertEqual(csv_rows[0][39], "8")
        self.assertEqual(csv_rows[0][44], "python/TarSlip")
        self.assertEqual(csv_rows[0][45], "PYTHON")

    @patch(
        "main.python3.experiment_1_generate_report.get_opencve_cwe_details",
        side_effect=mocked_response,
    )
    @patch(
        "main.python3.experiment_1_generate_report.get_cve_information_from_nvd",
        side_effect=mocked_nvd_response,
    )
    def test_parse_grype_data(self, mock_response_opencve, mock_response_nvd):
        csv_rows = experiment_1_generate_report.parse_grype_data(
            NVD_API_KEY,
            OPENCVE_USERNAME,
            OPENCVE_PASSWORD,
            REPORT_SCA_GRYPE,
        )
        self.assertTrue(len(csv_rows) > 0)
        self.assertEqual(csv_rows[0][0], "SCA")
        self.assertEqual(csv_rows[0][1], "GRYPE")
        self.assertEqual(csv_rows[0][2], "METADATA-BASED")
        self.assertEqual(csv_rows[0][3], "MEDIUM")
        self.assertEqual(csv_rows[0][5], CVE_ID_GRYPE)
        self.assertEqual(csv_rows[0][6], "NVD")
        self.assertEqual(csv_rows[0][7], "2016-04-07T20:59:05.567")
        self.assertEqual(csv_rows[0][8], "2020-10-20T22:15:18.483")
        self.assertEqual(csv_rows[0][9], "MODIFIED")
        self.assertEqual(
            csv_rows[0][10],
            "tqdm is an open source progress bar for Python and CLI. Any optional non-boolean CLI arguments (e.g. `--delim`, `--buf-size`, `--manpath`) are passed through python's `eval`, allowing arbitrary code execution. This issue is only locally exploitable and had been addressed in release version 4.66.3. All users are advised to upgrade. There are no known workarounds for this vulnerability.",
        )
        self.assertEqual(csv_rows[0][13], "3.1")
        self.assertEqual(csv_rows[0][15], 4.8)
        self.assertEqual(csv_rows[0][16], "UNCHANGED")
        self.assertEqual(csv_rows[0][17], 1.3)
        self.assertEqual(csv_rows[0][18], 3.4)
        self.assertEqual(csv_rows[0][19], "NETWORK")
        self.assertEqual(csv_rows[0][20], "HIGH")
        self.assertEqual(csv_rows[0][21], "NONE")
        self.assertEqual(csv_rows[0][22], "NONE")
        self.assertEqual(csv_rows[0][23], "HIGH")
        self.assertEqual(csv_rows[0][24], "HIGH")
        self.assertEqual(csv_rows[0][25], "HIGH")
        self.assertEqual(csv_rows[0][33], CWE_ID_GRYPE)
        self.assertEqual(csv_rows[0][34], "Use of Hard-coded Credentials")
        self.assertEqual(
            csv_rows[0][35],
            "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
        )
        self.assertEqual(csv_rows[0][40], "pkg:pypi/tqdm@4.64.1")
        self.assertEqual(csv_rows[0][45], "PYTHON")
        self.assertEqual(csv_rows[0][46], "/examples/cicd/requirements.txt")

    @patch(
        "main.python3.experiment_1_generate_report.get_opencve_cwe_details",
        side_effect=mocked_response,
    )
    @patch(
        "main.python3.experiment_1_generate_report.get_cve_information_from_nvd",
        side_effect=mocked_nvd_response,
    )
    def test_parse_eclipse_steady_data(
        self, mock_response_opencve, mock_response_nvd
    ):
        csv_rows = experiment_1_generate_report.parse_eclipse_steady_data(
            NVD_API_KEY,
            OPENCVE_USERNAME,
            OPENCVE_PASSWORD,
            REPORT_SCA_ECLIPSE_STEADY,
        )
        self.assertTrue(len(csv_rows) > 0)
        self.assertEqual(csv_rows[0][0], "SCA")
        self.assertEqual(csv_rows[0][1], "ECLIPSE STEADY")
        self.assertEqual(csv_rows[0][2], "CODE-CENTRIC")
        self.assertEqual(csv_rows[0][3], "HIGH")
        self.assertEqual(csv_rows[0][5], CVE_ID_ECLIPSE_STEADY)
        self.assertEqual(csv_rows[0][6], "NVD")
        self.assertEqual(csv_rows[0][7], "2016-04-07T20:59:05.567")
        self.assertEqual(csv_rows[0][8], "2020-10-20T22:15:18.483")
        self.assertEqual(csv_rows[0][9], "MODIFIED")
        self.assertEqual(
            csv_rows[0][10],
            "BeanShell (bsh) before 2.0b6, when included on the classpath by an application that uses Java serialization or XStream, allows remote attackers to execute arbitrary code via crafted serialized data, related to XThis.Handler.",
        )
        self.assertEqual(csv_rows[0][13], "3.1")
        self.assertEqual(csv_rows[0][14], "nvd@nist.gov")
        self.assertEqual(csv_rows[0][15], 8.1)
        self.assertEqual(csv_rows[0][16], "UNCHANGED")
        self.assertEqual(csv_rows[0][17], 2.2)
        self.assertEqual(csv_rows[0][18], 5.9)
        self.assertEqual(csv_rows[0][19], "NETWORK")
        self.assertEqual(csv_rows[0][20], "HIGH")
        self.assertEqual(csv_rows[0][21], "NONE")
        self.assertEqual(csv_rows[0][22], "NONE")
        self.assertEqual(csv_rows[0][23], "HIGH")
        self.assertEqual(csv_rows[0][24], "HIGH")
        self.assertEqual(csv_rows[0][25], "HIGH")
        self.assertEqual(csv_rows[0][33], CWE_ID_GRYPE)
        self.assertEqual(csv_rows[0][34], "Use of Hard-coded Credentials")
        self.assertEqual(
            csv_rows[0][35],
            "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
        )
        self.assertEqual(csv_rows[0][40], "fastjson-1.2.80.jar")
        self.assertEqual(csv_rows[0][41], "DIRECT")

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
                REPORT_SCA_OWASP_DEPENDENCY_CHECK,
            )
        )
        self.assertTrue(len(csv_rows) > 0)
        self.assertEqual(csv_rows[0][0], "SCA")
        self.assertEqual(csv_rows[0][1], "OWASP DEPENDENCY CHECK")
        self.assertEqual(csv_rows[0][2], "METADATA-BASED")
        self.assertEqual(csv_rows[0][3], "HIGH")
        self.assertEqual(csv_rows[0][4], "HIGH")
        self.assertEqual(csv_rows[0][5], "CVE-2016-2510")
        self.assertEqual(csv_rows[0][6], "NVD")
        self.assertEqual(csv_rows[0][7], "2016-04-07T20:59:05.567")
        self.assertEqual(csv_rows[0][8], "2020-10-20T22:15:18.483")
        self.assertEqual(csv_rows[0][9], "MODIFIED")
        self.assertEqual(
            csv_rows[0][10],
            "BeanShell (bsh) before 2.0b6, when included on the classpath by an application that uses Java serialization or XStream, allows remote attackers to execute arbitrary code via crafted serialized data, related to XThis.Handler.",
        )
        self.assertEqual(csv_rows[0][13], "3.1")
        self.assertEqual(csv_rows[0][15], 8.1)
        self.assertEqual(csv_rows[0][16], "UNCHANGED")
        self.assertEqual(csv_rows[0][17], "2.2")
        self.assertEqual(csv_rows[0][18], "5.9")
        self.assertEqual(csv_rows[0][19], "NETWORK")
        self.assertEqual(csv_rows[0][20], "HIGH")
        self.assertEqual(csv_rows[0][21], "NONE")
        self.assertEqual(csv_rows[0][22], "NONE")
        self.assertEqual(csv_rows[0][23], "HIGH")
        self.assertEqual(csv_rows[0][24], "HIGH")
        self.assertEqual(csv_rows[0][25], "HIGH")
        self.assertEqual(csv_rows[0][33], CWE_ID_OWASP_DEPENDENCY_CHECK)
        self.assertEqual(csv_rows[0][34], "Use of Hard-coded Credentials")
        self.assertEqual(
            csv_rows[0][35],
            "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
        )
        self.assertEqual(csv_rows[0][40], "pkg:maven/org.beanshell/bsh@2.0b4")

    @patch(
        "main.python3.experiment_1_generate_report.get_opencve_cwe_details",
        side_effect=mocked_response,
    )
    @patch(
        "main.python3.experiment_1_generate_report.get_cve_information_from_nvd",
        side_effect=mocked_nvd_response,
    )
    def test_parse_snyk_data(self, mock_response_opencve, mock_response_nvd):
        csv_rows = experiment_1_generate_report.parse_snyk_data(
            NVD_API_KEY,
            OPENCVE_USERNAME,
            OPENCVE_PASSWORD,
            REPORT_SCA_SNYK,
        )
        self.assertTrue(len(csv_rows) > 0)
        self.assertEqual(csv_rows[0][0], "SCA")
        self.assertEqual(csv_rows[0][1], "SNYK")
        self.assertEqual(csv_rows[0][2], "METADATA-BASED")
        self.assertEqual(csv_rows[0][3], "LOW")
        self.assertEqual(csv_rows[0][5], "CVE-2024-4603")
        self.assertEqual(csv_rows[0][7], "2024-05-19T10:46:05.728350Z")
        self.assertEqual(csv_rows[0][8], "2024-05-19T10:46:06.262960Z")
        self.assertEqual(
            csv_rows[0][10],
            "Uncontrolled Resource Consumption",
        )
        self.assertEqual(csv_rows[0][11], "FALSE")
        self.assertEqual(csv_rows[0][12], "FALSE")
        self.assertEqual(csv_rows[0][13], "3.1")
        self.assertEqual(csv_rows[0][14], "Red Hat")
        self.assertEqual(csv_rows[0][15], 5.3)
        self.assertEqual(csv_rows[0][16], "UNCHANGED")

        self.assertEqual(csv_rows[0][19], "NETWORK")
        self.assertEqual(csv_rows[0][20], "LOW")
        self.assertEqual(csv_rows[0][21], "NONE")
        self.assertEqual(csv_rows[0][22], "NONE")
        self.assertEqual(csv_rows[0][23], "NONE")
        self.assertEqual(csv_rows[0][24], "NONE")
        self.assertEqual(csv_rows[0][25], "LOW")
        self.assertEqual(csv_rows[0][33], CWE_ID_SNYK)
        self.assertEqual(csv_rows[0][40], "cryptography@42.0.7")
        self.assertEqual(csv_rows[0][41], "TRANSITIVE")
        self.assertEqual(csv_rows[0][42], "FALSE")
        self.assertEqual(csv_rows[0][43], "FALSE")
        self.assertEqual(csv_rows[0][44], "SNYK-PYTHON-CRYPTOGRAPHY-6913422")
        self.assertEqual(csv_rows[0][45], "PYTHON")

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
                "--sast-horusec-report-filename",
                REPORT_SAST_HORUSEC,
                "--sast-insider-report-filename",
                REPORT_SAST_INSIDER,
                "--sast-semgrep-report-filename",
                REPORT_SAST_SEMGREP,
                "--sast-snyk-code-report-filename",
                REPORT_SAST_SNYK_CODE,
                "--sca-grype-report-filename",
                REPORT_SCA_GRYPE,
                "--sca-eclipse-steady-report-filename",
                REPORT_SCA_ECLIPSE_STEADY,
                "--sca-owasp-dependency-check-report-filename",
                REPORT_SCA_OWASP_DEPENDENCY_CHECK,
                "--sca-snyk-report-filename",
                REPORT_SCA_SNYK,
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
