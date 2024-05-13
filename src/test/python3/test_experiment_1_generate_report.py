#!/usr/bin/env python3

import unittest
from unittest.mock import patch
from main.python3 import experiment_1_generate_report


class DevNull:
    def __init__(self):
        pass

    def write(self, s): pass

@patch('sys.stdout', new=DevNull())
@patch('sys.stderr', new=DevNull())
class TestExperiment1GenerateReport(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestExperiment1GenerateReport, self).__init__(*args, **kwargs)

    def test_get_mitre_top_25_cwe(self):
        mitre_top_25 = experiment_1_generate_report.get_mitre_top_25_cwe()
        self.assertTrue('CWE-276' in mitre_top_25)


if __name__ == '__main__':
    unittest.main()
