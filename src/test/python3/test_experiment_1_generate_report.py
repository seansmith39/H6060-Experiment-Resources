#!/usr/bin/env python3

import unittest
from argparse import Namespace
from unittest.mock import patch
from main.python3 import experiment_1_generate_report


DEFAULT_PRODUCT_NAME = 'horusec'


class DevNull:
    def __init__(self):
        pass

    def write(self, s): pass


@patch('sys.stdout', new=DevNull())
@patch('sys.stderr', new=DevNull())
class TestExperiment1GenerateReport(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestExperiment1GenerateReport, self).__init__(*args, **kwargs)

    def __mock_args(product_name: str) -> Namespace:
        """ Mock arguments in argparse.Namespace type

        :argument
            product_name:str -- Name of the product to be mocked in the arguments

        :return
            argparse.Namespace -- Mocked arguments
        """
        return Namespace(product_name=product_name)

    def test_get_mitre_top_25_cwe(self):
        mitre_top_25 = experiment_1_generate_report.get_mitre_top_25_cwe()
        self.assertTrue('CWE-276' in mitre_top_25)

    def test_get_owasp_top_10_cwe(self):
        owasp_top_10 = experiment_1_generate_report.get_owasp_top_10_cwe()
        for key, value in owasp_top_10.items():
            if 'CWE-213' in value:
                owasp_cwe_category = key
        self.assertEqual(owasp_cwe_category, 'A04 Insecure Design')

    def test_main(self):
        args = experiment_1_generate_report.get_args(['--product-name', DEFAULT_PRODUCT_NAME])
        result = experiment_1_generate_report.main(args)
        self.assertEqual(result, None)


if __name__ == '__main__':
    unittest.main()
