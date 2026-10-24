"""Input-gate unit tests, explicitly not deployed-backend conformance."""
import importlib.util
from pathlib import Path
import unittest

path=Path(__file__).resolve().parents[1]/'tools/check_domain_deployment.py'
spec=importlib.util.spec_from_file_location('domain_deployment_checker',path)
checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)

class DeploymentInputs(unittest.TestCase):
    def doc(self):return {'version':'domain-deployment-inputs-v1','inputs':{k:None for k in checker.FIELDS}}
    def test_missing_inputs_block_and_no_check_passes(self):
        result=checker.check_inputs(self.doc())
        self.assertEqual(result['status'],'BLOCKED');self.assertEqual(set(result['checks'].values()),{'NOT_RUN'})
        self.assertFalse(result['production_qualified']);self.assertFalse(result['backend_executed'])
    def test_complete_declarations_are_not_verification(self):
        doc=self.doc();doc['inputs']={k:'external-reviewed-reference' for k in checker.FIELDS}
        result=checker.check_inputs(doc)
        self.assertEqual(result['status'],'INPUTS_DECLARED_NOT_VERIFIED')
        self.assertFalse(result['authorization_granted']);self.assertFalse(result['production_qualified'])
    def test_secrets_not_allowed_in_manifest(self):
        doc=self.doc();doc['inputs']['password']='do-not-export'
        with self.assertRaises(ValueError):checker.check_inputs(doc)
    def test_authority_flag_cannot_be_supplied(self):
        doc=self.doc();doc['authorization_granted']=True
        with self.assertRaises(ValueError):checker.check_inputs(doc)
    def test_wrong_version_rejected(self):
        doc=self.doc();doc['version']='latest'
        with self.assertRaises(ValueError):checker.check_inputs(doc)
    def test_boolean_reference_rejected(self):
        doc=self.doc();doc['inputs']['deployment_authorization_reference']=True
        with self.assertRaises(ValueError):checker.check_inputs(doc)
