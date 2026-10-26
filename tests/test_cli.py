"""Safety checks that do not require an Eden executable."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]

class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.source=self.root/'input.exe'
        self.data=b'This is deliberately not an Eden executable.'
        self.source.write_bytes(self.data);self.output=self.root/'output.exe'

    def run_cli(self,script,args,optimized=False):
        command=[sys.executable]+(['-O'] if optimized else [])+[str(ROOT/script),*map(str,args)]
        result=subprocess.run(command,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0,result.stdout)
        self.assertEqual(self.source.read_bytes(),self.data)
        return result

    def test_unknown_input_rejected(self):
        for optimized in (False,True):
            self.run_cli('patch_joycon.py',[self.source,self.output],optimized)
            self.assertFalse(self.output.exists())

    def test_ir_hash_guard_survives_optimization(self):
        self.run_cli('patch_ir.py',[self.source,self.output],True)
        self.assertFalse(self.output.exists())

    def test_input_output_alias(self):
        self.run_cli('patch_joycon.py',[self.source,self.source],True)

    def test_manifest_aliases_rejected(self):
        for script in ('patch_joycon.py','patch_eden.py','patch_ir.py'):
            for manifest in (self.source,self.output):
                with self.subTest(script=script,manifest=manifest.name):
                    self.run_cli(script,[self.source,self.output,'--manifest',manifest],True)
                    self.assertFalse(self.output.exists())

    def test_hardlink_aliases_rejected(self):
        linked=self.root/'linked.exe'
        try:os.link(self.source,linked)
        except OSError as e:self.skipTest(str(e))
        for script in ('patch_joycon.py','patch_eden.py','patch_ir.py'):
            self.run_cli(script,[self.source,linked],True)
            self.assertEqual(linked.read_bytes(),self.data)

    def test_existing_output_preserved(self):
        self.output.write_bytes(b'keep this output')
        self.run_cli('patch_joycon.py',[self.source,self.output])
        self.assertEqual(self.output.read_bytes(),b'keep this output')

if __name__=='__main__':unittest.main()
