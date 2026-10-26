"""Build a separate, hash-checked Eden executable with the Joy-Con fixes."""
# SPDX-License-Identifier: GPL-3.0-or-later
import argparse
import hashlib
import json
from pathlib import Path

import patch_eden
import patch_ir

ORIGINAL_SHA=patch_eden.ORIGINAL_SHA256
RUMBLE_SHA=patch_ir.INPUT_SHA
FINAL_SHA='4a3662eb69f43fc06079285a0b2567397b6a6d05b19a1cefc632d42117ec821c'

def digest(data):
    return hashlib.sha256(data).hexdigest()

def distinct(paths):
    for i,left in enumerate(paths):
        for right in paths[i+1:]:
            if left.resolve()==right.resolve() or (left.exists() and right.exists() and left.samefile(right)):
                raise ValueError('Input, output and manifest must be distinct files')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('input',type=Path)
    p.add_argument('output',type=Path,nargs='?')
    p.add_argument('--manifest',type=Path)
    p.add_argument('--check',action='store_true',help='Identify the executable without writing anything')
    a=p.parse_args()
    try:
        if a.check and (a.output or a.manifest):
            raise ValueError('--check does not accept output or manifest paths')
        if not a.check and not a.output:
            raise ValueError('Provide a separate output path, or use --check')
        distinct([a.input]+([a.output] if a.output else [])+([a.manifest] if a.manifest else []))
        if not a.check and any(path.exists() for path in (a.output,a.manifest) if path):
            raise ValueError('Output and manifest must not already exist')
        source=a.input.read_bytes();sha=digest(source)
        states={ORIGINAL_SHA:'supported original',RUMBLE_SHA:'supported rumble-only predecessor',FINAL_SHA:'combined fixes already applied'}
        if sha not in states:
            raise ValueError('Unsupported SHA256: '+sha+'. This patch supports one exact Eden v0.2.1 Windows x64 build.')
        if a.check:
            print(json.dumps({'sha256':sha,'status':states[sha]}));return 0
        if sha==FINAL_SHA:
            raise ValueError('This executable already has the combined fixes; use --check')
        result=source;steps=[]
        if sha==ORIGINAL_SHA:
            result,report=patch_eden.patch(result);steps.append(report)
            if digest(result)!=RUMBLE_SHA:
                raise RuntimeError('Unexpected intermediate checksum; no output was written')
        result,report=patch_ir.patch(result);steps.append(report)
        if digest(result)!=FINAL_SHA:
            raise RuntimeError('Unexpected final checksum; no output was written')
        a.output.parent.mkdir(parents=True,exist_ok=True)
        with a.output.open('xb') as f:f.write(result)
        if a.manifest:
            a.manifest.parent.mkdir(parents=True,exist_ok=True)
            with a.manifest.open('x',encoding='utf-8') as f:
                json.dump({'input_sha256':sha,'output_sha256':FINAL_SHA,'steps':steps},f,indent=2)
        print(json.dumps({'sha256':FINAL_SHA,'status':'created separate patched executable'}));return 0
    except (OSError,ValueError,RuntimeError,AssertionError) as error:
        p.exit(1,'Error: '+str(error)+'\n')

if __name__=='__main__':raise SystemExit(main())
