"""Reproduce the tested, persistent vibration fix for one exact Eden v0.2.1 PE."""
# SPDX-License-Identifier: GPL-3.0-or-later
import argparse
import hashlib
import json
from pathlib import Path
import struct

import pefile

ORIGINAL_SHA256='c4135c90e5dca07bfc629081ddfc316ad35ebe6095e54854706c61b41e98a97c'
MARKER=b'EDEN_RUMBLEFIX_V2\0'
ROUTE=0x210d020
QUEUE=0x210d080
ROUTE_UNWIND=0x210d0c0
QUEUE_UNWIND=0x210d0d0
MARKER_RVA=0x210d100


def jump(address,target,length=5,prefix=b'\xe9'):
    code=prefix+struct.pack('<i',target-address-len(prefix)-4)
    return code+b'\x90'*(length-len(code))


class Code:
    def __init__(self,address):
        self.address=address
        self.data=bytearray()
        self.labels={}
        self.fixups=[]

    def emit(self,hexbytes):
        self.data.extend(bytes.fromhex(hexbytes))

    def branch(self,prefix,target):
        offset=len(self.data)
        self.data.extend(bytes.fromhex(prefix)+b'\0'*4)
        self.fixups.append((offset,bytes.fromhex(prefix),target))

    def label(self,name):
        self.labels[name]=self.address+len(self.data)

    def finish(self):
        for offset,prefix,target in self.fixups:
            to=self.labels[target] if isinstance(target,str) else target
            self.data[offset:offset+len(prefix)+4]=jump(self.address+offset,to,prefix=prefix)
        return bytes(self.data)


def patch(source: bytes):
    digest=hashlib.sha256(source).hexdigest()
    if digest!=ORIGINAL_SHA256:
        raise ValueError('Unsupported input SHA256: '+digest)
    pe=pefile.PE(data=source)
    assert pe.FILE_HEADER.Machine==0x8664
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size==0,'Signed input is not supported'
    assert pe.get_data(ROUTE,0x120)==b'\xcc'*0x120,'Code padding is not pristine'
    assert not any(f.struct.BeginAddress<=ROUTE<f.struct.EndAddress for f in pe.DIRECTORY_ENTRY_EXCEPTION)
    data=bytearray(source)
    changes=[]
    def write(rva,expected,new):
        offset=pe.get_offset_from_rva(rva)
        assert source[offset:offset+len(expected)]==expected,(hex(rva),'unexpected bytes')
        data[offset:offset+len(new)]=new
        changes.append({'rva':hex(rva),'offset':offset,'before':source[offset:offset+len(new)].hex(),'after':new.hex()})

    route=Code(ROUTE)
    route.emit('0f b6 41 52 3c 06')  # current npad style, using only volatile EAX
    route.branch('0f85','right')
    route.emit('80 fa 01')          # Left style: absent Right index
    route.branch('0f84',0x48c940)   # original false/epilogue
    route.branch('e9','pass')
    route.label('right')
    route.emit('3c 07')
    route.branch('0f85','pass')
    route.emit('84 d2')             # Right style: absent Left index
    route.branch('0f84',0x48c940)
    route.label('pass')
    route.emit('44 0f b6 49 58')     # displaced original initialization load
    route.branch('e9',0x48c770)
    route_code=route.finish()
    assert ROUTE+len(route_code)<QUEUE
    write(ROUTE,b'\xcc'*len(route_code),route_code)
    write(0x48c76b,bytes.fromhex('440fb64958'),jump(0x48c76b,ROUTE))

    queue=Code(QUEUE)
    queue.emit('48 8b 86 10 01 00 00 48 83 f8 01')
    queue.branch('0f87',0x7b76a0)   # original Pop/destruction loop
    queue.branch('e9',0x7b7627)     # original one-sample dequeue/send
    queue_code=queue.finish()
    write(QUEUE,b'\xcc'*len(queue_code),queue_code)
    write(0x7b7620,bytes.fromhex('488b8610010000'),jump(0x7b7620,QUEUE,7))
    write(0x7b7688,bytes.fromhex('488b8610010000'),jump(0x7b7688,0x7b7550,7))
    write(0x7b76dc,bytes.fromhex('4883f806'),bytes.fromhex('4883f801'))
    write(0x7b76e2,bytes.fromhex('e969feffff'),jump(0x7b76e2,0x7b7620))

    # The two noncontiguous code fragments execute inside existing stack frames.
    # Register chained unwind records instead of describing them as leaf functions.
    def chained(primary_begin,destination):
        primary=next(f.struct for f in pe.DIRECTORY_ENTRY_EXCEPTION if f.struct.BeginAddress==primary_begin)
        frame=pe.get_data(primary.UnwindData+3,1)[0]
        info=bytes([0x21,0,0,frame])+struct.pack('<III',primary.BeginAddress,primary.EndAddress,primary.UnwindData)
        write(destination,b'\xcc'*16,info)
    chained(0x48c750,ROUTE_UNWIND)
    chained(0x7b7470,QUEUE_UNWIND)
    directory=pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    extra=struct.pack('<III',ROUTE,ROUTE+len(route_code),ROUTE_UNWIND)
    extra+=struct.pack('<III',QUEUE,QUEUE+len(queue_code),QUEUE_UNWIND)
    write(directory.VirtualAddress+directory.Size,b'\0'*len(extra),extra)
    struct.pack_into('<I',data,directory.get_file_offset()+4,directory.Size+len(extra))
    pdata=next(s for s in pe.sections if s.Name.startswith(b'.pdata'))
    struct.pack_into('<I',data,pdata.get_file_offset()+8,directory.Size+len(extra))
    text=pe.sections[0]
    struct.pack_into('<I',data,text.get_file_offset()+8,MARKER_RVA+len(MARKER)-text.VirtualAddress)
    write(MARKER_RVA,b'\xcc'*len(MARKER),MARKER)
    checksum=pefile.PE(data=bytes(data)).generate_checksum()
    struct.pack_into('<I',data,pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),checksum)
    result=bytes(data)
    return result,{'original_sha256':digest,'patched_sha256':hashlib.sha256(result).hexdigest(),
                   'changes':changes,'route_bytes':route_code.hex(),'queue_bytes':queue_code.hex(),
                   'unwind_entries_added':2,'file_size':len(result)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original',type=Path)
    parser.add_argument('destination',type=Path)
    parser.add_argument('--manifest',type=Path)
    args=parser.parse_args()
    paths=[args.original,args.destination]+([args.manifest] if args.manifest else [])
    for i,left in enumerate(paths):
        for right in paths[i+1:]:
            if left.resolve()==right.resolve() or (left.exists() and right.exists() and left.samefile(right)):
                parser.error('Input, destination and manifest must be distinct files')
    result,manifest=patch(args.original.read_bytes())
    args.destination.parent.mkdir(parents=True,exist_ok=True)
    args.destination.write_bytes(result)
    if args.manifest:
        args.manifest.write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in manifest.items() if k not in ['changes','route_bytes','queue_bytes']}))


if __name__=='__main__':
    main()
