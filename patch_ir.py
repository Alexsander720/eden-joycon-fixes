"""Build the per-camera routing and paused-input fix for an exact rumble-fixed Eden PE.

The input must already contain EDEN_RUMBLEFIX_V2. Never modifies the input file.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
import argparse,hashlib,json,struct
from pathlib import Path
import pefile

INPUT_SHA='04f4dba6deb5cde35f0e1aecde1a3fab1cb6202befac863003ec85e7ebe2a945'
SITES=[
 (0x8f8eae,0x8f8df0,'rsp',0x64), # StopImageProcessor
 (0x8f90ac,0x8f8f00,'rsp',0x7c), # RunMomentProcessor
 (0x8f93e5,0x8f9230,'rsp',0x7c), # RunClusteringProcessor
 (0x8f975e,0x8f9570,'rsp',0x6c), # RunImageTransferProcessor
 (0x8f9d1b,0x8f9b10,'rbp',0x4c), # RunTeraPluginProcessor
 (0x8fa0ee,0x8f9ee0,'rbp',0x4c), # RunPointingProcessor
 (0x8fa68e,0x8fa4a0,'rsp',0x7c), # RunImageTransferExProcessor
 (0x8fa9ab,0x8fa7a0,'rbp',0x4c), # RunIrLedProcessor
 (0x8faade,0x8faa20,'rsp',0x64), # StopImageProcessorAsync
]
MARKER=b'EDEN_IRFIX_V3\0'

def align(n,a):return (n+a-1)//a*a
def jmp(src,dst,n=5):return b'\xe9'+struct.pack('<i',dst-src-5)+b'\x90'*(n-5)

def route_body(register,slot):
    # IRS::system -> System::impl -> HIDCore at +0x378.
    # Index 8 is Handheld, stored after Other in HIDCore's member layout.
    code=bytes.fromhex('488b8ff0000000 488b09')
    code+=bytes.fromhex('0fb64424')+bytes([slot]) if register=='rsp' else bytes.fromhex('0fb645')+bytes([slot])
    code+=bytes.fromhex('83f808 7502 ffc0 488b8cc178030000')
    return code

def patch(source):
    if hashlib.sha256(source).hexdigest()!=INPUT_SHA:
        raise ValueError('Unsupported input SHA256')
    pe=pefile.PE(data=source)
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size==0,'Signed inputs not supported'
    assert b'EDEN_RUMBLEFIX_V2\0' in source
    sa=pe.OPTIONAL_HEADER.SectionAlignment;fa=pe.OPTIONAL_HEADER.FileAlignment
    header=pe.sections[-1].get_file_offset()+40
    assert header+40<=min(s.PointerToRawData for s in pe.sections if s.PointerToRawData)
    assert source[header:header+40]==b'\0'*40
    rva=align(max(s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData) for s in pe.sections),sa)
    offset=align(len(source),fa)
    payload=bytearray();entries=[];manifest=[]
    data=bytearray(source)
    def write(address,expected,new):
        off=pe.get_offset_from_rva(address)
        assert source[off:off+len(expected)]==expected,hex(address)
        data[off:off+len(new)]=new
        manifest.append({'rva':hex(address),'before':source[off:off+len(new)].hex(),'after':new.hex()})
    for site,begin,reg,slot in SITES:
        while len(payload)%16:payload.append(0xcc)
        start=rva+len(payload)
        code=route_body(reg,slot)
        code+=jmp(start+len(code),site+7)
        payload.extend(code)
        while len(payload)%4:payload.append(0xcc)
        unwind=rva+len(payload)
        primary=next(f.struct for f in pe.DIRECTORY_ENTRY_EXCEPTION if f.struct.BeginAddress==begin)
        frame=pe.get_data(primary.UnwindData+3,1)[0]
        payload.extend(bytes([0x21,0,0,frame])+struct.pack('<III',primary.BeginAddress,primary.EndAddress,primary.UnwindData))
        entries.append((start,start+len(code),unwind))
        write(site,bytes.fromhex('488b8f10010000'),jmp(site,start,7))
    # A paused input thread must not send rumble while a protocol owns the HID handle.
    write(0x7b75ca,bytes.fromhex('eb540f1f4000'),jmp(0x7b75ca,0x7b7550,6))
    # Invalid zero-report packets must also pass through the newest-sample prune.
    write(0x7b76f5,bytes.fromhex('0f8531ffffff'),bytes.fromhex('0f8525ffffff'))
    # Accept only a subcommand reply matching the requested command (both inlined copies).
    write(0xbe5ee0,bytes.fromhex('740c'),bytes.fromhex('758e'))
    write(0xbe60a6,bytes.fromhex('7413'),bytes.fromhex('7588'))
    # Retry the complete volatile MCU setup, resetting the MCU between failed attempts.
    while len(payload)%16:payload.append(0xcc)
    retry_start=rva+len(payload);retry=bytearray();fixups=[]
    def emit(h):retry.extend(bytes.fromhex(h))
    def branch(op,target):
        at=len(retry);prefix=bytes.fromhex(op);retry.extend(prefix+b'\0'*4);fixups.append((at,prefix,target))
    emit('c745c803000000');loop=retry_start+len(retry)
    emit('488b45f8488b4810');branch('e8',0x91bca0)
    emit('89c685c0');branch('0f84',0x7b7420)
    emit('488b45f8488b4810');branch('e8',0x91c530)
    emit('ff4dc8');branch('0f85',loop);branch('e9',0x7b7186)
    for at,prefix,dst in fixups:
        retry[at:at+len(prefix)+4]=prefix+struct.pack('<i',dst-(retry_start+at+len(prefix)+4))
    payload.extend(retry)
    while len(payload)%4:payload.append(0xcc)
    unwind=rva+len(payload)
    primary=next(f.struct for f in pe.DIRECTORY_ENTRY_EXCEPTION if f.struct.BeginAddress==0x7b7050)
    frame=pe.get_data(primary.UnwindData+3,1)[0]
    payload.extend(bytes([0x21,0,0,frame])+struct.pack('<III',primary.BeginAddress,primary.EndAddress,primary.UnwindData))
    entries.append((retry_start,retry_start+len(retry),unwind))
    write(0x7b7164,bytes.fromhex('488b4810e8334b1600'),jmp(0x7b7164,retry_start,9))
    # CHAININFO restores the original stack frame. Its C++ scope table also
    # needs the retry call sites so SCOPE_EXIT resets the input pause on throw.
    ip_map_rva=rva+len(payload)
    old_ip_map=bytes.fromhex('50707b00ffffffff7f707b000000000016747b00ffffffff')
    if pe.get_data(0x31ecbe0,24)!=old_ip_map:
        raise ValueError('Unexpected C++ IP-to-state map')
    payload.extend(old_ip_map+struct.pack('<IiIi',retry_start,0,retry_start+len(retry),-1))
    write(0x31ecbc4,struct.pack('<I',3),struct.pack('<I',5))
    write(0x31ecbc8,struct.pack('<I',0x31ecbe0),struct.pack('<I',ip_map_rva))
    payload.extend(MARKER)
    directory=pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    extra=b''.join(struct.pack('<III',*e) for e in entries)
    write(directory.VirtualAddress+directory.Size,b'\0'*len(extra),extra)
    struct.pack_into('<I',data,directory.get_file_offset()+4,directory.Size+len(extra))
    pdata=next(s for s in pe.sections if s.Name.startswith(b'.pdata'))
    struct.pack_into('<I',data,pdata.get_file_offset()+8,directory.Size+len(extra))
    virtual_size=len(payload);raw_size=align(virtual_size,fa)
    section=struct.pack('<8sIIIIIIHHI',b'.irfix\0\0',virtual_size,rva,raw_size,offset,0,0,0,0,0x60000020)
    data[header:header+40]=section
    struct.pack_into('<H',data,pe.FILE_HEADER.get_field_absolute_offset('NumberOfSections'),pe.FILE_HEADER.NumberOfSections+1)
    struct.pack_into('<I',data,pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfImage'),align(rva+virtual_size,sa))
    struct.pack_into('<I',data,pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfCode'),pe.OPTIONAL_HEADER.SizeOfCode+raw_size)
    data.extend(b'\0'*(offset-len(data)));data.extend(payload);data.extend(b'\0'*(raw_size-virtual_size))
    checksum=pefile.PE(data=bytes(data)).generate_checksum()
    struct.pack_into('<I',data,pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),checksum)
    result=bytes(data)
    return result,{'input_sha256':INPUT_SHA,'patched_sha256':hashlib.sha256(result).hexdigest(),
                   'section_rva':hex(rva),'retry_rva':hex(retry_start),'cpp_ip_map_rva':hex(ip_map_rva),'changes':manifest,'unwind_entries_added':len(entries),
                   'file_size':len(result),'scope':'per-camera routing; HID pause; strict replies; three MCU attempts'}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('destination',type=Path);p.add_argument('--manifest',type=Path)
    a=p.parse_args()
    paths=[a.source,a.destination]+([a.manifest] if a.manifest else [])
    for i,left in enumerate(paths):
        for right in paths[i+1:]:
            if left.resolve()==right.resolve() or (left.exists() and right.exists() and left.samefile(right)):
                p.error('Input, destination and manifest must be distinct files')
    data,manifest=patch(a.source.read_bytes());a.destination.parent.mkdir(parents=True,exist_ok=True);a.destination.write_bytes(data)
    if a.manifest:a.manifest.write_text(json.dumps(manifest,indent=2))
    print(json.dumps({k:v for k,v in manifest.items() if k!='changes'}))

if __name__=='__main__':main()
