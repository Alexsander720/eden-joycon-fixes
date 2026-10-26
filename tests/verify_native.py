"""Execute the actual x64 routing fragments against synthetic controller objects."""
import argparse,ctypes,hashlib,importlib.util,json,struct
from pathlib import Path
import pefile,capstone

ROOT=Path(__file__).resolve().parent
import sys
sys.path.insert(0,str(ROOT.parent))
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source',type=Path,required=True)
parser.add_argument('--candidate',type=Path,required=True)
parser.add_argument('--patcher',type=Path,default=ROOT.parent/'patch_ir.py')
parser.add_argument('--manifest',type=Path,required=True)
parser.add_argument('--report',type=Path,default=Path('local-results/native-check.json'))
args=parser.parse_args()
if sys.platform!='win32' or ctypes.sizeof(ctypes.c_void_p)!=8:
    parser.error('Native tests require Windows x64 Python')
spec=importlib.util.spec_from_file_location('patch_ir',args.patcher)
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
original=args.source.read_bytes()
if hashlib.sha256(original).hexdigest()!=mod.INPUT_SHA:
    import patch_eden
    original,_=patch_eden.patch(original)
candidate=args.candidate.read_bytes();pe=pefile.PE(data=candidate)
assert pe.verify_checksum()
assert len(candidate)==len(original)+1024
assert [f.struct.BeginAddress for f in pe.DIRECTORY_ENTRY_EXCEPTION]==sorted(f.struct.BeginAddress for f in pe.DIRECTORY_ENTRY_EXCEPTION)
assert b'EDEN_RUMBLEFIX_V2\0' in candidate
op=pefile.PE(data=original)
for rva,n in [(0x48c76b,5),(0x210d020,0xf2),(0x7b7620,7),(0x7b7688,7),(0x7b76dc,4),(0x7b76e2,5)]:
    assert pe.get_data(rva,n)==op.get_data(rva,n),f'Rumble regression {rva:x}'

irs=ctypes.create_string_buffer(0x200);system=ctypes.create_string_buffer(8);impl=ctypes.create_string_buffer(0x500)
controllers=[ctypes.create_string_buffer(32) for _ in range(10)]
for index,controller in enumerate(controllers):
    struct.pack_into('<I',controller,0,index)
    struct.pack_into('<Q',impl,0x378+index*8,ctypes.addressof(controller))
struct.pack_into('<Q',irs,0xf0,ctypes.addressof(system));struct.pack_into('<Q',irs,0x110,ctypes.addressof(controllers[0]))
struct.pack_into('<Q',system,0,ctypes.addressof(impl))
k=ctypes.windll.kernel32
k.VirtualAlloc.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint32,ctypes.c_uint32];k.VirtualAlloc.restype=ctypes.c_void_p
k.VirtualFree.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint32]
passed=0;red=0
for site,begin,reg,slot in mod.SITES:
    branch=pe.get_data(site,7);assert branch[0]==0xe9
    target=site+5+struct.unpack_from('<i',branch,1)[0]
    entry=next(f.struct for f in pe.DIRECTORY_ENTRY_EXCEPTION if f.struct.BeginAddress==target)
    raw=pe.get_data(target,entry.EndAddress-target);body=raw[:-5]
    assert raw[-5]==0xe9
    assert entry.EndAddress+struct.unpack_from('<i',raw,len(raw)-4)[0]==site+7
    assert body==mod.route_body(reg,slot)
    for old in (True,False):
        # Save nonvolatile registers; the fragment runs within the parent stack frame.
        prolog=bytes.fromhex('57 55 4881ec28010000 4889cf 488dac2480000000')
        store=(bytes.fromhex('899424')+struct.pack('<I',slot)) if reg=='rsp' else bytes.fromhex('8955')+bytes([slot])
        test_body=bytes.fromhex('488b8f10010000') if old else body
        code=prolog+store+test_body+bytes.fromhex('4889c8 4881c428010000 5d 5f c3')
        memory=k.VirtualAlloc(None,4096,0x3000,0x40);assert memory
        try:
            ctypes.memmove(memory,code,len(code))
            run=ctypes.WINFUNCTYPE(ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint32)(memory)
            for index in range(9):
                actual=run(ctypes.addressof(irs),index)
                expected=ctypes.addressof(controllers[9 if index==8 else index])
                if old:
                    assert actual==ctypes.addressof(controllers[0]);red+=actual!=expected
                else:assert actual==expected,(hex(site),index,actual,expected);passed+=1
        finally:k.VirtualFree(memory,0,0x8000)
assert passed==81 and red==72
reply_cases=0;reply_red=0
for address in (0xbe5edd,0xbe60a3):
    before=op.get_data(address,10);after=pe.get_data(address,10)
    assert before[:3]==after[:3]==bytes.fromhex('803e21')
    assert before[5:8]==after[5:8]==bytes.fromhex('385e0e')
    for raw in (before,after):
        code=bytearray(bytes.fromhex('56534889ce89d3'))
        code.extend(raw[:3]);condition=len(code);code.extend(bytes([raw[3],0]))
        code.extend(raw[5:8]);second=len(code);code.extend(bytes([raw[8],0]))
        accept=len(code);code.extend(bytes.fromhex('b8010000005b5ec3'))
        reject=len(code);code.extend(bytes.fromhex('31c05b5ec3'))
        code[condition+1]=(accept if raw[3]==0x74 else reject)-condition-2
        code[second+1]=reject-second-2
        memory=k.VirtualAlloc(None,4096,0x3000,0x40)
        try:
            ctypes.memmove(memory,bytes(code),len(code));run=ctypes.WINFUNCTYPE(ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32)(memory)
            for report,command in [(0x21,0x21),(0x21,3),(0x31,0x21),(0x31,3)]:
                buf=ctypes.create_string_buffer(64);buf[0]=bytes([report]);buf[14]=bytes([command])
                actual=run(ctypes.addressof(buf),0x21);expected=int(report==0x21 and command==0x21)
                if raw is before:reply_red+=actual!=expected
                else:assert actual==expected;reply_cases+=1
        finally:k.VirtualFree(memory,0,0x8000)
assert reply_cases==8 and reply_red==4

manifest=json.loads(args.manifest.read_text());manifest=manifest['steps'][-1] if 'steps' in manifest else manifest;retry_rva=int(manifest['retry_rva'],16)
entry=next(f.struct for f in pe.DIRECTORY_ENTRY_EXCEPTION if f.struct.BeginAddress==retry_rva)
retry=pe.get_data(retry_rva,entry.EndAddress-retry_rva)
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
driver=ctypes.create_string_buffer(0x40);struct.pack_into('<Q',driver,0x10,ctypes.addressof(irs))
enabled=ctypes.c_uint32();disabled=ctypes.c_uint32();failures=ctypes.c_uint32()
retry_cases=0
memory=k.VirtualAlloc(None,4096,0x3000,0x40)
try:
    prolog=bytes.fromhex('56554881ecb8000000488dac247000000048894df8')
    cleanup=bytes.fromhex('89f04881c4b80000005d5ec3')
    enable_code=b'\x48\xb8'+struct.pack('<Q',ctypes.addressof(enabled))+bytes.fromhex('ff008b08')
    enable_code+=b'\x48\xb8'+struct.pack('<Q',ctypes.addressof(failures))+bytes.fromhex('3b080f96c00fb6c001c0c3')
    disable_code=b'\x48\xb8'+struct.pack('<Q',ctypes.addressof(disabled))+bytes.fromhex('ff0031c0c3')
    retry_offset=len(prolog);cleanup_offset=retry_offset+len(retry);enable_offset=cleanup_offset+len(cleanup);disable_offset=enable_offset+len(enable_code)
    relocated=bytearray(retry)
    for ins in md.disasm(retry,retry_rva):
        if ins.mnemonic not in ('call','je','jne','jmp'):continue
        target=int(ins.op_str,16)
        if retry_rva<=target<entry.EndAddress:dest=memory+retry_offset+(target-retry_rva)
        else:
            mapping={0x91bca0:enable_offset,0x91c530:disable_offset,0x7b7420:cleanup_offset,0x7b7186:cleanup_offset}
            assert target in mapping;dest=memory+mapping[target]
        at=ins.address-retry_rva
        struct.pack_into('<i',relocated,at+ins.size-4,dest-(memory+retry_offset+at+ins.size))
    code=prolog+relocated+cleanup+enable_code+disable_code
    ctypes.memmove(memory,bytes(code),len(code));run=ctypes.WINFUNCTYPE(ctypes.c_int,ctypes.c_void_p)(memory)
    for count in (0,1,2,3,100):
        enabled.value=disabled.value=0;failures.value=count
        result=run(ctypes.addressof(driver))
        assert enabled.value==min(count+1,3) and disabled.value==min(count,3),(count,enabled.value,disabled.value)
        assert result==(2 if count>=3 else 0);retry_cases+=1
finally:k.VirtualFree(memory,0,0x8000)
new_entries=[f.struct for f in pe.DIRECTORY_ENTRY_EXCEPTION if f.struct.BeginAddress>=int(manifest['section_rva'],16)]
assert len(new_entries)==10
for f in new_entries:
    info=pe.get_data(f.UnwindData,16)
    assert info[:3]==bytes([0x21,0,0])
    parent_begin,parent_end,parent_unwind=struct.unpack_from('<III',info,4)
    primary=next(x.struct for x in op.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress==parent_begin)
    assert (parent_end,parent_unwind)==(primary.EndAddress,primary.UnwindData)
    assert info[3]==op.get_data(parent_unwind+3,1)[0]
assert pe.get_data(0x7b76f5,6)==bytes.fromhex('0f8525ffffff')
assert struct.unpack('<I',pe.get_data(0x31ecbc4,4))[0]==5
ip_map_rva=struct.unpack('<I',pe.get_data(0x31ecbc8,4))[0]
assert ip_map_rva==int(manifest['cpp_ip_map_rva'],16)
assert pe.get_data(ip_map_rva,24)==op.get_data(0x31ecbe0,24)
assert pe.get_data(ip_map_rva+24,16)==struct.pack('<IiIi',retry_rva,0,entry.EndAddress,-1)
report={'native_routing_cases_passed':passed,'original_misrouting_cases_reproduced':red,
        'native_reply_cases_passed':reply_cases,'original_invalid_replies_reproduced':reply_red,'native_retry_cases_passed':retry_cases,
        'rumble_fragments_unchanged':True,'checksum_valid':True,'unwind_entries_added':10,
        'candidate_sha256':hashlib.sha256(candidate).hexdigest()}
args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report,indent=2));print(json.dumps(report))
