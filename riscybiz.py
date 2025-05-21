import binaryninja as bn
from binaryninja import BinaryView, SegmentFlag, Symbol, SymbolType, Architecture
from .riscv import RISCV, RISCV64
from .helper import helper_function

import struct

class RiscyBiz(RISCV64):
    name = "riscy-business"
    load_base = 0x10000
    encryption_key = None
    is_encrypted = False

    def set_enc_from_settings(self):
        if self.encryption_key is None:
            self.is_encrypted = False
            self.encryption_key = None
            enc_key = bn.Settings().get_integer("riscy-business.key")
            if enc_key != 0:
                self.encryption_key = enc_key
                self.is_encrypted = True
            else:
                self.encryption_key = 0xdeadbeef
                self.is_encrypted = True 

    def set_encryption(self,encryption_key:int):
        self.encryption_key = encryption_key
        self.is_encrypted = True
    
    def get_instruction_text(self, data, addr):
        self.set_enc_from_settings()
        data = self.vm_fetch(data, addr-self.load_base)
        tokens, size = super().get_instruction_text(data, addr)
        return tokens, size
    
    def get_instruction_low_level_il(self, data, addr, il):
        self.set_enc_from_settings()
        data = self.vm_fetch(data, addr-self.load_base)
        size = super().get_instruction_low_level_il(data, addr, il)
        return size
    
    def get_instruction_info(self, data, addr):
        self.set_enc_from_settings()
        data = self.vm_fetch(data, addr-self.load_base)
        info = super().get_instruction_info(data, addr)
        return info


    def vm_fetch(self,data,address):
        data = int.from_bytes(data[:4],"little")
        if self.is_encrypted:
            data = data ^ self.transform(address,self.encryption_key)
        data = int.to_bytes(data,4,"little")
        return data

    @staticmethod
    def transform(offset: int, key: int) -> int:
        key2 = key + offset

        data = struct.pack("<I",key2)
        assert len(data) == 4, "Input should be 4 bytes"
        input_val = int.from_bytes(data, 'little')  # Convert bytes to an integer
        prime1 = 0x9E3779B1
        input_val ^= input_val >> 15
        input_val *= prime1
        input_val &= 0xFFFFFFFF
        input_val ^= input_val >> 12
        input_val *= prime1
        input_val &= 0xFFFFFFFF
        input_val ^= input_val >> 4
        input_val *= prime1
        input_val &= 0xFFFFFFFF
        input_val ^= input_val >> 16

        return input_val & 0xFFFFFFFF

def create_header_struct_type(bv):

    struct_type = bn.types.StructureBuilder.create(packed=True)
    struct_type.append(bn.Type.array(bn.Type.int(1), 0x4), 'magic')
    struct_type.append(bn.Type.bool(), 'relocs')
    struct_type.append(bn.Type.array(bn.Type.int(1), 0x4), 'feat_magic')
    # struct_type.append(bn.Type.bool(), 'features')
    enum = bn.EnumerationBuilder.create()
    enum.append("BYTECODE_ENCRYPTED", 0x1)
    enum.append("OPCODES_SHUFFLED", 0x2)

    # Register the enum in the binary view’s type system
    bv.define_user_type("FeatureFlags", bn.Type.enumeration(bv.arch,enum, 1))
    flag_enum = bn.Type.named_type_from_type("FeatureFlags", bn.Type.enumeration(bv.arch,enum, 1))
    struct_type.append(flag_enum, 'feat_flags')
    struct_type.append(bn.Type.int(4,False), 'enc_key')
    return struct_type


class RiscyBizView(BinaryView):
    name = "RiscyBiz"
    long_name = "Riscy Business Bytecode"
    bank = None
    is_encrypted = False
    is_shuffled = False
    encryption_key = None
    load_base = 0x10000
    
    def __init__(self,data:BinaryView):
        BinaryView.__init__(self,parent_view=data,file_metadata=data.file)
        length = data.length
        self.bc_data = data.read(0,length)
        self.parse_bc()
        self.arch = Architecture["riscy-business"]
        self.platform = Architecture["riscy-business"].standalone_platform
        self.data = data

    def parse_bc(self):
        size = len(self.bc_data)
        rela_offset = self.bc_data.rfind(b"RELA")
        if rela_offset == -1:
            print("Could not find RELA section")
            return False
        assert rela_offset == size - 0xe, "Are you sure binary doesn't have null bytes appended at the end?"
        rela_offset += 4
        while self.bc_data[rela_offset] != 0:
            rela = self.bc_data[rela_offset:rela_offset + 13]
            assert len(rela) == 13
            type, offset, addend = struct.unpack("<BIq", rela)
            print(f"Relocation type {type} at offset {hex(offset)} with addend {addend}")
            rela_offset += 13
        needle_offset = rela_offset + 1
        self.parse_features(needle_offset)

    def parse_features(self,needle_offset):
        feature_magic = int.from_bytes(self.bc_data[needle_offset:needle_offset+4],'little')
        if feature_magic != 0x54414546:
            print("Incorrect feature magic")
            return False  
                  
        needle_offset += 4
        features = self.bc_data[needle_offset]
        encrypted, shuffled = False,False

        if features & 0x1 == 1: encrypted = True
        if features & 0x2 == 1: shuffled = True
        self.is_encrypted = encrypted
        self.is_shuffled = shuffled
        print(f"Is encrypted : {encrypted} , Is shuffled opcodes : {shuffled}")
        if encrypted:
            needle_offset += 1
            feature_key = int.from_bytes(self.bc_data[needle_offset:needle_offset+4],"little")
            print(f"Encryption key : {hex(feature_key)}")
            self.encryption_key = feature_key

    @classmethod
    def is_valid_for_data(cls, data:BinaryView) -> bool:
        length = data.length
        bc_data = data.read(0,length)
        rela_offset = bc_data.rfind(b"RELA")
        if rela_offset == -1:
            print("Could not find RELA section")
            return False
        
        rela_offset += 4
        while bc_data[rela_offset] != 0 and rela_offset < length:
            rela = bc_data[rela_offset:rela_offset + 13]
            if len(rela) != 13:
                return False
            type, offset, addend = struct.unpack("<BIq", rela)
            rela_offset += 13
        if rela_offset >= length:
            return False
        needle_offset = rela_offset + 1

        feature_magic = int.from_bytes(bc_data[needle_offset:needle_offset+4],'little')
        if feature_magic != 0x54414546:
            print("Incorrect feature magic")
            return False

        return True
    
    def define_header_struct(self):
        header_struct = create_header_struct_type(self)
        self.define_user_data_var(self.header_segment_offset, header_struct, 'riscyvm_header')


    def on_complete(self):
        # Define structs
        self.define_header_struct()
        print('Initial analysis is completed, calling helper function')
        # Call the helper function
        helper_function(self)

    def init(self)->bool:
        self.add_auto_segment(
			  self.load_base, 0x8000, 0, 0x8000, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable
		)
        
        self.header_segment_offset = self.bc_data.rfind(b"RELA")
        self.add_auto_segment(
            self.header_segment_offset,
            0xe,
            self.header_segment_offset,
            0xe,
            bn.SegmentFlag.SegmentReadable
        )
        self.add_user_section("header", self.header_segment_offset, 0xe,
            bn.SectionSemantics.ReadOnlyDataSectionSemantics)
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.load_base, "_start"))
        self.add_entry_point(self.load_base)
        self.update_analysis()
        bn.AnalysisCompletionEvent(self, self.on_complete)

        return True

    def perform_is_executable(self) -> bool:
        return True

    def perform_get_address_size(self) -> int:
        return 8

    def perform_get_entry_point(self) -> int:
        return 0
