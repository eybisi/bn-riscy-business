from binaryninja import *
from .dll_exports import ws32_exports, kernel32_exports, ntdll_exports, advapi32_exports, user32_exports

def process_riscvm_imports(bv, func):
    """
    0000156c        void* a0 = sub_60(0x536cd652)
    00001588        int64_t zero
    00001588        data_2040 = sub_b4(a0, 0xb23cae4, zero)
    000015a0        data_2048 = sub_b4(a0, 0x3defdc66, zero)
    000015b8        data_2050 = sub_b4(a0, 0x1a0d151b, zero)
    000015d0        data_2058 = sub_b4(a0, -0x275beae9, zero)
    000015e8        data_2060 = sub_b4(a0, -0x413724f9, zero)
    00001600        data_2068 = sub_b4(a0, -0x344ca545, zero)
    00001618        data_2070 = sub_b4(a0, 0x5e173207, zero)
    Process function calls and rename variables to known function names.
    ASSIGN_CALL is when return value is assigned to a variable
    But maybe binary ninja didnt set return value for this function, 
    if so first correct the function then rename the variables
    """
    print(f"Processing risvm_imports function: {func.name} at {hex(func.start)}")
    count = 0
    constants = []
    dll_names = []
    for block in func.hlil:
        for instr in block:
            # Check if the instruction is a call
            if (instr.operation == HighLevelILOperation.HLIL_ASSIGN or instr.operation == HighLevelILOperation.HLIL_VAR_INIT) and instr.src.operation == HighLevelILOperation.HLIL_CALL:
                call_expr = instr.src
                for arg in call_expr.params:
                    if arg.operation in [HighLevelILOperation.HLIL_CONST, HighLevelILOperation.HLIL_CONST_PTR]:
                        called_func = bv.get_function_at(call_expr.dest.constant)
                        if arg.constant == 0x536cd652 or arg.constant == -0xb97a82c:
                            called_func.name = "riscvm_resolve_dll"
                            if arg.constant == 0x536cd652 or arg.constant == -0x275beae9:
                                instr.dest.name = "kernel32_base"
                            if arg.constant == -0xb97a82c or arg.constant == 0xf46857d4:
                                instr.dest.name = "ntdll_base"
                        else:
                            called_func.name = "riscvm_resolve_import"
                            dll,name = find_export_by_hash(arg.constant)
                            if dll and name:
                                print(f"Found DLL: {dll}, Name: {name} : {instr.dest}")
                                if instr.operation == HighLevelILOperation.HLIL_VAR_INIT:
                                    instr.dest.name = name
                                else:
                                    ptr = instr.dest.src
                                    if ptr.operation == HighLevelILOperation.HLIL_CONST_PTR:
                                        print(f"Found constant pointer: {ptr.constant}")
                                        var = bv.get_data_var_at(ptr.constant)
                                        var.name = name
                                        rename_caller_function(var)
                            else:
                                print(f"Unknown hash: {hex(arg.constant)}")
            if instr.operation == HighLevelILOperation.HLIL_ASSIGN or instr.operation == HighLevelILOperation.HLIL_VAR_INIT:
                call_expr = instr.src
                if ".dll" in str(call_expr):
                    dll_names.append(str(call_expr)[1:-1])
    print(f"Constants: {constants}")
    print(f"DLL Names: {dll_names}")



def rename_caller_function(var):
    # Find references to variable
    # check if there is one call in the function
    # which is syscall_host_call that calls this function
    # rename the function at reference with the name
    # sys_name
    print("Checking for references to variable:", var.name)
    for code_ref in var.code_refs:
        ref_func = code_ref.function
        if ref_func.name == "riscvm_imports":
            continue
        print(f"Found reference in function: {ref_func.name} at {hex(ref_func.start)}")
        bad_func = False
        found_sys_host_call = False
        for block in ref_func.hlil:
            for instr in block:
                if instr.operation == HighLevelILOperation.HLIL_RET:
                    target = instr.src
                    target = target[0]
                    if target.operation == HighLevelILOperation.HLIL_CALL:
                        if str(target.dest) == "syscall_host_call":
                            found_sys_host_call = True
                            print(f"Found syscall_host_call in function: {ref_func.name} at {hex(ref_func.start)}")
                        else:
                            bad_func = True
        if not bad_func and found_sys_host_call:
            ref_func.name = f"{var.name}"
            print(f"Renaming {ref_func.name} at {hex(ref_func.start)} to caller_{var.name}")


def hash_x65599(s: str) -> int:
    hash_value = 0
    for c in s:
        hash_value = ord(c) + (hash_value * 65599)
    return hash_value & 0xFFFFFFFF  # Often hashed values are truncated to 32 bits

def find_export_by_hash(hash):
    hash_n = 0xffffffff + hash + 1
    for f in ws32_exports:
        if hash_x65599(f) == hash or hash_x65599(f) == hash_n:
            return "ws32.dll",f
    for f in kernel32_exports:
        if hash_x65599(f) == hash or hash_x65599(f) == hash_n:
            return "kernel32.dll",f
    for f in ntdll_exports:
        if hash_x65599(f) == hash or hash_x65599(f) == hash_n:
            return "ntdll.dll",f
    for f in advapi32_exports:
        if hash_x65599(f) == hash or hash_x65599(f) == hash_n:
            return "advapi32.dll",f
    for f in user32_exports:
        if hash_x65599(f) == hash or hash_x65599(f) == hash_n:
            return "user32.dll",f
    return None, None

def get_disassembly_of_function(func):
    disas_lines = []
    for block in func.basic_blocks:
        for instr in block:
            inst_str = "".join([str(op) for op in instr[0]])
            disas_lines.append(inst_str)
    return disas_lines

def rename_calls_in_start(bv, func):
    print(f"Processing function: {func.name} at {hex(func.start)}")
    # https://github.com/thesecretclub/riscy-business/blob/e3bf776561b33469d2ee22b43a07437bdb912102/riscvm/lib/crt0.c#L8-L9
    func_names = [
        "riscvm_relocs",
        "riscvm_imports",
        "riscvm_init_arrays",
        "main",
        "exit",
    ]
    count = 0
    for block in func.hlil:
        for instr in block:
            # Check if the instruction is a call
            if instr.operation == HighLevelILOperation.HLIL_CALL:
                target = instr.dest
                # Direct call to a known function (not indirect through a register)
                if target.operation == HighLevelILOperation.HLIL_CONST_PTR:
                    addr = target.constant
                    called_func = bv.get_function_at(addr)
                    if called_func:
                        if count < len(func_names):
                            new_name = func_names[count]
                            print(f"Renaming {called_func.name} at {hex(addr)} to {new_name}")
                            called_func.name = new_name
                            count += 1

def helper_function(bv):
    exit_insn = ["lui     a1, 0x2","addiw   a7, a1, 0x710","ecall  ","ret    "]
    syscall_host_call = ["lui     a2, 0x5","addiw   a7, a2, -0x1e0","ecall  ","ret    "]
    syscall_get_peb = ["lui     a0, 0x5","addiw   a7, a0, -0x1df","mv      a0, zero","ecall  ","ret    "]
    memset = ['beqz    a2, 0x18', 'ret    ', 'add     a2, a0, a2', 'mv      a3, a0', 'sb      a1, a3', 'addi    a3, a3, 0x1', 'bne     a3, a2, -0x8']
    memcpy = ['beqz    a2, 0x20', 'ret    ', 'add     a2, a0, a2', 'mv      a3, a0', 'lbu     a4, a1', 'sb      a4, a3', 'addi    a3, a3, 0x1', 'addi    a1, a1, 0x1', 'bne     a3, a2, -0x10']
    for f in bv.functions:
        disas = get_disassembly_of_function(f)
        if disas == exit_insn:
            print(f"Found exit function at {hex(f.start)}")
            types,func_name = bv.parse_type_string('int64_t exit(int64_t arg1)')
            f.type = types
            f.name = str(func_name)
        if disas == syscall_host_call:
            print(f"Found syscall_host_call function at {hex(f.start)}")
            types,func_name = bv.parse_type_string('int64_t syscall_host_call(int64_t arg1, int64_t (& arg2)[0xd])')
            f.type = types
            f.name = str(func_name)
        if disas == syscall_get_peb:
            print(f"Found syscall_get_peb function at {hex(f.start)}")
            types,func_name = bv.parse_type_string('int64_t syscall_get_peb()')
            f.type = types
            f.name = func_name
        if disas == memset:
            print(f"Found memset function at {hex(f.start)}")
            types,func_name = bv.parse_type_string('void riscvm_memset(void* dest, int64_t ch, int64_t count)')
            f.type = types
            f.name = str(func_name)
        if disas == memcpy:
            print(f"Found memcpy function at {hex(f.start)}")
            types,func_name = bv.parse_type_string('void riscvm_memcpy(void* dest, void* src, int64_t count)')
            f.type = types
            f.name = str(func_name)
    start_func = bv.get_function_at(0x0)  # Replace with the actual start address of your function
    if start_func:
        rename_calls_in_start(bv, start_func)
    else:
        print("Could not find start function")
    import_fn = bv.get_functions_by_name("riscvm_imports")
    if import_fn:
        process_riscvm_imports(bv, import_fn[0])
    else:
        print("Could not find riscv_imports function")