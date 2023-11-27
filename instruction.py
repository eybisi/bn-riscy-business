# Copyright 2020 Katharina Utz <katharina.utz@stud.uni-due.de>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import capstone
from capstone import (CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCV64,
                      CS_MODE_RISCVC)
from capstone.riscv import RISCV_OP_IMM, RISCV_OP_MEM, RISCV_OP_REG, RISCVOp

from typing import List

from binaryninja import InstructionTextToken, InstructionTextTokenType, log_warn

_OFFSET = {
    'beq', 'beqz', 'bne', 'bnez', 'bge', 'blez', 'bgez', 'blt', 'bltz', 'bgtz',
    'bltu', 'bgeu', 'jal', 'jalr', 'j', 'jr'
}
_OFFSET.update(["c." + bi for bi in _OFFSET if not bi.startswith('c.')])


class RVInstruction:
    __slots__ = 'address', 'size', 'name', 'op_str', 'operands', 'imm', 'imm_val', '_cs_inst'

    def __init__(self, address : int, size: int, name: str, op_str: str, operands: List[str], imm: int, imm_val: bool):
        self.address = address
        self.size = size
        self.name = name
        self.op_str = op_str
        self.operands = operands
        self.imm = imm
        self.imm_val = imm_val
        self._cs_inst = None

    def __repr__(self):
        return f"RVInstruction({self.address!r}, {self.size!r}, {self.name!r}, {self.op_str!r}, {self.operands!r}, {self.imm!r}, {self.imm_val!r})"


class RVDisassembler:
    """
    Wraps a RISC-V disassembler
    """
    def __init__(self, mode):
        if mode == 4:
            self._mode = CS_MODE_RISCV32
        elif mode == 8:
            self._mode = CS_MODE_RISCV64

        # we enable RISC-V compressed ISA extension by default
        self._mode |= CS_MODE_RISCVC

        # initialize capstone
        self._md = capstone.Cs(CS_ARCH_RISCV, self._mode)
        # enabled capstone detailed mode
        self._md.detail = True

    def decode(self, data, addr):
        op_str = ""
        imm = 0
        operands: List[str] = []

        try:
            insn = next(self._md.disasm(data, addr, count=1))
        except StopIteration:
            return None
        size: int = insn.size
        name: str = insn.mnemonic
        imm_val = False

        if len(insn.operands) > 0:
            for i in insn.operands:
                i: RISCVOp = i
                if i.type == RISCV_OP_REG:
                    op_str += f" {insn.reg_name(i.value.reg)}"
                    operands.append(insn.reg_name(i.value.reg))
                elif i.type == RISCV_OP_IMM:
                    imm: int = i.value.imm
                    imm_val = True
                elif i.type == RISCV_OP_MEM:
                    if i.mem.base != 0:
                        op_str += f" {insn.reg_name(i.mem.base)}"
                        operands.append(insn.reg_name(i.mem.base))

                    if i.mem.disp != 0:
                        imm: int = i.mem.disp
                        imm_val = True
                else:
                    log_warn(
                        f"[RISC-V] unhandled capstone instruction type {i.type!r} (while disassembling {name})"
                    )

        return RVInstruction(insn.address, size, name, op_str, operands, imm,
                             imm_val)


def gen_token(instr: RVInstruction):
    tokens = [
        InstructionTextToken(InstructionTextTokenType.InstructionToken,
                             "{:6} ".format(instr.name))
    ]
    operands = instr.operands

    for i, reg in enumerate(operands):
        tokens.append(
            InstructionTextToken(InstructionTextTokenType.TextToken, " " if i == 0 else ", "))
        tokens.append(
            InstructionTextToken(InstructionTextTokenType.RegisterToken, reg))

    if instr.imm_val:
        tokens.append(
            InstructionTextToken(InstructionTextTokenType.TextToken, ", "))

        if instr.name in _OFFSET:
            # val = instr.address + instr.imm
            val = instr.imm
            tokens.append(
                InstructionTextToken(
                    InstructionTextTokenType.PossibleAddressToken,
                    hex(val),
                    value=val))
        else:
            tokens.append(
                InstructionTextToken(InstructionTextTokenType.IntegerToken,
                                     hex(instr.imm),
                                     value=instr.imm))

    return tokens
