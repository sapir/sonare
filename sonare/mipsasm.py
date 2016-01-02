from __future__ import unicode_literals
from capstone import *
from capstone.mips_const import *
from io import StringIO


OFFSET_GP_GOT = 0x7ff0


class MipsAsmFormatter:
    def __init__(self, mainWin, bigEndian=True, mode64=False):
        self.mainWin = mainWin

        mode = 0
        if bigEndian:
            mode |= CS_MODE_BIG_ENDIAN

        if mode64:
            mode |= CS_MODE_64
        else:
            mode |= CS_MODE_32

        self.cs = Cs(CS_ARCH_MIPS, mode)
        self.cs.detail = True

    @staticmethod
    def _makeSpan(classAttr, textFmtStr, *args):
        return '<span class="{}">{}</span>'.format(
            classAttr, textFmtStr.format(*args))

    def format(self, codeBytes, addr):
        fmtdInsns = []

        opndSeparator = self._makeSpan("op", ",&nbsp;")

        for insn in self.cs.disasm(codeBytes, addr):
            mnem = self._makeSpan("mnem", "{}", insn.mnemonic)

            ops = opndSeparator.join(
                self._formatOp(insn, op) for op in insn.operands)

            fmtdInsns.append('<div class="insn">{} {}</div>'.format(mnem, ops))

        return '\n'.join(fmtdInsns)

    def _formatOpNum(self, val):
        addrName = self.mainWin.getAddrName(val)
        if addrName is None:
            return self._makeSpan("opnd num", "{}", self.mainWin.fmtNum(val))
        else:
            return self._makeSpan("opnd ref", "{}", addrName)

    def _formatOp(self, insn, op):
        _makeSpan = self._makeSpan

        if op.type == MIPS_OP_REG:
            return _makeSpan("opnd reg", "${}", insn.reg_name(op.reg))

        elif op.type == MIPS_OP_IMM:
            return self._formatOpNum(op.imm)

        elif op.type == MIPS_OP_MEM:
            mem = op.mem

            if mem.base == MIPS_REG_GP:
                got = self.mainWin.core.getAddr('section..got')
                if got:
                    # based on
                    # https://www.cr0.org/paper/mips.elf.external.resolution.txt
                    # TODO: (but there's more stuff there that isn't
                        # implemented yet)
                    addr = got + OFFSET_GP_GOT + mem.disp
                    # TODO: this assumes that it's a lw insn
                    # TODO 2: in this case, we should convert insn to li/la
                    val = self.mainWin.core.getWord(addr)
                    return _makeSpan("op", "&") + self._formatOpNum(val)

            output = StringIO()
            output.write('<span class="opnd ptr">')

            # don't format 0 as hex
            dispStr = self.mainWin.fmtNum(mem.disp) if mem.disp else '0'
            output.write(_makeSpan("ptr_disp num", "{}", dispStr))
            output.write(_makeSpan("op", "("))
            output.write(_makeSpan("ptr_base reg", "${}",
                insn.reg_name(mem.base)))
            output.write(_makeSpan("op", ")"))

            output.write('</span>')

            return output.getvalue()
