from __future__ import unicode_literals
from capstone import *
from capstone.mips_const import *
from io import StringIO


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

    def _formatOp(self, insn, op):
        _makeSpan = self._makeSpan

        if op.type == MIPS_OP_REG:
            return _makeSpan("opnd reg", "${}", insn.reg_name(op.reg))

        elif op.type == MIPS_OP_IMM:
            addrName = self.mainWin.getAddrName(op.imm)
            if addrName is None:
                return _makeSpan("opnd num", "{:#x}", op.imm)
            else:
                return _makeSpan("opnd ref", "{}", addrName)

        elif op.type == MIPS_OP_MEM:
            mem = op.mem

            output = StringIO()
            output.write('<span class="opnd ptr">')

            # don't format 0 as hex
            dispStr = '{:#x}'.format(mem.disp) if mem.disp else '0'
            output.write(_makeSpan("ptr_disp num", "{}", dispStr))
            output.write(_makeSpan("op", "("))
            output.write(_makeSpan("ptr_base reg", "${}",
                insn.reg_name(mem.base)))
            output.write(_makeSpan("op", ")"))

            output.write('</span>')

            return output.getvalue()
