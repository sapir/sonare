from __future__ import unicode_literals
from capstone import *
from capstone.x86_const import *
from io import StringIO


class X86AsmFormatter:
    SIZE_NAMES = {
            1 : 'byte',
            2 : 'word',
            4 : 'dword',
            8 : 'qword',
        }

    def __init__(self, mainWin, mode64=False):
        self.mainWin = mainWin

        self.cs = Cs(CS_ARCH_X86, CS_MODE_64 if mode64 else CS_MODE_32)
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
        _makeSpan = X86AsmFormatter._makeSpan

        if op.type == X86_OP_REG:
            return _makeSpan("opnd reg", "{}", insn.reg_name(op.reg))

        elif op.type == X86_OP_IMM:
            addrName = self.mainWin.getAddrName(op.imm)
            if addrName is None:
                return _makeSpan("opnd num", "{}", self.mainWin.fmtNum(op.imm))
            else:
                return _makeSpan("opnd ref", "{}", addrName)

        elif op.type == X86_OP_FP:
            return _makeSpan("opnd fp", "fp(?) {}", op.fp)

        elif op.type == X86_OP_MEM:
            mem = op.mem

            output = StringIO()
            output.write('<span class="opnd ptr">')
            output.write(_makeSpan("ptr_size", "{} ",
                X86AsmFormatter.SIZE_NAMES[op.size]))

            if mem.segment:
                output.write(_makeSpan("ptr_seg reg", "{}:",
                    insn.reg_name(mem.segment)))

            output.write(_makeSpan("op", "["))

            ptrParts = []

            if mem.base:
                ptrParts.append(_makeSpan("ptr_base reg", "{}",
                    insn.reg_name(mem.base)))

            if mem.index:
                indexPart = _makeSpan("ptr_index reg", "{}",
                    insn.reg_name(mem.index))

                if mem.scale != 1:
                    indexPart += _makeSpan("op", "*")
                    indexPart += _makeSpan("ptr_scale num", "{}", mem.scale)

                ptrParts.append(indexPart)

            if mem.disp or not ptrParts:
                # don't format 0 as hex
                dispStr = self.mainWin.fmtNum(mem.disp) if mem.disp else '0'
                ptrParts.append(_makeSpan("ptr_disp num", "{}", dispStr))

            partSeparator = _makeSpan("op", "+")
            output.write(partSeparator.join(ptrParts))
            output.write(_makeSpan("op", "]"))

            output.write('</span>')

            return output.getvalue()
