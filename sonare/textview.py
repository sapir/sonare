from __future__ import print_function
import sys
import os
from binascii import unhexlify
from xml.sax.saxutils import escape as xmlEscape
from PySide.QtCore import *
from PySide.QtGui import *
from PySide.QtWebKit import *


class TextLineItem(QGraphicsItemGroup):
    STYLE_SHEET = '''
        .hex                { color: #EEBA6B; }
        .ptr_size           { color: #B5D3DD; font-style: italic; }
        .addr, .num         { color: #7FEC91; }

        .label, .ref        { color: #D8D8D8; font-weight: bold; }
        .hex, .op           { color: #D8D8D8; }
        .mnem               { color: #ECDE17; }
        .reg                { color: #E96976; }
        '''

    NUM_COLUMNS = 3
    COLIDX_ADDR, COLIDX_HEX, COLIDX_ASM = range(NUM_COLUMNS)

    COLUMN_SPACING = 15


    def __init__(self, mainWin, addr, asmOp, font):
        QGraphicsItemGroup.__init__(self)
        self.mainWin = mainWin

        self.addr = addr
        self.asmOp = asmOp
        self.font = font

        self.items = [
            self._makeTextItem(self.htmlAddr),
            self._makeTextItem(self.htmlHex),
            self._makeTextItem(self.htmlAsm),
            ]
        assert len(self.items) == self.NUM_COLUMNS

        # default column width, should be overridden later with updateColWidths
        for i, item in enumerate(self.items):
            item.setPos(i * 100, 0)

    def _makeTextItem(self, html):
        item = QGraphicsTextItem(self)
        item.setFont(self.font)
        doc = item.document()
        doc.setDefaultStyleSheet(self.STYLE_SHEET)
        doc.setHtml(html)
        return item

    @property
    def htmlAddr(self):
        '''Address, formatted nicely as HTML'''
        return '<span class="addr">{}</span>'.format(
            xmlEscape(self.mainWin.fmtNum(self.addr)))

    @property
    def htmlHex(self):
        '''Add spaces between hex chars, format nicely as HTML'''

        if self.asmOp is None:
            return ''

        hexstring = self.asmOp.get_hex()
        assert len(hexstring) % 2 == 0
        hexWithSpaces = ' '.join(
            hexstring[i:i+2]
            for i in xrange(0, len(hexstring), 2))
        return '<span class="hex">{}</span>'.format(
            xmlEscape(hexWithSpaces))

    @property
    def htmlAsm(self):
        '''Format op's assembly nicely [as HTML]'''
        if self.asmOp is None:
            return ''

        return self.mainWin.asmFormatter.format(
            unhexlify(self.asmOp.get_hex()), self.addr)

    @staticmethod
    def _getColWidth(colIdx, textLines):
        w = max(textln.items[colIdx].document().idealWidth()
                    for textln in textLines)

        isLast = (colIdx == TextLineItem.NUM_COLUMNS - 1)
        if not isLast:
            w += TextLineItem.COLUMN_SPACING

        return w

    @staticmethod
    def updateColWidths(textLines):
        colWidths = [TextLineItem._getColWidth(i, textLines)
            for i in xrange(TextLineItem.NUM_COLUMNS)]

        x = 0
        for i, w in enumerate(colWidths):
            for textln in textLines:
                textln.items[i].setPos(x, 0)

            x += w


class SonareTextScene(QGraphicsScene):
    HORIZ_MARGIN = VERT_MARGIN = 40


    def __init__(self, mainWin):
        QGraphicsScene.__init__(self)
        self.mainWin = mainWin

        self.setBackgroundBrush(mainWin.WINDOW_COLOR)

        self.font = QFont("Monospace", 8)
        self.lineSpacing = QFontMetricsF(self.font).lineSpacing()

        curAddr = 0x804841b
        op = self.mainWin.r2core.disassemble(curAddr)
        self.textLines = [TextLineItem(mainWin, curAddr, None, self.font)]
        TextLineItem.updateColWidths(self.textLines)

        for textln in self.textLines:
            self.addItem(textln)
