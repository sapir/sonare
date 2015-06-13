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

    def __init__(self, parent, addr, asmOp, font):
        QGraphicsItemGroup.__init__(self, parent)
        self.textView = parent

        self.addr = addr
        self.asmOp = asmOp
        self.font = font

        self.items = [
            self._makeTextItem(self.htmlAddr),
            self._makeTextItem(self.htmlHex),
            self._makeTextItem(self.htmlAsm),
            ]

        self._updateColWidths()

    @property
    def mainWin(self):
        return self.textView.mainWin

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

    def _updateColWidths(self):
        x = 0
        for item, colWidth in zip(self.items, self.textView.colWidths):
            item.setPos(x, 0)
            x += colWidth


class SonareTextView(QGraphicsItemGroup):
    COLUMN_SPACING = 15

    def __init__(self, mainWin, curAddr):
        QGraphicsItemGroup.__init__(self)
        self.mainWin = mainWin
        self.curAddr = curAddr

        self.font = QFont("Monospace", 8)

        self.numColumns = 3

        # start with a guess
        self.colWidths = [100] * self.numColumns

        op = self.mainWin.r2core.disassemble(self.curAddr)
        self.textLines = [TextLineItem(self, curAddr, op, self.font)]

        # now fix column widths
        self._updateColWidths()

    def _getColWidth(self, colIdx):
        w = max(textln.items[colIdx].document().idealWidth()
                    for textln in self.textLines)

        isLast = (colIdx == self.numColumns - 1)
        if not isLast:
            w += self.COLUMN_SPACING

        return w

    def _updateColWidths(self):
        self.colWidths = [self._getColWidth(i) for i in xrange(self.numColumns)]

        for textln in self.textLines:
            textln._updateColWidths()


class SonareTextScene(QGraphicsScene):
    HORIZ_MARGIN = VERT_MARGIN = 40


    def __init__(self, mainWin):
        QGraphicsScene.__init__(self)
        self.mainWin = mainWin

        self.setBackgroundBrush(mainWin.WINDOW_COLOR)

        view = SonareTextView(mainWin, 0x804841b)
        self.addItem(view)
