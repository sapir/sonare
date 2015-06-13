from __future__ import print_function
import sys
import os
from collections import deque
from binascii import unhexlify
from xml.sax.saxutils import escape as xmlEscape
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtWebKit import *


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

        self.myTextWidths = [item.document().idealWidth()
            for item in self.items]

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
        w = max(textln.myTextWidths[colIdx] for textln in textLines)

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
    REMEMBERED_LINES = 10


    def __init__(self, mainWin):
        QGraphicsScene.__init__(self)
        self.mainWin = mainWin

        self.setBackgroundBrush(mainWin.WINDOW_COLOR)

        self.font = QFont("Monospace", 8)
        self.lineSpacing = QFontMetricsF(self.font).lineSpacing()

        self.textLines = deque()

        addr = mainWin.getAddr('main')
        item = self._makeLine(0, addr, None)
        self.addItem(item)
        self.textLines.append(item)

    @property
    def curTop(self):
        return self.textLines[0].y()

    @property
    def curBottom(self):
        return self.textLines[-1].y() + self.lineSpacing

    def _makeLine(self, y, addr, asmOp):
        item = TextLineItem(self.mainWin, addr, asmOp, self.font)
        item.setPos(0, y)
        return item

    def setLines(self, top, bottom):
        linesChanged = False

        # add any required lines:

        while self.curTop >= top:
            # add lines upwards
            item = self._makeLine(self.curTop - self.lineSpacing,
                self.textLines[0].addr - 4, None)
            self.addItem(item)
            self.textLines.appendleft(item)

            linesChanged = True

        while self.curBottom <= bottom:
            # add lines downwards
            item = self._makeLine(self.curBottom,
                self.textLines[-1].addr + 4, None)
            self.addItem(item)
            self.textLines.append(item)

            linesChanged = True
            # op = self.mainWin.r2core.disassemble(curAddr)

        # remove extraneous lines:

        rememberedY = self.REMEMBERED_LINES * self.lineSpacing
        while self.curTop < top - rememberedY:
            self.removeItem(self.textLines.popleft())
            linesChanged = True

        while self.curBottom > bottom + rememberedY:
            self.removeItem(self.textLines.pop())
            linesChanged = True


        if linesChanged:
            TextLineItem.updateColWidths(self.textLines)


class SonareTextView(QGraphicsView):
    def __init__(self, mainWin):
        self.scene = SonareTextScene(mainWin)
        QGraphicsView.__init__(self, self.scene)

        self.setRenderHints(
            QPainter.Antialiasing
            | QPainter.TextAntialiasing
            | QPainter.SmoothPixmapTransform
            | QPainter.HighQualityAntialiasing)

    def scrollContentsBy(self, dx, dy):
        QGraphicsView.scrollContentsBy(self, dx, dy)

        sceneViewPoly = self.mapToScene(self.viewport().rect())
        r = sceneViewPoly.boundingRect()
        self.scene.setLines(r.top(), r.bottom())
