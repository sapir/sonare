from __future__ import print_function
import sys
import os
from collections import deque
from binascii import hexlify, unhexlify
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


    def __init__(self, mainWin, addr, size, asmOp, font):
        QGraphicsItemGroup.__init__(self)
        self.mainWin = mainWin

        self.addr = addr
        self.size = size
        self.asmOp = asmOp
        self.font = font

        self.hexBytes = bytearray(
            self.mainWin.core.getBytes(self.addr, self.size))

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

        hexWithSpaces = ' '.join(format(b, '02x') for b in self.hexBytes)
        return '<span class="hex">{}</span>'.format(
            xmlEscape(hexWithSpaces))

    @property
    def htmlAsm(self):
        '''Format op's assembly nicely [as HTML]'''
        if self.asmOp is None:
            return ''

        return self.mainWin.asmFormatter.format(str(self.hexBytes), self.addr)

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
    EXTRA_LINES = 10


    def __init__(self, mainWin):
        QGraphicsScene.__init__(self)
        self.mainWin = mainWin

        self.setBackgroundBrush(mainWin.WINDOW_COLOR)

        self.font = QFont("Monospace", 8)
        self.lineSpacing = QFontMetricsF(self.font).lineSpacing()

        self.textLines = deque()

        self.gotoAddr(0)

    def gotoAddr(self, addr):
        self.clear()        # clear QGraphicsScene
        self.textLines.clear()

        size = self.mainWin.core.nextAddr(addr) - addr
        item = self._makeLine(0, addr, size)
        self.addItem(item)
        self.textLines.append(item)

        # TODO: when >1 view, setLines ranges will conflict
        for v in self.views():
            # TODO: this should be in View code, not here
            v.centerOn(item.x(), item.y())

    @property
    def curTop(self):
        return self.textLines[0].y()

    @property
    def curBottom(self):
        return self.textLines[-1].y() + self.lineSpacing

    def _makeLine(self, y, addr, size):
        asmOp = self.mainWin.core.getAsmOp(addr)
        item = TextLineItem(self.mainWin, addr, size, asmOp, self.font)
        item.setPos(0, y)
        return item

    def setLines(self, top, bottom):
        linesChanged = False

        extraY = self.EXTRA_LINES * self.lineSpacing

        # add any required lines:

        while self.curTop >= top - extraY:
            # add lines upwards
            oldTopAddr = self.textLines[0].addr
            addr = self.mainWin.core.prevAddr(oldTopAddr)
            size = oldTopAddr - addr
            item = self._makeLine(self.curTop - self.lineSpacing, addr, size)
            self.addItem(item)
            self.textLines.appendleft(item)

            linesChanged = True

        while self.curBottom <= bottom + extraY:
            # add lines downwards
            addr = self.textLines[-1].addr + self.textLines[-1].size
            size = self.mainWin.core.nextAddr(addr) - addr
            item = self._makeLine(self.curBottom, addr, size)
            self.addItem(item)
            self.textLines.append(item)

            linesChanged = True
            # op = self.mainWin.r2core.disassemble(curAddr)

        # remove extraneous lines:

        while self.curTop < top - extraY:
            self.removeItem(self.textLines.popleft())
            linesChanged = True

        while self.curBottom > bottom + extraY:
            self.removeItem(self.textLines.pop())
            linesChanged = True


        if linesChanged:
            TextLineItem.updateColWidths(self.textLines)


class SonareTextView(QGraphicsView):
    linesUpdated = pyqtSignal([int, int])

    def __init__(self, mainWin):
        self.scene = SonareTextScene(mainWin)
        QGraphicsView.__init__(self, self.scene)

        self.setRenderHints(
            QPainter.Antialiasing
            | QPainter.TextAntialiasing
            | QPainter.SmoothPixmapTransform
            | QPainter.HighQualityAntialiasing)

        self.linesUpdated.connect(self.scene.setLines)

    def getYRange(self):
        sceneViewPoly = self.mapToScene(self.viewport().rect())
        r = sceneViewPoly.boundingRect()
        return (r.top(), r.bottom())

    def resizeEvent(self, evt):
        QGraphicsView.resizeEvent(self, evt)
        self._emitLinesSignal()

    def scrollContentsBy(self, dx, dy):
        QGraphicsView.scrollContentsBy(self, dx, dy)
        self._emitLinesSignal()

    def _emitLinesSignal(self):
        y0, y1 = self.getYRange()
        self.linesUpdated.emit(y0, y1)

    def gotoAddr(self, addr):
        self.scene.gotoAddr(addr)
