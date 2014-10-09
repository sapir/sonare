from __future__ import print_function
import sys
import os
import networkx
import itertools
from binascii import unhexlify
from xml.sax.saxutils import escape as xmlEscape
from HTMLParser import HTMLParser
from mako.template import Template
from PySide.QtCore import *
from PySide.QtGui import *
from PySide.QtWebKit import *
import main


BAD_ADDR = 0xffffffffffffffff
R_ANAL_OP_TYPE_COND  = 0x80000000
R_ANAL_OP_TYPE_JMP   = 1        # mandatory jump
R_ANAL_OP_TYPE_UJMP  = 2        # unknown jump (register or so)
R_ANAL_OP_TYPE_CJMP  = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_JMP     # conditional jump
R_ANAL_OP_TYPE_UCJMP = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_UJMP        # conditional unknown jump
R_ANAL_OP_TYPE_CALL  = 3        # call to subroutine (branch+link)
R_ANAL_OP_TYPE_UCALL = 4        # unknown call (register or so)
R_ANAL_OP_TYPE_CCALL = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_CALL        # conditional call to subroutine
R_ANAL_OP_TYPE_UCCALL= R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_UCALL       # conditional unknown call
R_ANAL_OP_TYPE_RET   = 5        # returns from subroutine
R_ANAL_OP_TYPE_CRET  = R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_RET     # conditional return from subroutine


def isEndBlockOp(op):
    return ((op.type & 0xffffffff) & ~R_ANAL_OP_TYPE_COND) in [
        R_ANAL_OP_TYPE_JMP, R_ANAL_OP_TYPE_UJMP, R_ANAL_OP_TYPE_RET]

def normalizeAddr(addr):
    if addr in (0, BAD_ADDR):
        return None
    else:
        return addr

def pointListToPairs(points):
    return zip(points, points[1:])

def pointListToLines(points):
    return (QLineF(p1, p2) for (p1, p2) in pointListToPairs(points))

def chainPointLists(pointLists):
    # check that each list ends with the starting point of the next list
    assert all(pl1[-1] == pl2[0]
        for (pl1, pl2)
        in zip(pointLists, pointLists[1:]))

    return reduce(
        lambda pl1, pl2: pl1[:-1] + pl2,
        pointLists)

def rectCorners(rect):
    return [rect.topLeft(), rect.topRight(),
        rect.bottomRight(), rect.bottomLeft()]

def rectLines(rect):
    corners = rectCorners(rect)
    return pointListToLines(corners + [corners[-1]])

def isEmptyIterable(iterable):
    for _ in iterable:
        return False

    return True


class MLStripper(HTMLParser):
    '''http://stackoverflow.com/questions/753052'''
    def __init__(self):
        self.reset()
        self.fed = []
    def handle_data(self, d):
        self.fed.append(d)
    def get_data(self):
        return ''.join(self.fed)

def stripHtmlTags(html):
    """strip HTML tags from a string (not secure)"""
    s = MLStripper()
    s.feed(html)
    return s.get_data()


class EdgeItem(QGraphicsPathItem):
    EDGE_WIDTH = 1.5
    REVERSE_EDGE_WIDTH = 3

    ARROW_PEN_COLOR = QColor(20, 20, 20)

    COLORS_BY_TYPE = {
            'jump': Qt.gray,
            'ok':   Qt.green,
            'fail': Qt.red,
        }

    '''spacing between ok/fail edges for a conditional branch'''
    COND_EDGE_SPACING = 20

    '''
    amount that edge must leave block with a straight vertical line
    before travelling to other block
    '''
    MIN_VERT_LENGTH = 15

    EPSILON = 0.5


    def __init__(self, type_, block1Addr, block2Addr, parent):
        '''type can be "jump", "ok" or "fail".'''

        QGraphicsPathItem.__init__(self, parent)
        self.type_ = type_
        self.block1Addr = block1Addr
        self.block2Addr = block2Addr

        self._updatePen()

        self.arrow = self._makeArrow()

    @property
    def color(self):
        return self.COLORS_BY_TYPE[self.type_]

    @property
    def edgeWidth(self):
        if self.path() is None or self.path().elementCount() < 2:
            return self.EDGE_WIDTH

        firstElem = self.path().elementAt(0)
        assert firstElem.isMoveTo()

        lastElem = self.path().elementAt(self.path().elementCount() - 1)
        assert lastElem.isLineTo()

        isReverse = (lastElem.y < firstElem.y)
        return self.REVERSE_EDGE_WIDTH if isReverse else self.EDGE_WIDTH

    @property
    def _lastLine(self):
        path = self.path()

        elemCnt = path.elementCount()
        if elemCnt < 2:
            return None

        # note each elem can be either move to/line to/curve to
        assert not path.elementAt(elemCnt - 1).isMoveTo()
        return QLineF(
            QPointF(path.elementAt(elemCnt - 2)),
            QPointF(path.elementAt(elemCnt - 1)))

    def setEdgePath(self, path):
        ppath = QPainterPath()

        ppath.moveTo(*path[0])
        for pt in path[1:]:
            ppath.lineTo(*pt)

        self.setPath(ppath)

        self._updateArrowPos()
        self._updatePen()

    def _updatePen(self):
        pen = QPen(self.color, self.edgeWidth)
        pen.setCapStyle(Qt.FlatCap)
        self.setPen(pen)

    def _makeArrow(self):
        # right side of arrow is at (0,0)
        # this will be the end of the line
        pts = [QPointF(-10, -4.5), QPointF(0, 0), QPointF(-10, 4.5)]
        poly = QPolygonF(pts)

        # slightly move triangle so that it covers wide edge widths
        poly.translate(2, 0)

        polyItem = QGraphicsPolygonItem(poly, self)
        polyItem.setPen(QPen(self.ARROW_PEN_COLOR))
        polyItem.setBrush(self.color)
        return polyItem

    def _updateArrowPos(self):
        line = self._lastLine
        self.arrow.setPos(line.p2())
        self.arrow.setRotation(-line.angle())


class MyBlock(object):
    def __init__(self, r2core, ops, endOp):
        '''(endOp causes the end of the block, but might not be the
            last op due to delay slots)'''

        self.r2core = r2core
        self.ops = ops
        self.endOp = endOp

    @property
    def addr(self):
        return self.ops[0].addr

    @property
    def jump(self):
        return normalizeAddr(self.endOp.jump)

    @property
    def fail(self):
        return normalizeAddr(self.endOp.fail)

    @property
    def asmOps(self):
        for op in self.ops:
            addr = op.addr
            asmOp = self.r2core.disassemble(addr)
            assert asmOp is not None, \
                "Couldn't disassemble @ {:#x}".format(addr)
            yield (addr, asmOp)

        # addr = self.r2block.addr
        # endAddr = addr + self.r2block.size

        # while addr < endAddr:
        #     op = self.r2core.disassemble(addr)
        #     yield (addr, op)

        #     addr += op.size

    @property
    def labelName(self):
        return 'blk_{0:x}'.format(self.addr)

    @staticmethod
    def _makeMyBlockAt(r2core, addr):
        ops = []
        endOp = None

        opsLeft = -1
        while opsLeft != 0:
            op = r2core.op_anal(addr)
            ops.append(op)

            if isEndBlockOp(op):
                endOp = op
                # +1 including this one
                opsLeft = op.delay + 1

            addr += op.size
            if opsLeft > 0:
                opsLeft -= 1

        return MyBlock(r2core, ops, endOp)

    @staticmethod
    def _makeFuncBlocks(r2core, funcAddr):
        visited = set()

        todo = set([funcAddr])
        while todo:
            cur = todo.pop()
            if cur in visited:
                continue

            visited.add(cur)

            mb = MyBlock._makeMyBlockAt(r2core, cur)
            yield mb

            if mb.jump:
                todo.add(mb.jump)

            if mb.fail:
                todo.add(mb.fail)


# TODO: use a QWebView directly instead of QGraphicsScene
class SonareGraphScene(QGraphicsScene):
    GRAPHVIZ_SCALE_FACTOR = 72.

    HORIZ_MARGIN = VERT_MARGIN = 40


    def __init__(self, mainWin):
        QGraphicsScene.__init__(self)

        self.setBackgroundBrush(mainWin.WINDOW_COLOR)

        self.mainWin = mainWin

        self.clear()

    def clear(self):
        QGraphicsScene.clear(self)

        self.funcAddr = self.myBlocks = self.myBlocksByAddr = \
            self.blockGraph = self.edgeItems = None

    def loadFunc(self, funcAddr):
        if funcAddr == self.funcAddr:
            return

        self.clear()

        self.funcAddr = funcAddr

        self._makeBlockGraph()
        self._makeGraphItem()
        self._makeEdgeItemsFromGraph()
        self._layoutBlockGraph()

    @property
    def blockAddrs(self):
        return (b.addr for b in self.myBlocks)

    def _makeBlockGraph(self):
        # r2blocks = self.func.get_bbs()
        # self.graphBlocks = [
        #     GraphBlock(self.mainWin, r2b)
        #     for r2b in r2blocks]
        self.myBlocks = list(
            MyBlock._makeFuncBlocks(self.mainWin.r2core, self.funcAddr))

        self.myBlocksByAddr = dict((b.addr, b) for b in self.myBlocks)

        self.blockGraph = networkx.DiGraph()
        for b in self.myBlocks:
            self.blockGraph.add_node(b.addr)

            if b.fail is not None:
                self.blockGraph.add_edge(b.addr, b.fail, type='fail')

            if b.jump is not None:
                type_ = 'jump' if b.fail is None else 'ok'
                self.blockGraph.add_edge(b.addr, b.jump, type=type_)

    def _getBlockElementID(self, blockAddr):
        return 'b{:08x}'.format(blockAddr)

    def _blockElementIDToAddr(self, elemID):
        assert elemID[0] == 'b'
        return int(elemID[1:], 16)

    def _parseCssSize(self, cssSize):
        assert cssSize.endswith('px'), \
            "Don't know how to parse {0!q}".format(cssSize)
        return float(cssSize[:-2])

    def _getBlockSize(self, blockAddr):
        elem = self.blockElements[blockAddr]
        return elem.geometry().size()

    def _getBlockRect(self, blockAddr):
        elem = self.blockElements[blockAddr]

        xStr = elem.styleProperty("left", QWebElement.ComputedStyle)
        yStr = elem.styleProperty("top",  QWebElement.ComputedStyle)

        x = self._parseCssSize(xStr)
        y = self._parseCssSize(yStr)

        # getBlockSize uses geometry() which doesn't actually offset the
        # rect it returns by (left, top), which is why we have to do it
        # ourselves
        return QRect(QPoint(x, y), self._getBlockSize(blockAddr))

    def _setBlockPos(self, blockAddr, pos):
        x, y = pos

        elem = self.blockElements[blockAddr]
        elem.setStyleProperty("left", "{:.2f}px".format(x))
        elem.setStyleProperty("top",  "{:.2f}px".format(y))

    def _makeGraphItem(self):
        self.graphItem = QGraphicsWebView()
        self.graphItem.setResizesToContents(True)
        self.graphItem.setPos(0, 0)
        self.graphItem.setZValue(-1)    # put under edges

        tmpl = Template(filename=os.path.join(main.MAIN_DIR, 'graph.html'))
        html = tmpl.render(
            blocks=[
                (self._getBlockElementID(mb.addr), mb)
                for mb in self.myBlocks],
            fmtAddr=self._formatAddr,
            fmtHex=self._formatHex,
            fmtAsm=self._formatAsm)
        self.graphItem.setHtml(html)

        self.addItem(self.graphItem)

        self.blockElements = dict(
            (self._blockElementIDToAddr(blockElem.attribute('id')), blockElem)
            for blockElem
            in self.graphItem.page().mainFrame().findAllElements(".block"))

    def _formatAddr(self, addr):
        '''Format address nicely as HTML'''
        return xmlEscape(self.mainWin.fmtNum(addr))

    def _formatHex(self, hexstring):
        '''Add spaces between hex chars, format nicely as HTML'''

        assert len(hexstring) % 2 == 0
        hexWithSpaces = ' '.join(
            hexstring[i:i+2]
            for i in xrange(0, len(hexstring), 2))
        return xmlEscape(hexWithSpaces)

    def _formatAsm(self, addr, op):
        '''Format op's assembly nicely as HTML'''
        return self.mainWin.asmFormatter.format(unhexlify(op.get_hex()), addr)

    def _makeEdgeItemsFromGraph(self):
        self.edgeItems = {}

        for b1Addr, b2Addr, edgeData in self.blockGraph.edges_iter(data=True):
            edgeType = edgeData['type']
            edgeItem = EdgeItem(edgeType, b1Addr, b2Addr, self.graphItem)
            self.edgeItems[b1Addr, b2Addr] = edgeItem

    def _updateGraphNodeSizes(self):
        for addr, elem in self.blockElements.iteritems():
            r = elem.geometry()

            # note that graphviz expects scaled input, so we scale it back
            nodeData = self.blockGraph.node[addr]
            nodeData['width'] = r.width() / self.GRAPHVIZ_SCALE_FACTOR
            nodeData['height'] = r.height() / self.GRAPHVIZ_SCALE_FACTOR
            nodeData['fixedsize'] = 'true'

    def _fixGraphvizLayout(self, layout):
        fixedLayout = {}

        for blockAddr, pos in layout.items():
            x, y = pos

            y = -y      # graphviz likes y to grow upward

            # graphviz gives us center position for node, but we need the
            # top-left
            r = self._getBlockSize(blockAddr)
            x -= r.width() / 2.
            y -= r.height() / 2.

            fixedLayout[blockAddr] = (x, y)

        # now adjust so minimum (x,y) is at (0, 0)
        minX = min(x for (x, _) in fixedLayout.itervalues())
        minY = min(y for (_, y) in fixedLayout.itervalues())
        fixedLayout2 = dict(
            (blockAddr, (x - minX, y - minY))
            for (blockAddr, (x, y))
            in fixedLayout.iteritems())

        return fixedLayout2

    def _layoutBlockGraph(self):
        self._updateGraphNodeSizes()

        # dot is for directed graphs
        layout = networkx.graphviz_layout(self.blockGraph, prog='dot')

        layout = self._fixGraphvizLayout(layout)

        for blockAddr in self.blockAddrs:
            self._setBlockPos(blockAddr, layout[blockAddr])

        self._layoutEdges()

        # TODO: perhaps margins should be inside the graphItem
        # TODO: include edges, too
        r = reduce(QRect.united,
            (self._getBlockRect(blockAddr) for blockAddr in self.blockAddrs))
        r.adjust(
            -self.HORIZ_MARGIN, -self.VERT_MARGIN,
             self.HORIZ_MARGIN,  self.VERT_MARGIN)
        self.setSceneRect(r)

    @staticmethod
    def _intersectsHorizLineWithRect(x1, x2, y, rect):
        return (x1 < rect.right() and x2 > rect.left()
            and rect.top() < y < rect.bottom())

    @staticmethod
    def _intersectsVertLineWithRect(x, y1, y2, rect):
        return (y1 < rect.bottom() and y2 > rect.top()
            and rect.left() < x < rect.right())

    def _layoutEdges(self):
        CLEARANCE = 15
        NUM_RECT_OUTLINES = 3
        OUTLINE_SPACING = 10

        blockRectsByAddr = dict(
            (addr, self._getBlockRect(addr))
            for addr in self.blockAddrs)

        blockRects = blockRectsByAddr.values()

        blockOutEdgesByDstX = dict(
            (addr, sorted(self.blockGraph.successors(addr),
                    key=lambda dstAddr: blockRectsByAddr[dstAddr].center().x()))
            for addr in self.blockAddrs)

        blockInEdgesBySrcX = dict(
            (addr, sorted(self.blockGraph.predecessors(addr),
                    key=lambda srcAddr: blockRectsByAddr[srcAddr].center().x()))
            for addr in self.blockAddrs)

        endPoints = []
        for b1Addr, b2Addr in self.blockGraph.edges_iter():
            b1Rect = blockRectsByAddr[b1Addr]
            b2Rect = blockRectsByAddr[b2Addr]

            b1OutList = blockOutEdgesByDstX[b1Addr]
            b1EdgeAreaWidth = (len(b1OutList) - 1) * CLEARANCE
            b1Ofs = -b1EdgeAreaWidth / 2. + b1OutList.index(b2Addr) * CLEARANCE

            b2InList = blockInEdgesBySrcX[b2Addr]
            b2EdgeAreaWidth = (len(b2InList) - 1) * CLEARANCE
            b2Ofs = -b2EdgeAreaWidth / 2. + b2InList.index(b1Addr) * CLEARANCE

            endPoints.append(
                (b1Addr, b2Addr,
                 (b1Rect.center().x() + b1Ofs, b1Rect.bottom() + CLEARANCE),
                 (b2Rect.center().x() + b2Ofs, b2Rect.top() - CLEARANCE)))

        G = networkx.Graph()

        xs = set()
        ys = set()
        for r in blockRects:
            for i in xrange(NUM_RECT_OUTLINES):
                outlineMargin = CLEARANCE + i * OUTLINE_SPACING
                xs.add(r.left() - outlineMargin)
                xs.add(r.right() + outlineMargin)
                ys.add(r.top() - outlineMargin)
                ys.add(r.bottom() + outlineMargin)

        for _, _, p1, p2 in endPoints:
            for p in [p1, p2]:
                x, y = p
                xs.add(x)
                ys.add(y)

        sortedXs = sorted(xs)
        sortedYs = sorted(ys)
        adjacentXs = zip(sortedXs, sortedXs[1:])
        adjacentYs = zip(sortedYs, sortedYs[1:])

        # we use larger rects for intersecting with edges, so other edges won't
        # get in the way of the edge arrows in the area around the rects
        expandedBlockRects = [
            r.adjusted(-CLEARANCE, -CLEARANCE, CLEARANCE, CLEARANCE)
            for r in blockRects]

        for (x1, x2) in adjacentXs:
            for y in ys:
                if not any(
                    self._intersectsHorizLineWithRect(x1, x2, y, r)
                    for r in expandedBlockRects):

                    p1 = (x1, y)
                    p2 = (x2, y)
                    dist = x2 - x1
                    G.add_edge(p1, p2, weight=dist)

        for (y1, y2) in adjacentYs:
            for x in xs:
                if not any(
                    self._intersectsVertLineWithRect(x, y1, y2, r)
                    for r in expandedBlockRects):

                    p1 = (x, y1)
                    p2 = (x, y2)
                    dist = y2 - y1
                    G.add_edge(p1, p2, weight=dist)

        # sort endpoints by Y values. the idea is that the straight flow's edges
        # will be handled first and will get nicer edges, though we probably
        # won't be doing exactly the right thing here.
        endPoints.sort(
            key=lambda (b1a,b2a,(x1,y1),(x2,y2)): (y1, y2 >= y1, abs(y2 - y1)))

        for b1Addr, b2Addr, p1, p2 in endPoints:
            p1x, p1y = p1
            p2x, p2y = p2

            try:
                path = networkx.shortest_path(G, p1, p2, weight='weight')

                # don't use these edges for any other paths
                for q1, q2 in zip(path, path[1:]):
                    G.remove_edge(q1, q2)
            except networkx.NetworkXNoPath:
                print('no path! between', p1, p2, file=sys.stderr)
                # create direct edge for debugging
                path = [p1, p2]

            path.insert(0, (p1x, p1y - CLEARANCE))
            path.append((p2x, p2y + CLEARANCE))

            self.edgeItems[b1Addr, b2Addr].setEdgePath(path)
