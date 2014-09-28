from __future__ import print_function
import sys
import os
import networkx
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


    def __init__(self, type_, block1, block2, parent):
        '''type can be "jump", "ok" or "fail".'''

        QGraphicsPathItem.__init__(self, parent)
        self.type_ = type_
        self.block1 = block1
        self.block2 = block2

        self.block1.addOutgoingEdgeItem(self)
        self.block2.addIncomingEdgeItem(self)

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

    def _xOffset(self, outgoing=True):
        # note that GraphBlock keeps edge items sorted by X
        if outgoing:
            edges = self.block1.outgoingEdgeItems
        else:
            edges = self.block2.incomingEdgeItems

        n = len(edges)
        i = edges.index(self)
        totalWidth = self.COND_EDGE_SPACING * (n - 1)
        return (-totalWidth / 2.) + (i * self.COND_EDGE_SPACING)

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

    def updatePos(self):
        rect1 = self.block1.rect()
        rect2 = self.block2.rect()

        # TODO: horrible algorithm
        self.p1 = p1 = QPointF(rect1.center().x() + self._xOffset(True), rect1.bottom())
        self.p2 = p2 = QPointF(rect2.center().x() + self._xOffset(False), rect2.top())

        # edges always leave the bottom of the block. move down
        # MIN_VERT_LENGTH before trying to get to p2.
        p1b = QPointF(p1.x(), p1.y() + self.MIN_VERT_LENGTH)
        # and the other way around before end of path
        p2a = QPointF(p2.x(), p2.y() - self.MIN_VERT_LENGTH)

        # TODO: cut off backtracking lines
        # TODO: try to make lines more balanced
        pts = [p1] + self._splitLine(p1b, p2a) + [p2]

        path = QPainterPath()
        path.moveTo(pts[0])
        for pt in pts[1:]:
            path.lineTo(pt)
        self.setPath(path)

        self._updateArrowPos()
        self._updatePen()

    def _updatePen(self):
        pen = QPen(self.color, self.edgeWidth)
        pen.setCapStyle(Qt.FlatCap)
        self.setPen(pen)

    def _splitLine(self, p1, p2):
        scene = self.scene()

        if (abs(p1.x() - p2.x()) > self.EPSILON
            and abs(p1.y() - p2.y()) > self.EPSILON):

            # we have two options: either travel horizontally first, or
            # travel vertically first.
            # we prefer vertical, unless it intersects stuff
            optVert = [p1, QPointF(p1.x(), p2.y()), p2]
            if any(scene.doesLineIntersectWithBlocks(line)
                for line in pointListToLines(optVert)):

                optHoriz = [p1, QPointF(p2.x(), p1.y()), p2]
                preferredOpt = optHoriz
            else:
                preferredOpt = optVert

            return chainPointLists([
                self._splitLine(p1a, p2a)
                for (p1a, p2a)
                in pointListToPairs(preferredOpt)])

        line = QLineF(p1, p2)
        inters = list(scene.intersectLineWithBlocks(line))
        # sort by distance from p1 (all points are on the same line,
            # so manhattan length is ok)
        inters.sort(key=lambda (b, p): (p - p1).manhattanLength())

        # if number of intersections is odd, that means one of our points
        # is inside a block. better give up now.
        if len(inters) % 2 == 1:
            print(
                'WARNING: line forced to cross block; intersections: {0}'
                    .format([b for (b, _) in inters]),
                file=sys.stderr)

            return [p1, p2]

        # break any intersections
        result = [p1, p2]
        while inters:
            dp = QVector2D(p2 - p1).normalized().toPointF()

            graphBlock, p1b = inters.pop(0)
            graphBlock2, p2a = inters.pop(0)
            assert graphBlock2 is graphBlock

            # move both points away from the block
            p1b -= dp * self.MIN_VERT_LENGTH
            p2a += dp * self.MIN_VERT_LENGTH

            # now we need to find a way around the block.
            r = graphBlock.rect()
            r.adjust(-self.MIN_VERT_LENGTH, -self.MIN_VERT_LENGTH,
                self.MIN_VERT_LENGTH, self.MIN_VERT_LENGTH)

            g = networkx.Graph()

            def addLineAsEdge(line):
                length = (line.p2() - line.p1()).manhattanLength()
                g.add_edge(
                    (line.x1(), line.y1()), (line.x2(), line.y2()),
                    weight=length)

            for line in rectLines(r):
                addLineAsEdge(line)

            corners = rectCorners(r)
            for p in [p1b, p2a]:
                for c in corners:
                    line = QLineF(p, c)
                    if not scene.doesLineIntersectWithBlocks(line):
                        addLineAsEdge(line)

            p1bTuple = (p1b.x(), p1b.y())
            p2aTuple = (p2a.x(), p2a.y())
            shortestPath = networkx.shortest_path(g,
                source=p1bTuple, target=p2aTuple)
            shortestPathPoints = [QPointF(x, y) for (x, y) in shortestPath]

            result = (result[:-1] + shortestPathPoints + [result[-1]])

        return result

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
    def __init__(self, ops, endOp):
        '''(endOp causes the end of the block, but might not be the
            last op due to delay slots)'''

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

        return MyBlock(ops, endOp)

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


class GraphBlock(object):
    def __init__(self, mainWin, myblock):
        self.mainWin = mainWin
        self.graphItem = None       # filled in later
        self.myblock = myblock

        self.outgoingEdgeItems = []
        self.incomingEdgeItems = []

        self._pos = QPointF()
        self._element = None

    @property
    def addr(self):
        return self.myblock.addr

    @property
    def jump(self):
        return normalizeAddr(self.myblock.jump)

    @property
    def fail(self):
        return normalizeAddr(self.myblock.fail)

    @property
    def labelName(self):
        return 'blk_{0:x}'.format(self.addr)

    @property
    def x(self):
        return self._pos.x()

    @property
    def y(self):
        return self._pos.y()

    def setPos(self, x, y):
        elem = self.getElement()
        elem.setStyleProperty("left", "{:.2f}px".format(x))
        elem.setStyleProperty("top",  "{:.2f}px".format(y))

        self._pos = QPointF(x, y)

    @property
    def width(self):
        return self.size().width()

    @property
    def height(self):
        return self.size().height()

    def size(self):
        return self.getElement().geometry().size()

    def rect(self):
        r = self.getElement().geometry()
        r.translate(self._pos.toPoint())
        return r

    @property
    def centerX(self):
        return self.x + self.width / 2.

    @property
    def elementID(self):
        return "b{:08x}".format(self.addr)

    def getElement(self):
        # (this only works after the element is created. first the GraphBlock
            # is created, then it's used as an input to the html template,
            # then we can get the QWebPageElements from the template output)

        if self._element is None:
            frame = self.graphItem.page().mainFrame()
            self._element = frame.findFirstElement("#" + self.elementID)

        return self._element

    def resortEdgeItems(self):
        '''this needs to be called after block positions are updated.'''
        # sort by dst X
        self.outgoingEdgeItems.sort(key=lambda ei: ei.block2.centerX)
        # sort by src X
        self.incomingEdgeItems.sort(key=lambda ei: ei.block1.centerX)

    def addOutgoingEdgeItem(self, edgeItem):
        self.outgoingEdgeItems.append(edgeItem)
        self.resortEdgeItems()

    def addIncomingEdgeItem(self, edgeItem):
        self.incomingEdgeItems.append(edgeItem)
        self.resortEdgeItems()

    def _getAsmOps(self):
        for op in self.myblock.ops:
            addr = op.addr
            asmOp = self.mainWin.r2core.disassemble(addr)
            assert asmOp is not None, \
                "Couldn't disassemble @ {:#x}".format(addr)
            yield (addr, asmOp)

        # addr = self.r2block.addr
        # endAddr = addr + self.r2block.size

        # while addr < endAddr:
        #     op = self.mainWin.r2core.disassemble(addr)
        #     yield (addr, op)

        #     addr += op.size

    def formatAddr(self, addr):
        '''Format address nicely as HTML'''
        return xmlEscape(self.mainWin.fmtNum(addr))

    @staticmethod
    def formatHex(hexstring):
        '''Add spaces between hex chars, format nicely as HTML'''
        assert len(hexstring) % 2 == 0
        hexWithSpaces = ' '.join(
            hexstring[i:i+2]
            for i in xrange(0, len(hexstring), 2))
        return xmlEscape(hexWithSpaces)

    def formatAsm(self, addr, op):
        '''Format op's assembly nicely as HTML'''
        return self.mainWin.asmFormatter.format(unhexlify(op.get_hex()), addr)

    def formatInsns(self):
        addrsAndOps = list(self._getAsmOps())

        return [
            (self.formatAddr(addr), self.formatHex(op.get_hex()),
                self.formatAsm(addr, op))
            for (addr, op) in addrsAndOps]


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

        self.funcAddr = self.graphBlocks = self.graphBlocksByAddr = \
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

    def _makeBlockGraph(self):
        # r2blocks = self.func.get_bbs()
        # self.graphBlocks = [
        #     GraphBlock(self.mainWin, r2b)
        #     for r2b in r2blocks]
        self.graphBlocks = [
            GraphBlock(self.mainWin, mb)
            for mb in MyBlock._makeFuncBlocks(self.mainWin.r2core, self.funcAddr)]

        self.graphBlocksByAddr = dict((b.addr, b) for b in self.graphBlocks)

        self.blockGraph = networkx.DiGraph()
        for b in self.graphBlocks:
            self.blockGraph.add_node(b.addr)

            if b.fail is not None:
                self.blockGraph.add_edge(b.addr, b.fail, type='fail')

            if b.jump is not None:
                type_ = 'jump' if b.fail is None else 'ok'
                self.blockGraph.add_edge(b.addr, b.jump, type=type_)

    def _makeGraphItem(self):
        self.graphItem = QGraphicsWebView()
        self.graphItem.setResizesToContents(True)
        self.graphItem.setPos(0, 0)
        self.graphItem.setZValue(-1)    # put under edges

        for block in self.graphBlocks:
            block.graphItem = self.graphItem

        tmpl = Template(filename=os.path.join(main.MAIN_DIR, 'graph.html'))
        html = tmpl.render(blocks=self.graphBlocks)
        self.graphItem.setHtml(html)

        self.addItem(self.graphItem)

    def _makeEdgeItemsFromGraph(self):
        self.edgeItems = {}

        for b1Addr, b2Addr, edgeData in self.blockGraph.edges_iter(data=True):
            edgeType = edgeData['type']
            try:
                b1 = self.graphBlocksByAddr[b1Addr]
                b2 = self.graphBlocksByAddr[b2Addr]
            except LookupError:
                print('missing:', hex(b1Addr), 'or', hex(b2Addr),
                    file=sys.stderr)
                continue

            edgeItem = EdgeItem(edgeType, b1, b2, self.graphItem)

            self.edgeItems[b1Addr, b2Addr] = edgeItem

    def _layoutBlockGraph(self):
        # set node sizes
        for b in self.graphBlocks:
            r = b.rect()

            # note that graphviz expects scaled input, so we scale it back
            nodeData = self.blockGraph.node[b.addr]
            nodeData['width'] = r.width() / self.GRAPHVIZ_SCALE_FACTOR
            nodeData['height'] = r.height() / self.GRAPHVIZ_SCALE_FACTOR
            nodeData['fixedsize'] = 'true'

        # dot is for directed graphs
        layout = networkx.graphviz_layout(self.blockGraph, prog='dot')

        fixedLayout = {}
        for blockAddr, pos in layout.items():
            block = self.graphBlocksByAddr[blockAddr]

            x, y = pos

            y = -y      # graphviz likes y to grow upward

            # graphviz gives us center position for node, but we need the
            # top-left
            s = block.size()
            x -= s.width() / 2.
            y -= s.height() / 2.

            fixedLayout[blockAddr] = (x, y)

        # set position, but adjust so minimum (x,y) is at (0, 0)
        minX = min(x for (x, _) in fixedLayout.itervalues())
        minY = min(y for (_, y) in fixedLayout.itervalues())
        for graphBlock in self.graphBlocks:
            x, y = fixedLayout[graphBlock.addr]
            graphBlock.setPos(x - minX, y - minY)

        # now we moved the blocks around, resort the blocks' edge item lists
        for graphBlock in self.graphBlocks:
            graphBlock.resortEdgeItems()

        # update edges according to block positions
        for edge in self.edgeItems.itervalues():
            edge.updatePos()

        # TODO: perhaps margins should be inside the graphItem
        r = reduce(QRect.united, (gb.rect() for gb in self.graphBlocks))
        r.adjust(
            -self.HORIZ_MARGIN, -self.VERT_MARGIN,
             self.HORIZ_MARGIN,  self.VERT_MARGIN)
        self.setSceneRect(r)

    def intersectLineWithBlocks(self, line):
        for graphBlock in self.graphBlocks:
            r = graphBlock.rect()

            # convert rectangle to lines
            rpts = [r.topLeft(), r.topRight(), r.bottomRight(), r.bottomLeft(),
                r.topLeft()]
            rlines = pointListToLines(rpts)

            # test rectangle's lines against our line, yield any intersections
            for rline in rlines:
                intrtype, intrpt = line.intersect(rline)
                if intrtype != QLineF.BoundedIntersection:
                    continue

                yield (graphBlock, intrpt)

    def doesLineIntersectWithBlocks(self, line):
        return not isEmptyIterable(self.intersectLineWithBlocks(line))
