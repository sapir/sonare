from __future__ import print_function
import sys
import os
import networkx
import itertools
from binascii import unhexlify
from heapq import heappush, heappop
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


    def __init__(self, type_, block1Addr, block2Addr):
        '''type can be "jump", "ok" or "fail".'''

        QGraphicsPathItem.__init__(self)
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

    @staticmethod
    def normalizeAddr(addr):
        if addr in (0, BAD_ADDR):
            return None
        else:
            return addr

    @property
    def jump(self):
        return MyBlock.normalizeAddr(self.endOp.jump)

    @property
    def fail(self):
        return MyBlock.normalizeAddr(self.endOp.fail)

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
    def isEndBlockOp(op):
        return ((op.type & 0xffffffff) & ~R_ANAL_OP_TYPE_COND) in [
            R_ANAL_OP_TYPE_JMP, R_ANAL_OP_TYPE_UJMP, R_ANAL_OP_TYPE_RET]

    @staticmethod
    def _makeMyBlockAt(r2core, addr):
        ops = []
        endOp = None

        opsLeft = -1
        while opsLeft != 0:
            op = r2core.op_anal(addr)
            ops.append(op)

            if MyBlock.isEndBlockOp(op):
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


class _BlockLayoutInfo(object):
    """
    Temporary object describing info about a graph block, used for edge layout.
    """


    "Horizontal spacing between incoming/outgoing edge arrows"
    EDGE_SPACING = 15


    def __init__(self, blockAddr, rect, blockGraph, blockRectsByAddr):
        self.addr = blockAddr
        self.rect = rect
        self.centerX = self.rect.center().x()

        centerXOfBlock = lambda blockAddr: blockRectsByAddr[blockAddr].center().x()

        # destinations of outgoing edges, sorted by X position of dest block.
        self.sortedSuccessors = sorted(
            blockGraph.successors(self.addr), key=centerXOfBlock)

        # sources of incoming edges, sorted by Y position of source block.
        self.sortedPredecessors = sorted(
            blockGraph.predecessors(self.addr), key=centerXOfBlock)

    def _getEdgeXPos(self, otherBlockList, otherBlockAddr):
        edgeAreaWidth = (len(otherBlockList) - 1) * self.EDGE_SPACING
        edgeIdx = otherBlockList.index(otherBlockAddr)
        return self.centerX - edgeAreaWidth / 2. + edgeIdx * self.EDGE_SPACING

    def getOutgoingEdgePos(self, otherBlockAddr):
        return self._getEdgeXPos(self.sortedSuccessors, otherBlockAddr)

    def getIncomingEdgePos(self, otherBlockAddr):
        return self._getEdgeXPos(self.sortedPredecessors, otherBlockAddr)

class _EdgeLayoutInfo(object):
    """
    Temporary object describing info about a graph block, used for edge layout.
    """

    def __init__(self, b1Addr, b2Addr, blockLayoutInfosByAddr):
        self.b1Addr = b1Addr
        self.b2Addr = b2Addr

        self.bli1 = blockLayoutInfosByAddr[self.b1Addr]
        self.bli2 = blockLayoutInfosByAddr[self.b2Addr]

        # the edge path goes from (x1, y1) to (x2, y2). but we add some bits
        # before and after that:

        # first line segment in edge is a straight downward line from
        # (x1, y0) to (x1, y1)
        self.x1 = self.bli1.getOutgoingEdgePos(b2Addr)
        self.y0 = self.bli1.rect.bottom()
        self.y1 = self.y0 + _EdgeLayoutAlgo.CLEARANCE

        # last line segment in edge is the one with the arrow, a straight
        # downward line from (x2, y2) to (x2, y3)
        self.x2 = self.bli2.getIncomingEdgePos(b1Addr)
        self.y3 = self.bli2.rect.top()
        self.y2 = self.y3 - _EdgeLayoutAlgo.CLEARANCE

    @property
    def p0(self):
        return (self.x1, self.y0)

    @property
    def p1(self):
        return (self.x1, self.y1)

    @property
    def p2(self):
        return (self.x2, self.y2)

    @property
    def p3(self):
        return (self.x2, self.y3)


# TODO: minimum distance between edges
class _EdgeLayoutAlgo(object):
    """
    Implementation of edge layout algorithm. (In a separate object
    because it has some state.)
    """


    NUM_RECT_OUTLINES = 3
    OUTLINE_SPACING = 10
    CLEARANCE = 15

    """
    When finding 'shortest' edge paths, angles in paths are penalized by
    adding this 'distance' to the edge length.
    """
    ANGLE_PENALTY = 100


    def __init__(self, blockGraph):
        """
        blockGraph should contain x, y, width and height attributes for
        each node.
        """

        self.blockAddrs = blockGraph.nodes()

        blocksAndRects = [
            (blockAddr,
                QRect(data['x'], data['y'], data['width'], data['height']))
            for (blockAddr, data)
            in blockGraph.nodes_iter(data=True)]

        self.blockRects = [rect for (_, rect) in blocksAndRects]
        self.blockRectsByAddr = dict(blocksAndRects)

        self.blockGraph = blockGraph

        self._makeLayoutInfos()

    def _makeLayoutInfos(self):
        self.blockLayoutInfos = [
            _BlockLayoutInfo(addr, self.blockRectsByAddr[addr],
                self.blockGraph, self.blockRectsByAddr)
            for addr in self.blockAddrs]

        self.blockLayoutInfosByAddr = dict(
            (bli.addr, bli) for bli in self.blockLayoutInfos)

        self.edgeLayoutInfos = [
            _EdgeLayoutInfo(b1Addr, b2Addr, self.blockLayoutInfosByAddr)
            for (b1Addr, b2Addr) in self.blockGraph.edges_iter()]

    def doLayout(self):
        self._makeGridGraph()
        return self._makeEdgePaths()

    def _makeGridGraph(self):
        # make a grid graph, with X and Y values of lines around rectangles
        # and of edge endpoints. exclude lines that intersect rectangles.

        self._graph = networkx.Graph()

        xs = set()
        ys = set()

        for r in self.blockRects:
            for i in xrange(self.NUM_RECT_OUTLINES):
                outlineMargin = self.CLEARANCE + i * self.OUTLINE_SPACING
                xs.add(r.left() - outlineMargin)
                xs.add(r.right() + outlineMargin)
                ys.add(r.top() - outlineMargin)
                ys.add(r.bottom() + outlineMargin)

        for eli in self.edgeLayoutInfos:
            for p in [eli.p1, eli.p2]:
                x, y = p
                xs.add(x)
                ys.add(y)

        # we use larger rects for intersecting with edges, so other edges won't
        # get in the way of the edge arrows in the area around the rects
        expandedBlockRects = [
            r.adjusted(
                -self.CLEARANCE, -self.CLEARANCE,
                 self.CLEARANCE,  self.CLEARANCE)
            for r in self.blockRects]

        sortedXs = sorted(xs)
        adjacentXs = zip(sortedXs, sortedXs[1:])
        for (x1, x2) in adjacentXs:
            for y in ys:
                # TODO: for a given y, we could just remove Xs inside rects
                # crossing that Y, and then take adjacents. (and same for
                # vertical). premature optimization?
                if not any(
                    self._collideHorizLineAndRect(x1, x2, y, r)
                    for r in expandedBlockRects):

                    p1 = (x1, y)
                    p2 = (x2, y)
                    dist = x2 - x1
                    self._graph.add_edge(p1, p2, weight=dist)

        sortedYs = sorted(ys)
        adjacentYs = zip(sortedYs, sortedYs[1:])
        for (y1, y2) in adjacentYs:
            for x in xs:
                if not any(
                    self._collideVertLineAndRect(x, y1, y2, r)
                    for r in expandedBlockRects):

                    p1 = (x, y1)
                    p2 = (x, y2)
                    dist = y2 - y1
                    self._graph.add_edge(p1, p2, weight=dist)

    def _choosePath(self, source, target):
        """
        Choose a path through self._graph from source to target.

        (Implementation is A*, but past-path cost makes angles costly, so we
            prefer straight edges.)
        """

        # Code copied from networkx astar module.
        #    Copyright (C) 2004-2011 by
        #    Aric Hagberg <hagberg@lanl.gov>
        #    Dan Schult <dschult@colgate.edu>
        #    Pieter Swart <swart@lanl.gov>
        #    All rights reserved.
        #    BSD license.

        # A few changes were made to customize the cost calculation. See code
        # there for comments.

        def manhattanDistance(p1, p2):
            x1, y1 = p1
            x2, y2 = p2
            return abs(x2 - x1) + abs(y2 - y1)

        heuristic = manhattanDistance

        def calcPastCost(costToP1, p0, p1, p2):
            baseCost = costToP1 + manhattanDistance(p1, p2)

            if p0 is None:
                # angle penalty is irrelevant, there is no previous line
                # segment
                return baseCost

            x0, y0 = p0
            x1, y1 = p1
            x2, y2 = p2

            if not ((x0 == x1 == x2) or (y0 == y1 == y2)):
                # it's not a straight line
                penalty = self.ANGLE_PENALTY
            else:
                penalty = 0

            return baseCost + penalty


        queue = [(0, hash(source), source, 0, None)]
        enqueued = {}
        explored = {}

        while queue:
            _, __, curnode, dist, parent = heappop(queue)

            if curnode == target:
                path = [curnode]
                node = parent
                while node is not None:
                    path.append(node)
                    node = explored[node]
                path.reverse()
                return path

            if curnode in explored:
                continue

            explored[curnode] = parent

            for neighbor, w in self._graph[curnode].items():
                if neighbor in explored:
                    continue

                ncost = calcPastCost(dist, parent, curnode, neighbor)

                if neighbor in enqueued:
                    qcost, h = enqueued[neighbor]
                    if qcost <= ncost:
                        continue
                else:
                    h = heuristic(neighbor, target)
                enqueued[neighbor] = ncost, h
                heappush(queue, (ncost + h, hash(neighbor), neighbor,
                                 ncost, curnode))

        raise networkx.NetworkXNoPath(
            "Node %s not reachable from %s" % (source, target))

    def _makeEdgePaths(self):
        """Make edgePaths dict. (Also removes used edges from _graph.)"""

        # sort edges by Y values. the idea is that the straight flow's edges
        # will be handled first and will get nicer edges, though we probably
        # won't be doing exactly the right thing here.
        self.edgeLayoutInfos.sort(
            key=lambda eli: (eli.y1, eli.y2 >= eli.y1, abs(eli.y2 - eli.y1)))

        edgePaths = {}
        for eli in self.edgeLayoutInfos:
            try:
                path = self._choosePath(eli.p1, eli.p2)

                # don't use these edges for any other paths
                for p1, p2 in zip(path, path[1:]):
                    self._graph.remove_edge(p1, p2)
            except networkx.NetworkXNoPath:
                # TODO: try again with more rect outlines
                print('no path! between', p1, p2, file=sys.stderr)
                # create direct edge for debugging
                path = [p1, p2]

            # Force vertical beginning and end of edges.
            # TODO: it'd be nicer to include these edges in the graph
            path.insert(0, eli.p0)
            path.append(eli.p3)

            edgePaths[eli.b1Addr, eli.b2Addr] = path

        return edgePaths

    @staticmethod
    def _collideHorizLineAndRect(x1, x2, y, rect):
        """
        Check for collision between a horizontal line and a QRect.
        (doesn't include the QRect's edges).
        """
        return (x1 < rect.right() and x2 > rect.left()
            and rect.top() < y < rect.bottom())

    @staticmethod
    def _collideVertLineAndRect(x, y1, y2, rect):
        """
        Check for collision between a vertical line and a QRect.
        (doesn't include the QRect's edges).
        """
        return (y1 < rect.bottom() and y2 > rect.top()
            and rect.left() < x < rect.right())


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

    def getBlockSize(self, blockAddr):
        elem = self.blockElements[blockAddr]
        return elem.geometry().size()

    def getBlockRect(self, blockAddr):
        elem = self.blockElements[blockAddr]

        xStr = elem.styleProperty("left", QWebElement.ComputedStyle)
        yStr = elem.styleProperty("top",  QWebElement.ComputedStyle)

        x = self._parseCssSize(xStr)
        y = self._parseCssSize(yStr)

        # getBlockSize uses geometry() which doesn't actually offset the
        # rect it returns by (left, top), which is why we have to do it
        # ourselves
        return QRect(QPoint(x, y), self.getBlockSize(blockAddr))

    def _setBlockPos(self, blockAddr, pos):
        x, y = pos

        elem = self.blockElements[blockAddr]
        elem.setStyleProperty("left", "{:.2f}px".format(x))
        elem.setStyleProperty("top",  "{:.2f}px".format(y))

        nodeData = self.blockGraph.node[blockAddr]
        nodeData['x'] = x
        nodeData['y'] = y

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
            edgeItem = EdgeItem(edgeType, b1Addr, b2Addr)
            self.edgeItems[b1Addr, b2Addr] = edgeItem

            self.addItem(edgeItem)

    def _setGraphNodeSizes(self, scalingFactor):
        for addr, elem in self.blockElements.iteritems():
            r = elem.geometry()

            nodeData = self.blockGraph.node[addr]
            nodeData['width'] = r.width() * scalingFactor
            nodeData['height'] = r.height() * scalingFactor
            nodeData['fixedsize'] = 'true'

    def _fixGraphvizLayout(self, layout):
        fixedLayout = {}

        for blockAddr, pos in layout.items():
            x, y = pos

            y = -y      # graphviz likes y to grow upward

            # graphviz gives us center position for node, but we need the
            # top-left
            r = self.getBlockSize(blockAddr)
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
        # note that graphviz expects sizes in inches, so we scale them back
        self._setGraphNodeSizes(1. / self.GRAPHVIZ_SCALE_FACTOR)

        # dot is for directed graphs
        layout = networkx.graphviz_layout(self.blockGraph, prog='dot')

        layout = self._fixGraphvizLayout(layout)

        for blockAddr in self.blockAddrs:
            # this both updates the HTML element, and the graph node's
            # x and y attributes
            self._setBlockPos(blockAddr, layout[blockAddr])

        # now set node sizes for edge layout algo
        self._setGraphNodeSizes(scalingFactor=1.0)

        layoutAlgo = _EdgeLayoutAlgo(self.blockGraph)
        edgePaths = layoutAlgo.doLayout()

        for (b1Addr, b2Addr), edgeItem in self.edgeItems.iteritems():
            edgeItem.setEdgePath(edgePaths[b1Addr, b2Addr])

        self._updateSceneRect()

    def _updateSceneRect(self):
        # TODO: perhaps margins should be inside the graphItem
        r = reduce(QRect.united,
            (self.getBlockRect(blockAddr) for blockAddr in self.blockAddrs))

        for edgeItem in self.edgeItems.itervalues():
            r |= edgeItem.boundingRect().toRect()

        r.adjust(
            -self.HORIZ_MARGIN, -self.VERT_MARGIN,
             self.HORIZ_MARGIN,  self.VERT_MARGIN)

        self.setSceneRect(r)
