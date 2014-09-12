from __future__ import print_function
import sys
import os
from binascii import unhexlify
from struct import pack, unpack
from PySide.QtCore import *
from PySide.QtGui import *
from r2.r_core import RCore
from graph import SonareGraphScene


BASE_ADDR = 0x08048000


class FlagListModel(QStandardItemModel):
    def __init__(self, r2core):
        QStandardItemModel.__init__(self)

        self.r2core = r2core

        self._update()

    def _update(self):
        self.clear()

        self.setHorizontalHeaderLabels(['Address', 'Name'])

        flags = self.r2core.flags
        oldFlagSpace = flags.space_get_i(flags.space_idx)
        flags.space_set('symbols')

        # TODO: get flags through API
        for line in self.r2core.cmd_str('f').splitlines():
            addr, _, name = line.split(' ', 2)
            addr = int(addr, 16)
            self.appendRow([
                # TODO: use nice hex formatting
                QStandardItem('{0:#x}'.format(addr)),
                QStandardItem(name)])

        flags.space_set(oldFlagSpace)


class SonareWindow(QMainWindow):
    def __init__(self, path):
        QMainWindow.__init__(self)
        self.setMinimumSize(QSize(600, 400))

        self.open(path)

        self._makeScene()
        self._makeFlagList()

        self.funcName = None

        self._updateWindowTitle()

    def _makeScene(self):
        self.scene = SonareGraphScene(self)
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHints(
            QPainter.Antialiasing
            | QPainter.TextAntialiasing
            | QPainter.SmoothPixmapTransform
            | QPainter.HighQualityAntialiasing)
        self.setCentralWidget(self.view)

    def _makeFlagList(self):
        model = FlagListModel(self.scene.r2core)

        tree = QTreeView(self)
        tree.setModel(model)
        tree.setRootIsDecorated(False)
        tree.setEditTriggers(0)

        treeDock = QDockWidget("Flags", self)
        treeDock.setWidget(tree)
        self.addDockWidget(Qt.LeftDockWidgetArea, treeDock)

        def onDblClick(modelIdx):
            addrItem = model.item(modelIdx.row(), 0)
            # TODO: store number directly instead of converting to string
            addr = int(addrItem.text(), 16)
            self.gotoAddr(addr)
        tree.doubleClicked.connect(onDblClick)

    def _updateWindowTitle(self):
        self.setWindowTitle('Sonare - {} ({})'
            .format(self.funcName or '?', os.path.basename(self.filePath)))

    def open(self, path):
        self.r2core = RCore()
        self.r2core.flags.space_set(b'symbols')

        self.r2core.file_open(path.encode('ascii'), False, BASE_ADDR)
        self.r2core.bin_load("", 0)

        self.r2core.anal_all()
        print() # anal_all is noisy

        # clean up function overlaps
        self.r2core.cmd_str('aff')

        self.filePath = path

    def getAddr(self, addrName):
        if isinstance(addrName, unicode):
            addrName = addrName.encode('ascii')

        return self.r2core.num.get(addrName)

    def gotoFunc(self, funcName):
        funcAddr = self.getAddr(funcName)
        if funcAddr is None:
            raise ValueError("Unknown func '{}'".format(funcName))

        self.gotoAddr(funcAddr)

    def gotoAddr(self, funcAddr):
        self.scene.loadFunc(funcAddr)

        firstBlockItem = self.scene.blockItems[0]
        p = firstBlockItem.pos()
        r = firstBlockItem.rect()
        self.view.centerOn(p.x() + r.center().x(), p.y() + r.top())

        func = self.r2core.anal.get_fcn_at(funcAddr)
        if func is None:
            self.funcName = '?'
        else:
            self.funcName = func.name

        self._updateWindowTitle()

    def getAddrName(self, addr):
        flag = self.r2core.flags.get_i(int(addr) & 0xffffffffffffffff)
        if flag is None:
            return None
        else:
            return flag.name

    @property
    def isBigEndian(self):
        return self.r2core.config.get('cfg.bigendian') == 'true'

    def getWord(self, addr):
        # TODO: use r2 api
        hexStr = self.r2core.cmd_str('p8 4@{:#x}'.format(addr)).strip()
        buf = unhexlify(hexStr)
        fmt = '>L' if self.isBigEndian else '<L'
        return unpack(fmt, buf)[0]

    def fmtNum(self, val):
        if abs(val) < 10:
            return str(val)


        if abs(val) <= 0xffff:
            return format(val, '#x')
        else:
            hexStr = format(val, '08x')
            # split off last 2 bytes
            return hexStr[:-4] + ':' + hexStr[-4:]


if __name__ == '__main__':
    app = QApplication(sys.argv)
    args = app.arguments()
    if len(args) < 2:
        raise SystemExit("Usage: {0} <binary file>".format(args[0]))

    path, = args[1:]
    window = SonareWindow(path)
    window.showMaximized()
    app.exec_()
