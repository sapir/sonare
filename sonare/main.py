from __future__ import print_function
import sys
import os
from binascii import unhexlify
from struct import pack, unpack
from PySide.QtCore import *
from PySide.QtGui import *
from r2.r_core import RCore
from x86asm import X86AsmFormatter
from mipsasm import MipsAsmFormatter
import graph


BASE_ADDR = 0x08048000

MAIN_DIR = os.path.abspath(os.path.dirname(__file__))


class FlagListModel(QStandardItemModel):
    def __init__(self, mainWin):
        QStandardItemModel.__init__(self)

        self.mainWin = mainWin
        self.r2core = mainWin.r2core

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

            addrItem = QStandardItem(self.mainWin.fmtNum(addr))
            addrItem.setData(addr)
            addrItem.setForeground(self.mainWin.ADDR_COLOR)
            addrItem.setFont(self.mainWin.font)
            addrItem.setTextAlignment(Qt.AlignCenter)

            nameItem = QStandardItem(name)
            nameItem.setForeground(self.mainWin.SYMBOL_COLOR)
            nameItem.setFont(self.mainWin.font)

            self.appendRow([addrItem, nameItem])

        flags.space_set(oldFlagSpace)


class FilteredTreeDock(QDockWidget):
    def __init__(self, mainWin, name, model, parent=None):
        QDockWidget.__init__(self, name, parent)

        self.model = model

        self.proxyModel = QSortFilterProxyModel()
        self.proxyModel.setSourceModel(model)
        self.proxyModel.setDynamicSortFilter(True)

        self.treeView = QTreeView()
        self.treeView.setModel(self.proxyModel)

        self.treeView.setRootIsDecorated(False)
        self.treeView.setEditTriggers(0)
        self.treeView.setAllColumnsShowFocus(True)
        self.treeView.setUniformRowHeights(True)
        self.treeView.setSortingEnabled(True)

        self.searchWidget = QLineEdit()
        self.searchWidget.setFont(mainWin.font)
        self.searchWidget.setPlaceholderText("Filter")
        self.searchWidget.textChanged.connect(self._onSearchTextChanged)

        vboxLayout = QVBoxLayout()
        vboxLayout.addWidget(self.treeView)
        vboxLayout.addWidget(self.searchWidget)

        vbox = QWidget(self)
        vbox.setLayout(vboxLayout)

        self.setWidget(vbox)

    def setFilterKeyColumn(self, idx):
        self.proxyModel.setFilterKeyColumn(idx)

    def sortByColumn(self, idx, order):
        self.treeView.sortByColumn(idx, order)

    def _onSearchTextChanged(self, text):
        regexp = QRegExp(text, Qt.CaseInsensitive)
        self.proxyModel.setFilterRegExp(regexp)


class SonareWindow(QMainWindow):
    # TODO: HTML should use settings specified here
    FONT_NAME = 'Monospace'
    FONT_SIZE = 8

    WINDOW_COLOR       = QColor(0x3c, 0x3c, 0x3c)
    BG_COLOR           = QColor(0x50, 0x50, 0x64)
    DEFAULT_TEXT_COLOR = QColor(0xD8, 0xD8, 0xD8)

    # TODO: HTML should use settings specified here
    ADDR_COLOR = QColor(0x7F, 0xEC, 0x91)
    SYMBOL_COLOR = QColor(0xD8, 0xD8, 0xD8)


    def __init__(self, path):
        QMainWindow.__init__(self)
        self.setMinimumSize(QSize(600, 400))

        self.font = QFont(self.FONT_NAME, self.FONT_SIZE)
        self.fontMetrics = QFontMetricsF(self.font)

        palette = self.palette()
        # palette.setColor(QPalette.Window, self.WINDOW_COLOR)
        # palette.setColor(QPalette.WindowText, self.DEFAULT_TEXT_COLOR)
        palette.setColor(QPalette.Base, self.BG_COLOR)
        palette.setColor(QPalette.Text, self.DEFAULT_TEXT_COLOR)
        self.setPalette(palette)

        self.open(path)

        self._makeScene()
        self._makeFlagList()

        self.funcName = None

        self._updateWindowTitle()

    def _makeScene(self):
        self.scene = graph.SonareGraphScene(self)
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHints(
            QPainter.Antialiasing
            | QPainter.TextAntialiasing
            | QPainter.SmoothPixmapTransform
            | QPainter.HighQualityAntialiasing)
        self.setCentralWidget(self.view)

    def _makeFlagList(self):
        model = FlagListModel(self)

        ftdock = FilteredTreeDock(self, "Flags", model, self)
        ftdock.setFilterKeyColumn(1)                  # filter by name
        ftdock.sortByColumn(0, Qt.AscendingOrder)     # sort by address

        self.addDockWidget(Qt.LeftDockWidgetArea, ftdock)

        def onDblClick(modelIdx):
            addrItemIdx = modelIdx.sibling(modelIdx.row(), 0)

            # this is actually the proxy model
            model = ftdock.treeView.model()
            addr = model.data(addrItemIdx, Qt.UserRole + 1)
            self.gotoAddr(addr)

        ftdock.treeView.doubleClicked.connect(onDblClick)

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

        arch = self.r2core.config.get('asm.arch')
        if arch == 'x86':
            self.asmFormatter = X86AsmFormatter(self)
        elif arch == 'mips':
            self.asmFormatter = MipsAsmFormatter(self)
        else:
            raise NotImplementedError("asm formatting for {}".format(arch))

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
        func = self.r2core.anal.get_fcn_at(funcAddr, 1) # R_ANAL_FCN_TYPE_FCN
        if func is None:
            self.funcName = '?'
        else:
            self.funcName = func.name
            funcAddr = func.addr

        self.scene.loadFunc(funcAddr)

        firstBlock = self.scene.myBlocks[0]
        r = self.scene.getBlockRect(firstBlock.addr)
        self.view.centerOn(r.center().x(), r.top())

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

    try:
        window.gotoFunc('main')
    except ValueError:
        pass

    window.showMaximized()
    window.raise_()
    app.exec_()
