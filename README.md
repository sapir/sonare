Sonare
======

A Qt-based disassembly viewer based on
[radare2](https://github.com/radare/radare2/).

Currently also uses [capstone](https://github.com/aquynh/capstone)
directly (rather than through radare2) for syntax highlighting.

![a screenshot](/doc/screenshot-test.png?raw=true)


# Running

First install the dependencies described below under Dependencies.

To run Sonare to view the `path/to/my/binary` file:

    cd /path/to/sonare/
    python sonare/main.py path/to/my/binary

(Note that Sonare currently expects to be run from the root of its source
tree.)


# Dependencies

Sonare currently has the following dependencies, which you'll need to
install first:

* Python 2.7 (2.6 may be ok, too. 2.5 probably won't be.)

* [radare2](https://github.com/radare/radare2)

* [radare2-bindings](https://github.com/radare/radare2-bindings)

* [capstone](https://github.com/aquynh/capstone)'s python bindings

  radare2 pulls in capstone while compiling. after compiling
  radare2, you can find capstone's python bindings in the radare2
  tree under `shlr/capstone/bindings/python` and install them from
  there:

  ```
  python setup.py build
  sudo python setup.py install
  ```

* Various python modules: networkx, PyQt5, mako, sortedcontainers

  ```
  sudo apt-get install python-networkx python-pyqt5 \
      python-pyqt5.qtwebkit python-mako

  sudo pip install sortedcontainers
  ```
