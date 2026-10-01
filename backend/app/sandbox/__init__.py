"""Parser sandbox (Phase 10, guide 10.7): parse jobs run in a separate container without network.

* ``protocol``: the files and line format shared by the worker, the sandbox server and the child.
* ``child``: runs one parser on one evidence copy and streams cleaned events to stdout.
* ``server``: the long-running process in the ``parser-sandbox`` container.
* ``client``: the worker side (slot lock, request, wait, read the untrusted output).
"""
