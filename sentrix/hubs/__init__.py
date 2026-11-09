"""SENTRIX Hubs — one shared Open Chat plus private one-to-one messages.

The package is intentionally small:

* :mod:`sentrix.hubs.storage` owns every SQLite read and write.
* :mod:`sentrix.hubs.api` turns HTTP routes into storage calls.

Direct messages are private between their two participants. There is no
administrative listing or read-through anywhere in this package.
"""
