"""Persistence layer.

One SQLite database, one schema, one connection per thread. Import what you
need from here rather than reaching into the submodules::

    from lpr.db import init_db, PlateRepository, LogRepository, UserRepository

    init_db()
    plates = PlateRepository()
    if plates.is_registered("34ABC123"):
        ...

``init_db()`` is idempotent, so every entry point (API, GUI, migration CLI)
can simply call it at startup.
"""

from __future__ import annotations

from lpr.db.connection import (
    MEMORY,
    close_all,
    database_path,
    get_connection,
    init_db,
    schema_version,
    shutdown,
    transaction,
)
from lpr.db.repository import (
    ADMIN_ROLE,
    DEFAULT_ROLE,
    LEGACY_PREFIX,
    LogRepository,
    PlateRepository,
    SystemMetaRepository,
    UserRepository,
    normalise_plate,
)

__all__ = [
    "ADMIN_ROLE",
    "DEFAULT_ROLE",
    "LEGACY_PREFIX",
    "MEMORY",
    "LogRepository",
    "PlateRepository",
    "SystemMetaRepository",
    "UserRepository",
    "close_all",
    "database_path",
    "get_connection",
    "init_db",
    "normalise_plate",
    "schema_version",
    "shutdown",
    "transaction",
]
