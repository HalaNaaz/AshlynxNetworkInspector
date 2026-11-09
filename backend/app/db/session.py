import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional

from backend.app.core.config import settings
from backend.app.core.logging import logger

# Default database path: data/ani.db relative to repository root
DEFAULT_DB_DIR = Path(__file__).resolve().parent.parent.parent / "data"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "ani.db"


def get_db_path() -> Path:
    """Returns the resolved SQLite database file path.
    
    Creates parent directories if they do not exist.
    """
    configured = getattr(settings, "db_path", None)
    if configured:
        p = Path(configured)
        if not p.is_absolute():
            p = (Path(__file__).resolve().parent.parent.parent / p).resolve()
    else:
        p = DEFAULT_DB_PATH

    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def get_db_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Creates a new SQLite connection with WAL mode and foreign keys enabled."""
    target_path = db_path or get_db_path()
    conn = sqlite3.connect(
        str(target_path),
        timeout=5.0,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row

    # Performance and integrity pragmas
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.execute("PRAGMA synchronous = NORMAL;")

    return conn


@contextmanager
def get_db(db_path: Optional[Path] = None) -> Generator[sqlite3.Connection, None, None]:
    """Context manager for SQLite database transactions."""
    conn = get_db_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

