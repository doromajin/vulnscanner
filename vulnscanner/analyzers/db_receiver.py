"""Evidence that a JS `.query()` / `.execute()` / `.run()` call is a database call.

`query`, `execute`, `run`, `all` and `raw` are generic method names: `activitypub.helpers.query(handle)` and
`$.run(...)` are not SQL.  A call counts as SQL only with evidence: a database-looking receiver name, or a file
that loads a database library.
"""
import re

_DB_RECEIVER_RE = re.compile(
    r"db|database|pool|conn|client|knex|sequelize|sql|postgres|prisma|entity|manager|repositor|"
    r"transaction|cursor|stmt|statement|session|orm|"
    r"\b(?:pg|trx?|con|c)\b|models?\b",
    re.IGNORECASE,
)

_DB_LIB_RE = re.compile(
    r"""(?:require\(\s*|from\s+|import\s+)['"](?:mysql2?|pg|pg-promise|sqlite3?|better-sqlite3|knex|sequelize|"""
    r"""typeorm|mssql|oracledb|mariadb|slonik|postgres|drizzle-orm[^'"]*|@prisma/client|@databases/[^'"]*|"""
    r"""mysql2/promise|node-postgres)['"]"""
)

_RECEIVER_BEFORE_DOT_RE = re.compile(r"([\w$.\[\]()'\"]+)$")


def file_loads_db_library(lines: list[str]) -> bool:
    return any(_DB_LIB_RE.search(ln) for ln in lines)


def receiver_looks_like_db(receiver_text: str) -> bool:
    return bool(_DB_RECEIVER_RE.search(receiver_text))


def receiver_before(line: str, dot_index: int) -> str:
    """The expression written in front of the `.` at *dot_index* (for a regex-based scanner)."""
    m = _RECEIVER_BEFORE_DOT_RE.search(line[:dot_index])
    return m.group(1) if m else ""
