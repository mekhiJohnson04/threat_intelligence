import os
import psycopg
from dotenv import load_dotenv
from pathlib import Path

# Same .env the rest of the backend uses (project root)
load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=True)


def get_connection() -> psycopg.Connection:
    """
    Opens a connection to the database in DATABASE_URL.

    TODO:
      1. Read DATABASE_URL from the environment.
      2. If it's missing, raise a clear error (e.g. RuntimeError) instead of
         letting psycopg fail with a confusing message.
      3. Return psycopg.connect(...) with that URL.

    Used as:  with get_connection() as conn:
    psycopg commits when the `with` block ends cleanly and rolls back on an exception.
    """
    url = os.getenv("DATABASE_URL")

    if url is None:
        raise RuntimeError("Database url not in .env")
    
    return psycopg.connect(conninfo=url)
    
