import os


def is_database_initialized() -> bool:
    """Check if the database file exists."""
    db_path = os.path.join(os.getcwd(), 'storage.db')
    return os.path.exists(db_path)
