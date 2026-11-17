"""Firebase Firestore synchronization and cloud configuration module for Sentinel Audit.

This module provides bi-directional data synchronization between the relational
SQLite database and Firebase Firestore, as well as dynamic server discovery for
the mobile app.
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

# Add package directory to path if executed standalone
pkg_dir = Path(__file__).resolve().parent
if str(pkg_dir) not in sys.path:
    sys.path.insert(0, str(pkg_dir))

from db import connect, rows

logger = logging.getLogger("sentinel.firebase")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

DEFAULT_PROJECT_ID = "sentinel-audit-cae96"

TABLES_TO_SYNC = (
    "organizations",
    "projects",
    "assets",
    "assessments",
    "findings",
    "controls",
    "control_results",
    "scan_jobs",
)


def get_firestore_client(project_id=None, credentials_path=None):
    """Initializes and returns a Firebase Firestore client."""
    try:
        import firebase_admin
        from firebase_admin import credentials, firestore
    except ImportError:
        logger.error(
            "firebase-admin is not installed. Install with: pip install firebase-admin"
        )
        return None

    if not firebase_admin._apps:
        proj = project_id or os.environ.get("FIREBASE_PROJECT_ID", DEFAULT_PROJECT_ID)
        cred_file = credentials_path or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        if cred_file and Path(cred_file).exists():
            cred = credentials.Certificate(cred_file)
            firebase_admin.initialize_app(cred, {"projectId": proj})
        else:
            firebase_admin.initialize_app(options={"projectId": proj})

    return firestore.client()


def set_server_url(url, project_id=None):
    """Publishes the active cloud server URL to Firestore config/server."""
    db_fs = get_firestore_client(project_id)
    if not db_fs:
        return False
    doc_ref = db_fs.collection("config").document("server")
    doc_ref.set({"url": url.strip().rstrip("/") + "/"}, merge=True)
    logger.info("Published server URL '%s' to Firestore config/server", url)
    return True


def export_sqlite_to_firestore(db=None, project_id=None):
    """Exports SQLite records to Firebase Firestore collections."""
    db_fs = get_firestore_client(project_id)
    if not db_fs:
        return False

    sql_conn = db or connect()
    logger.info("Exporting SQLite data to Firebase Firestore...")

    for table in TABLES_TO_SYNC:
        try:
            records = rows(sql_conn.execute(f"SELECT * FROM {table}"))
            batch = db_fs.batch()
            count = 0
            for record in records:
                doc_id = str(record.get("id"))
                doc_ref = db_fs.collection(table).document(doc_id)
                # Ensure JSON string fields are clean
                doc_data = dict(record)
                batch.set(doc_ref, doc_data, merge=True)
                count += 1
                if count % 450 == 0:
                    batch.commit()
                    batch = db_fs.batch()
            if count % 450 != 0:
                batch.commit()
            logger.info("Synced %d records to Firestore collection '%s'", count, table)
        except Exception as e:
            logger.warning("Could not sync table '%s': %s", table, e)

    return True


def import_firestore_to_sqlite(db=None, project_id=None):
    """Imports Firestore records into the local SQLite database."""
    db_fs = get_firestore_client(project_id)
    if not db_fs:
        return False

    sql_conn = db or connect()
    logger.info("Importing Firebase Firestore collections into SQLite...")

    for table in TABLES_TO_SYNC:
        try:
            docs = db_fs.collection(table).stream()
            count = 0
            for doc in docs:
                data = doc.to_dict()
                if not data:
                    continue
                keys = list(data.keys())
                placeholders = ", ".join(["?" for _ in keys])
                cols = ", ".join(keys)
                vals = [data[k] for k in keys]
                sql = f"INSERT OR REPLACE INTO {table} ({cols}) VALUES ({placeholders})"
                sql_conn.execute(sql, vals)
                count += 1
            sql_conn.commit()
            logger.info("Imported %d records from Firestore collection '%s'", count, table)
        except Exception as e:
            logger.warning("Could not import collection '%s': %s", table, e)

    return True


def main():
    parser = argparse.ArgumentParser(description="Sentinel Audit Firebase Sync Utility")
    parser.add_argument("--export", action="store_true", help="Export SQLite tables to Firestore")
    parser.add_argument("--import-all", action="store_true", help="Import Firestore collections to SQLite")
    parser.add_argument("--set-url", metavar="URL", help="Set the active server URL in Firestore config/server")
    parser.add_argument("--project", default=DEFAULT_PROJECT_ID, help="Firebase/GCP project ID")
    args = parser.parse_args()

    if args.set_url:
        set_server_url(args.set_url, args.project)
    if args.export:
        export_sqlite_to_firestore(project_id=args.project)
    if args.import_all:
        import_firestore_to_sqlite(project_id=args.project)


if __name__ == "__main__":
    main()
