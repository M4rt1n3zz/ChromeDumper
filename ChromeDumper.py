import argparse
import os
import datetime
import json
import csv
import base64
import sqlite3
import shutil
import win32crypt

from Crypto.Cipher import AES
from datetime import datetime, timedelta


def get_chrome_datetime(chromedate):
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)


def get_encryption_key(chrome_profile_dir):
    local_state_path = os.path.join(chrome_profile_dir, "Local State")

    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    decrypted_key = win32crypt.CryptUnprotectData(
        encrypted_key[5:], None, None, None, 0
    )[1]

    return decrypted_key


def decrypt_data(data, key):
    iv, encrypted_data = data[3:15], data[15:]
    cipher = AES.new(key, AES.MODE_GCM, iv)
    decrypted_data = cipher.decrypt(encrypted_data)[:-16].decode()
    return decrypted_data


def export_passwords(chrome_profile_dir):
    db_path = os.path.join(chrome_profile_dir, "Default", "Login Data")
    db = sqlite3.connect(db_path)
    cursor = db.cursor()

    cursor.execute(
        """
    SELECT 
        origin_url, action_url, username_value, password_value, date_created, date_last_used 
    FROM 
        logins 
    """
    )

    key = get_encryption_key(chrome_profile_dir)

    password_list = []
    column_names = [description[0] for description in cursor.description]
    for row in cursor.fetchall():
        element = dict(zip(column_names, row))
        element["password"] = (
            decrypt_data(element.get("password_value"), key)
            if element.get("password_value")
            else None
        )
        del element["password_value"]
        element["date_created"] = get_chrome_datetime(element["date_created"])
        element["date_last_used"] = get_chrome_datetime(element["date_last_used"])
        password_list.append(element)
    cursor.close()
    db.close()

    return password_list


def export_downloads(chrome_profile_dir):
    db_path = os.path.join(chrome_profile_dir, "Default", "History")
    db = sqlite3.connect(db_path)
    cursor = db.cursor()
    cursor.execute(
        """
    SELECT
       site_url, end_time, start_time, state, total_bytes, received_bytes,
       danger_type, interrupt_reason, last_modified, mime_type, referrer,
       tab_url, tab_referrer_url, opened, transient
    FROM
        downloads
    """
    )

    download_list = []
    column_names = [description[0] for description in cursor.description]
    for row in cursor.fetchall():
        element = dict(zip(column_names, row))
        element["start_time"] = get_chrome_datetime(element["start_time"])
        element["end_time"] = get_chrome_datetime(element["end_time"])
        download_list.append(element)
    cursor.close()
    db.close()

    return download_list


def export_history(chrome_profile_dir):
    db_path = os.path.join(chrome_profile_dir, "Default", "History")
    db = sqlite3.connect(db_path)
    cursor = db.cursor()

    cursor.execute(
        """
    SELECT 
        title, url, visit_count, last_visit_time
    FROM 
        urls
    """
    )

    history_list = []
    column_names = [description[0] for description in cursor.description]
    for row in cursor.fetchall():
        element = dict(zip(column_names, row))
        element["last_visit_time"] = get_chrome_datetime(element["last_visit_time"])
        history_list.append(element)
    cursor.close()
    db.close()

    return history_list


def export_cookies(chrome_profile_dir):
    db_path = os.path.join(chrome_profile_dir, "Default", "Network", "Cookies")
    db = sqlite3.connect(db_path)
    cursor = db.cursor()

    cursor.execute(
        """
    SELECT 
        host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value 
    FROM 
        cookies
    """
    )

    key = get_encryption_key(chrome_profile_dir)

    cookie_list = []
    column_names = [description[0] for description in cursor.description]
    for row in cursor.fetchall():
        element = dict(zip(column_names, row))
        element["value"] = decrypt_data(
            element.get("value") or element.get("encrypted_value"), key
        )
        del element["encrypted_value"]
        element["creation_utc"] = get_chrome_datetime(element["creation_utc"])
        element["last_access_utc"] = get_chrome_datetime(element["last_access_utc"])
        element["expires_utc"] = get_chrome_datetime(element["expires_utc"])
        cookie_list.append(element)
    cursor.close()
    db.close()

    return cookie_list


def main():
    modules = {
        "passwords": export_passwords,
        "downloads": export_downloads,
        "history": export_history,
        "cookies": export_cookies,
    }

    parser = argparse.ArgumentParser(
        description="Exports data from Google Chrome browser"
    )
    parser.add_argument(
        "-m",
        "--module",
        required=True,
        help="Script to run",
        choices=list(modules.keys()),
    )
    parser.add_argument(
        "-o", "--output", default="json", help="Output format", choices=["json", "csv"]
    )
    parser.add_argument("-p", "--profile", help="Chrome profile", default="User Data")
    parser.add_argument(
        "--user-data",
        help="Chrome user data path",
        default=os.path.join(
            os.environ["USERPROFILE"], "AppData\\Local\\Google\\Chrome"
        ),
    )

    args = parser.parse_args()

    result = modules[args.module](os.path.join(args.user_data, args.profile))

    output_file = f"{args.module}.{args.output}"

    if args.output == "json":
        with open(output_file, "w") as fp:
            json.dump(result, fp, indent=4, sort_keys=True, default=str)
    else:
        with open(output_file, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, result[0].keys())
            writer.writeheader()
            writer.writerows(result)


if __name__ == "__main__":
    main()
