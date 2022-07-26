import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
from datetime import timezone, datetime, timedelta


def chrome_finder():
    def get_chrome_datetime(chromedate):
        """Return a `datetime.datetime` object from a chrome format datetime
        Since `chromedate` is formatted as the number of microseconds since January, 1601"""
        return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

    def get_encryption_key():
        local_state_path = os.path.join(os.environ["USERPROFILE"],
                                        "AppData", "Local", "Google", "Chrome",
                                        "User Data", "Local State")
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)

        # decode the encryption key from Base64
        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        # remove DPAPI str
        key = key[5:]
        # return decrypted key that was originally encrypted
        # using a session key derived from current user's logon credentials
        # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

    def decrypt_password(password, key):
        try:
            # get the initialization vector
            iv = password[3:15]
            password = password[15:]
            # generate cipher
            cipher = AES.new(key, AES.MODE_GCM, iv)
            # decrypt password
            return cipher.decrypt(password)[:-16].decode()
        except:
            try:
                return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
            except:
                # not supported
                return ""
    def chrome_main():
        # get the AES key
        key = get_encryption_key()
        # local sqlite Chrome database path
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                                "Google", "Chrome", "User Data", "default", "Login Data For Account")
        # copy the file to another location
        # as the database will be locked if chrome is currently running
        filename = "ChromeData.db"
        shutil.copyfile(db_path, filename)
        # connect to the database
        db = sqlite3.connect(filename)
        cursor = db.cursor()
        # `logins` table has the data we need
        cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
        # iterate over all rows
        for row in cursor.fetchall():
            origin_url = row[0]
            action_url = row[1]
            username = row[2]
            password = decrypt_password(row[3], key)
            date_created = row[4]
            date_last_used = row[5]        
            if username or password:
                print(f"Origin URL: {origin_url}")
                print(f"Action URL: {action_url}")
                print(f"Username: {username}")
                print(f"Password: {password}")
            else:
                continue
            if date_created != 86400000000 and date_created:
                print(f"Creation date: {str(get_chrome_datetime(date_created))}")
            if date_last_used != 86400000000 and date_last_used:
                print(f"Last Used: {str(get_chrome_datetime(date_last_used))}")
            print("="*50)
        cursor.close()
        db.close()
        try:
            # try to remove the copied db file
            os.remove(filename)
        except:
            pass
    if __name__ == "__main__":
        chrome_main()

def chrome_finder_sub(): # This checks if the google account has any stored passwords
    def get_chrome_datetime(chromedate):
        """Return a `datetime.datetime` object from a chrome format datetime
        Since `chromedate` is formatted as the number of microseconds since January, 1601"""
        return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

    def get_encryption_key():
        local_state_path = os.path.join(os.environ["USERPROFILE"],
                                        "AppData", "Local", "Google", "Chrome",
                                        "User Data", "Local State")
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)

        # decode the encryption key from Base64
        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        # remove DPAPI str
        key = key[5:]
        # return decrypted key that was originally encrypted
        # using a session key derived from current user's logon credentials
        # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

    def decrypt_password(password, key):
        try:
            # get the initialization vector
            iv = password[3:15]
            password = password[15:]
            # generate cipher
            cipher = AES.new(key, AES.MODE_GCM, iv)
            # decrypt password
            return cipher.decrypt(password)[:-16].decode()
        except:
            try:
                return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
            except:
                # not supported
                return ""
    def chrome_main_sub():
        # get the AES key
        key = get_encryption_key()
        # local sqlite Chrome database path
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                                "Google", "Chrome", "User Data", "default", "Login Data")
        # copy the file to another location
        # as the database will be locked if chrome is currently running
        filename = "ChromeData.db"
        shutil.copyfile(db_path, filename)
        # connect to the database
        db = sqlite3.connect(filename)
        cursor = db.cursor()
        # `logins` table has the data we need
        cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
        # iterate over all rows
        for row in cursor.fetchall():
            origin_url = row[0]
            action_url = row[1]
            username = row[2]
            password = decrypt_password(row[3], key)
            date_created = row[4]
            date_last_used = row[5]        
            if username or password:
                print(f"Origin URL: {origin_url}")
                print(f"Action URL: {action_url}")
                print(f"Username: {username}")
                print(f"Password: {password}")
            else:
                continue
            if date_created != 86400000000 and date_created:
                print(f"Creation date: {str(get_chrome_datetime(date_created))}")
            if date_last_used != 86400000000 and date_last_used:
                print(f"Last Used: {str(get_chrome_datetime(date_last_used))}")
            print("="*50)
        cursor.close()
        db.close()
        try:
            # try to remove the copied db file
            os.remove(filename)
        except:
            pass
    if __name__ == "__main__":
        chrome_main_sub()

def edge_finder():
    def get_edge_datetime(edgedate):
        """Return a `datetime.datetime` object from a edge format datetime
        Since `edgedate` is formatted as the number of microseconds since January, 1601"""
        return datetime(1601, 1, 1) + timedelta(microseconds=edgedate)

    def get_encryption_key():
        local_state_path = os.path.join(os.environ["USERPROFILE"],
                                        "AppData", "Local", "Microsoft", "Edge",
                                        "User Data", "Local State")
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)

        # decode the encryption key from Base64
        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        # remove DPAPI str
        key = key[5:]
        # return decrypted key that was originally encrypted
        # using a session key derived from current user's logon credentials
        # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

    def decrypt_password(password, key):
        try:
            # get the initialization vector
            iv = password[3:15]
            password = password[15:]
            # generate cipher
            cipher = AES.new(key, AES.MODE_GCM, iv)
            # decrypt password
            return cipher.decrypt(password)[:-16].decode()
        except:
            try:
                return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
            except:
                # not supported
                return ""
    def edge_main():
        # get the AES key
        key = get_encryption_key()
        # local sqlite edge database path
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                                "Microsoft", "Edge", "User Data", "Default", "Login Data")
        # copy the file to another location
        # as the database will be locked if edge is currently running
        filename = "edgeData.db"
        shutil.copyfile(db_path, filename)
        # connect to the database
        db = sqlite3.connect(filename)
        cursor = db.cursor()
        # `logins` table has the data we need
        cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
        # iterate over all rows
        for row in cursor.fetchall():
            origin_url = row[0]
            action_url = row[1]
            username = row[2]
            password = decrypt_password(row[3], key)
            date_created = row[4]
            date_last_used = row[5]        
            if username or password:
                print(f"Origin URL: {origin_url}")
                print(f"Action URL: {action_url}")
                print(f"Username: {username}")
                print(f"Password: {password}")
            else:
                continue
            if date_created != 86400000000 and date_created:
                print(f"Creation date: {str(get_edge_datetime(date_created))}")
            if date_last_used != 86400000000 and date_last_used:
                print(f"Last Used: {str(get_edge_datetime(date_last_used))}")
            print("="*50)
        cursor.close()
        db.close()
        try:
            # try to remove the copied db file
            os.remove(filename)
        except:
            pass
    if __name__ == "__main__":
        edge_main()

def opera_finder():
    def get_opera_datetime(operadate):
        """Return a `datetime.datetime` object from a opera format datetime
        Since `operadate` is formatted as the number of microseconds since January, 1601"""
        return datetime(1601, 1, 1) + timedelta(microseconds=operadate)

    def get_encryption_key():
        local_state_path = os.path.join(os.environ["USERPROFILE"],
                                        "AppData", "Roaming", "Opera Software", "Opera Stable", "Local State")
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)

        # decode the encryption key from Base64
        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        # remove DPAPI str
        key = key[5:]
        # return decrypted key that was originally encrypted
        # using a session key derived from current user's logon credentials
        # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

    def decrypt_password(password, key):
        try:
            # get the initialization vector
            iv = password[3:15]
            password = password[15:]
            # generate cipher
            cipher = AES.new(key, AES.MODE_GCM, iv)
            # decrypt password
            return cipher.decrypt(password)[:-16].decode()
        except:
            try:
                return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
            except:
                # not supported
                return ""
    def opera_main():
        # get the AES key
        key = get_encryption_key()
        # local sqlite opera database path
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Roaming",
                                "Opera Software", "Opera Stable", "Login Data")
        # copy the file to another location
        # as the database will be locked if opera is currently running
        filename = "operaData.db"
        shutil.copyfile(db_path, filename)
        # connect to the database
        db = sqlite3.connect(filename)
        cursor = db.cursor()
        # `logins` table has the data we need
        cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
        # iterate over all rows
        for row in cursor.fetchall():
            origin_url = row[0]
            action_url = row[1]
            username = row[2]
            password = decrypt_password(row[3], key)
            date_created = row[4]
            date_last_used = row[5]        
            if username or password:
                print(f"Origin URL: {origin_url}")
                print(f"Action URL: {action_url}")
                print(f"Username: {username}")
                print(f"Password: {password}")
            else:
                continue
            if date_created != 86400000000 and date_created:
                print(f"Creation date: {str(get_opera_datetime(date_created))}")
            if date_last_used != 86400000000 and date_last_used:
                print(f"Last Used: {str(get_opera_datetime(date_last_used))}")
            print("="*50)
        cursor.close()
        db.close()
        try:
            # try to remove the copied db file
            os.remove(filename)
        except:
            pass
    if __name__ == "__main__":
        opera_main()

browser_choise = input('Chrome, Edge, Opera, All: ')



if browser_choise.lower() == 'all':

    try:
        chrome_finder()
    except FileNotFoundError:
        print('\n\nChrome not installed')
    
    try:
        chrome_finder_sub()
    except FileNotFoundError:
        print('\n\nNo account passwords found')
    
    try:
        edge_finder()
    except FileNotFoundError:
        print('\n\nMicrosoft Edge not installed')
    
    try:
        opera_finder()
    except FileNotFoundError:
        print('\n\nOpera is not installed')

if browser_choise.lower() == 'chrome':
    try:
        chrome_finder()
    except FileNotFoundError:
        print('Chrome not installed')
        input('\nPress Enter to Exit...')
        quit()
    try:
        chrome_finder_sub()
    except FileNotFoundError:
        print('\n\nNo account passwords found')
elif browser_choise.lower() == 'edge':
    try:
        edge_finder()
    except FileNotFoundError:
        print('Microsoft Edge not installed')
        input('\nPress Enter to Exit...')
        quit()
elif browser_choise.lower() == 'opera':
    try:
        opera_finder()
    except FileNotFoundError:
        print('Opera is not installed')
        input('\nPress Enter to Exit...')
        quit()








# When the code ends this will stop it from exiting immediatly
input('\n\n\nThis is the End...')
