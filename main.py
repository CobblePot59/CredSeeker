from dpapi_utils import is_admin
from chromium_extractor import fetch_chromium_passwords
from mozilla_extractor import fetch_firefox_passwords, fetch_thunderbird_passwords

def main():
    if not is_admin():
        print("Run as administrator")
        return

    print("=== Chromium ===")
    try:
        passwords = fetch_chromium_passwords()
        print(f"Found {len(passwords)} passwords")
        for p in passwords:
            print(f"{p['browser']} | {p['url']} | {p['username']} | {p['password']}")
    except Exception as e:
        print(f"Error: {e}")
    
    print("\n=== Firefox ===")
    try:
        passwords = fetch_firefox_passwords()
        print(f"Found {len(passwords)} passwords")
        for p in passwords:
            print(f"{p['browser']} | {p['url']} | {p['username']} | {p['password']}")
    except Exception as e:
        print(f"Error: {e}")
    
    print("\n=== Thunderbird ===")
    try:
        passwords = fetch_thunderbird_passwords()
        print(f"Found {len(passwords)} passwords")
        for p in passwords:
            print(f"{p['browser']} | {p['url']} | {p['username']} | {p['password']}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()

