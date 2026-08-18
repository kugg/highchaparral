from app.license import verify_license, get_license_status

def main():
    if not verify_license():
        print("ERROR: Invalid or missing license. Set OPLANE_API_KEY.")
        return 1
    
    status = get_license_status()
    print(f"Licensed: {status['key_prefix']} (length {status['key_length']})")
    return 0

if __name__ == "__main__":
    exit(main())
