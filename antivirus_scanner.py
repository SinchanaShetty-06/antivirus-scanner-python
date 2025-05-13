import os
import hashlib
import shutil

# Path to directory to scan
SCAN_DIRECTORY = "sample_files"

# Sample virus signatures (normally you'd use a large database)
KNOWN_VIRUS_SIGNATURES = {
    "e99a18c428cb38d5f260853678922e03",  # example MD5 hash
    "098f6bcd4621d373cade4e832627b4f6"   # another example hash
}

# Quarantine folder
QUARANTINE_FOLDER = "quarantine"

def calculate_md5(file_path):
    with open(file_path, "rb") as f:
        file_hash = hashlib.md5()
        while chunk := f.read(4096):
            file_hash.update(chunk)
    return file_hash.hexdigest()

def scan_files(directory):
    print(f"Scanning directory: {directory}")
    infected_files = []

    for root, dirs, files in os.walk(directory):
        for filename in files:
            full_path = os.path.join(root, filename)
            file_hash = calculate_md5(full_path)
            if file_hash in KNOWN_VIRUS_SIGNATURES:
                print(f"[!] Infected file detected: {full_path}")
                infected_files.append(full_path)

    return infected_files

def quarantine_files(files):
    if not os.path.exists(QUARANTINE_FOLDER):
        os.makedirs(QUARANTINE_FOLDER)

    for file_path in files:
        try:
            shutil.move(file_path, QUARANTINE_FOLDER)
            print(f"[+] Quarantined: {file_path}")
        except Exception as e:
            print(f"[!] Failed to quarantine {file_path}: {e}")

if __name__ == "__main__":
    infected = scan_files(SCAN_DIRECTORY)
    if infected:
        quarantine_files(infected)
    else:
        print("No threats detected. System is clean.")
