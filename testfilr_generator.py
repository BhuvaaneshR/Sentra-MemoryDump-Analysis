import os

def create_dummy_dump(filename, size_in_mb):
    """
    Creates a dummy file with specific extension and size to test 
    upload limits and extension validation.
    
    Args:
        filename (str): Name of the file (e.g., 'test_upload.mem')
        size_in_mb (int): Size in Megabytes
    """
    try:
        # Security Check: Ensure safe extension
        allowed_extensions = ['.raw', '.mem', '.dmp']
        _, ext = os.path.splitext(filename)
        
        if ext not in allowed_extensions:
            print(f"[ERROR] Unsafe extension '{ext}'. Use .raw, .mem, or .dmp")
            return

        print(f"[INFO] Generating {filename} ({size_in_mb} MB)...")
        
        # Write dummy bytes (Zeros) - Secure and clean
        with open(filename, 'wb') as f:
            f.seek((size_in_mb * 1024 * 1024) - 1)
            f.write(b'\0')
            
        print(f"[SUCCESS] File created: {os.path.abspath(filename)}")
        print("[NOTE] This file is for UPLOAD TESTING only. It contains no forensic data.")

    except Exception as e:
        print(f"[ERROR] Failed to create file: {e}")

# --- Execution ---
if __name__ == "__main__":
    # 1. Create a "Small" file to test success (e.g., 50MB)
    create_dummy_dump("small_test_clean.mem", 50)

    # 2. Create a "Large" file to test upload limits (e.g., 2GB)
    # Uncomment to generate: 
    # create_dummy_dump("large_stress_test.raw", 2048)