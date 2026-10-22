"""
triage.py

As stated in my thesis, when doing malware triage, analysts typically do a
first pass using static analysis methods.
This is becasue static analysis is faster, cheaper, and doesn't actually run the 
suspected malware.

This triage.py is a very limited sample of what that first pass may look like. All it 
does is prints the size and hashes of a file, so that the malware sample can be identified
and matched against other sandbox reports. The file is read only to keep it safe and
keep it static.


"""

import hashlib #used for md5, sha1, and sha256
import sys



def main():
    if len(sys.argv) != 2:
        print("Usage: python triage.py <file>")
        sys.exit(1) #error

    path = sys.argv[1]

    with open(path, "rb") as f: #read the whole file as bytes
        data = f.read()

    #MalwareBazaar and VirusTotal are keyed on SHA256
    #Older reports tend to be MD5
    #hedigest() returns the hash as a string
    print(f"File:   {path}")
    print(f"Size:   {len(data)} bytes")
    print(f"MD5:    {hashlib.md5(data).hexdigest()}")
    print(f"SHA1:   {hashlib.sha1(data).hexdigest()}")
    print(f"SHA256: {hashlib.sha256(data).hexdigest()}")

if __name__ == "__main__":
    main()