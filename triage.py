"""
triage.py

As stated in my thesis, when doing malware triage, analysts typically do a
first pass using static analysis methods.
This is becasue static analysis is faster, cheaper, and doesn't actually run the 
suspected malware.

This triage.py is a sample of what that first pass may look like. All it 
does is prints the size and hashes of a file, so that the malware sample can be identified
and matched against other sandbox reports. The file is read only to keep it safe and
keep it static.


Then, I use the pefile library to read the structure of the windows executable:
1. When it was compiled
2. What sections it has
3. What functions it imports

"""

import hashlib #used for md5, sha1, and sha256
import datetime
import sys
import pefile #library that parses the PE format



def print_hashes(path, data):
    """
    IDENTITY of the sample
    1. Size
    2. 3 different hashes
    """
    #MalwareBazaar and VirusTotal are keyed on SHA256
    #Older reports tend to be MD5
    #hedigest() returns the hash as a string
    print(f"File:   {path}")
    print(f"Size:   {len(data)} bytes")
    print(f"MD5:    {hashlib.md5(data).hexdigest()}")
    print(f"SHA1:   {hashlib.sha1(data).hexdigest()}")
    print(f"SHA256: {hashlib.sha256(data).hexdigest()}")


def print_pe_info(data):
    """
    STRUCTURE of the sample
    1. Compile time
    2. Sections
    3. Imports

    pefile.PE() parses headers from bytes in memory (above)
    If the file isn't valid, it raises PEFormatError, which doubles as my file type check
    """

    try:
        pe = pefile.PE(data=data)
    except pefile.PEFormatError:
        print("\nNot a PE file, skipping header analysis")
        return
 
    #COMPILE TIME
    #Since the compiler writes in Unix time, malware authors can forge it
    ts = pe.FILE_HEADER.TimeDateStamp
    compiled = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    print(f"\nCompiled: {compiled:%Y-%m-%d %H:%M:%S} UTC")


 
    #SECTIONS
    """
    All PEs are split into sections.
    Entropy measures how random the bytes look, 0 - 8.
    The closer to 8 the score goes, the more it looks like the file 
    has been packed.

    """
    print("\nSections:")
    print(f"  {'Name':<10}{'VirtSize':>10}{'RawSize':>10}{'Entropy':>9}")
    for s in pe.sections:
        #section names are 8 bytes padded with nulls
        #strip the padding and decode the bytes to string
        name = s.Name.rstrip(b"\x00").decode("latin-1")
        print(f"  {name:<10}{s.Misc_VirtualSize:>10}{s.SizeOfRawData:>10}{s.get_entropy():>9.2f}")
 
    #IMPORTS
    #This checks for what the program is asking to import
    #packed files could have no imports, double check
    print("\nImports:")
    total = 0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("latin-1")
            # imp.name is None = function is imported by number = skip
            names = [imp.name.decode("latin-1") for imp in entry.imports if imp.name]
            total += len(names)
            print(f"  {dll} ({len(names)} functions)")
    else:
        print("  (no import table)")
    print(f"  Total imported functions: {total}")
 



def main():
    if len(sys.argv) != 2:
        print("Usage: python triage.py <file>")
        sys.exit(1) #error

    path = sys.argv[1]

    with open(path, "rb") as f: #read the whole file as bytes
        data = f.read()

    print_hashes(path, data)
    print_pe_info(data)

    

if __name__ == "__main__":
    main()