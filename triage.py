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
import re
import subprocess
import json
import os


#---------------------------------------------------
#               PACKING INDICATORS                 ||
#---------------------------------------------------

#sections w/ this randomness are probably compressed or encrypted (Mohanta & Saldanha ch 7 p198: 7.8 packed vs 5.8 unpacked)
high_entropy = 7.0

#nromal programs import tons of stuff, and it's usually fine. A packed program imports
#only what the unpacking stub needs, so importing less is suspect
min_imports = 10

#shortest run of printable chars that count as a string. 4 is strings tool default
min_string_len = 4


#If these are all the imports, chances are the file is packed.
#this would allow the unpacking stub to load the real imports at runtime (hiding real imports)
#(Mohanta & Saldanha)

#Known way to bypass this check- pad the imports with useless imports
#That's why check_packing is built the way it is

loader_apis = {"LoadLibraryA",
               "LoadLibraryW",
               "GetProcAddress",
               "VirtualAlloc",
               "VirtualProtect",
               "ExitProcess"}


#Mapping a "footprint" to the name of the packer
#matching this will show you what packer is used but
#no match doesn't prove anything, since the malware can have no packers
#or use custom packers with no footprint(Mohanta & Saldanha)
packer_sections = {
    "UPX0" : "UPX",
    "UPX1" : "UPX",
    ".UPX0" : "UPX",
    ".UPX1" : "UPX",
    ".aspack" : "ASPack",
    ".adata" : "ASPack",
    ".MPRESS1" : "MPRESS",
    ".MPRESS2" : "MPRESS",
    ".nsp0" : "NsPack",
    ".nsp1" : "NsPack",
    ".nsp2" : "NsPack",
    "pec" : "PECompact",
    "pec1" : "PECompact",
    "pec2" : "PECompact",
    ".RLPack" : "RLPack",
    ".yP" : "Y0da Protector",
    ".y0da" : "Y0da Protector",
    ".Upack" : "Upack",
    ".vmp0" : "VMProtect",
    ".vmp1" : "VMProtect",
    ".vmp2" : "VMProtect",
    "PEPACK!!" : "PEPACK",
    "FSG!" : "FSG"
}

#sections a compiler normally puts the entry point in.
#entry point anywhere else = packer stub probably runs first
code_sections = {
    ".text",
    ".code",
    "CODE",
    "INIT",
    "PAGE"
}

#EXTERNAL TOOLS
tools_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools")
floss_exe = os.path.join(tools_dir, "floss.exe")
capa_exe = os.path.join(tools_dir, "capa.exe")


def get_strings(data):
    """
    STRINGS -> list of text found in the raw bytes.
    1. ASCII runs at least min_string_len long, same idea as unix strings
    2. UTF-16LE runs, printable byte then null byte. FLOSS counted ~200 more
       static strings than me, turned out it reads UTF-16 too. Mohanta ch 22
       GandCrab strings were all unicode (BinText "U" column), mine only saw "A"
    """
    ascii_pat = rb"[\x20-\x7e]{%d,}" % min_string_len
    wide_pat = rb"(?:[\x20-\x7e]\x00){%d,}" % min_string_len
    ascii_strings = [m.decode("ascii") for m in re.findall(ascii_pat, data)]
    wide_strings = [m.decode("utf-16le") for m in re.findall(wide_pat, data)]
    return ascii_strings + wide_strings



def is_dotnet(pe):
    """
    .NET check: Mohanta & Saldanha check file format first since .net samples need
    different tools and the right framwork (ch 12). They use trid; pefile
    can tell by the CLR header in the data directory (memory loc 14)
    """
    d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    return d.VirtualAddress != 0 and d.Size != 0


def get_sections(pe):
    """
    SECTIONS -> list, so check_packing can use them later
    """
    sections = []
    for s in pe.sections:
        #section names = 8 bytes padded w/ nulls
        #strip padding and decode the bytes to string 
        name = s.Name.rstrip(b"\x00").decode("latin-1")
        sections.append({
            "name": name,
            "virtual_address": s.VirtualAddress,
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "entropy": s.get_entropy(),
        })
    return sections


def get_imports(pe):
    """
    IMPORTS -> dict of dll: [function names]
    packed files could have no imports, so I'm double checking
    """
    imports = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("latin-1")
            # imp.name is None = function is imported by number = skip
            imports[dll] = [imp.name.decode("latin-1") for imp in entry.imports if imp.name]
    return imports


def check_packing(pe, sections, imports, dotnet):
    """
    PACKING ASSESSMENT
    1. high entropy / empty sections
    2. known packer section names
    3. entry point location
    4. import table (chekc imports)
    returns (signals, verdict)
    """
    signals = []

    #1. HIGH ENTROPY OR EMPTY SECTIONS
    #raw_size 0 but has a virtual size = gets filled at runtime (Ligh et al.)
    for s in sections:
        if s["entropy"] > high_entropy and s["raw_size"] > 0:
            signals.append(f"section {s['name']} has entropy {s['entropy']:.2f} (> {high_entropy})")
        if s["raw_size"] == 0 and s["virtual_size"] > 0:
            signals.append(f"section {s['name']} is empty on disk but {s['virtual_size']} bytes in memory")

    #2. KNOWN PACKER SECTION NAMES
    for s in sections:
        if s["name"] in packer_sections:
            signals.append(f"section {s['name']} is a {packer_sections[s['name']]} section name")

    #3. ENTRY POINT
    #entry point outside a code section or in the last section = suspect (Ligh et al.)
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for i, s in enumerate(sections):
        if s["virtual_address"] <= ep < s["virtual_address"] + max(s["virtual_size"], s["raw_size"]):
            if s["name"] not in code_sections:
                signals.append(f"entry point is in section {s['name']}, not a normal code section")
            elif i == len(sections) - 1 and len(sections) > 1:
                signals.append(f"entry point is in the last section ({s['name']})")
            break


    #4. IMPORT TABLE
    #ran InstallUtil.exe (clean .NET) and this rule ran on 0 imports. Did a little digging
    # and foudn that .NET hands off to the runtime through the CLR header so a tiny or missing table 
    #doesn't mean packed here. rule stays for native PEs
    #(Mohanta ch 17 p646, packed = only what the loader stub needs)
    if not dotnet:
        
        all_names = {n for names in imports.values() for n in names}

        if len(all_names) < min_imports:
            signals.append(f"only {len(all_names)} imported functions (< {min_imports})")
        if all_names and all_names <= loader_apis:
            signals.append("imports limited to loader APIs (LoadLibrary/GetProcAddress)")

    #VERDICT
    #These are my thresholds, explained earlier in the code.
    score = len(signals)
    if score >= 4:
        verdict = "likely packed or obfuscated"
    elif score >= 2:
        verdict = "possible packing, review manually"
    else:
        verdict = "no strong packing indicators"
    return signals, verdict


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
    4. Strings
    4. Packing assessment

    pefile.PE() parses headers from bytes in memory (above)
    If the file isn't valid, it raises PEFormatError, which doubles as my file type check
    """

    try:
        pe = pefile.PE(data=data)
    except pefile.PEFormatError:
        print("\nNot a PE file, skipping header analysis")
        return

    dotnet = is_dotnet(pe)
    print(f"\n.NET assembly: {'yes' if dotnet else 'no'}")
 
    #COMPILE TIME
    #Since the compiler writes in Unix time, malware authors can forge it
    #notepad.exe came back as 1979, so printed for reference only, not a packing signal
    ts = pe.FILE_HEADER.TimeDateStamp
    compiled = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    print(f"Compiled: {compiled:%Y-%m-%d %H:%M:%S} UTC (info only)")

 
    #SECTIONS
    """
    All PEs are split into sections.
    Entropy measures how random the bytes look, 0 - 8.
    The closer to 8 the score goes, the more it looks like the file 
    has been packed.

    """
    sections = get_sections(pe)
    print("\nSections:")
    print(f"  {'Name':<10}{'VirtSize':>10}{'RawSize':>10}{'Entropy':>9}")
    for s in sections:
        flag = "  <-- high" if s["entropy"] > high_entropy else ""
        print(f"  {s['name']:<10}{s['virtual_size']:>10}{s['raw_size']:>10}{s['entropy']:>9.2f}{flag}")
 
    #IMPORTS
    #This checks for what the program is asking to import
    imports = get_imports(pe)
    print("\nImports:")
    if imports:
        for dll, names in imports.items():
            print(f"  {dll} ({len(names)} functions)")
    else:
        print("  (no import table)")
    print(f"  Total imported functions: {sum(len(n) for n in imports.values())}")

    #STRINGS
    #readable txt in the file. URL, path, registry keys, etc. will show up 
    #here on an unpacked file.
    #On a packed file, this will be junk (Mohanta & Saldanha)
    strings = get_strings(data)
    print(f"\nStrings: {len(strings)} found (showing 20 longest)")
    for s in sorted(strings, key = len, reverse = True)[:20]:
        print(f"    {s[:100]}")

    #PACKING ASSESSMENT
    signals, verdict = check_packing(pe, sections, imports, dotnet)
    print(f"\nPacking assessment: {verdict}")
    for sig in signals:
        print(f"  - {sig}")
    if dotnet: #so ppl know if its .net and it ran or not
        print("  (import rules skipped: .NET assembly)")







def print_floss(found, limit=30):
    """
    FLOSS section  print
    1. counts for all 4 kinds on one line
    2. print the runtime-built ones (stack/tight/decoded). these are what
       packing hides from plain string extraction, so they're what I'm mainly interested in
    3. static strings already shown above so I'm not going to print them here
    """
    print("\nFLOSS:")
    if found is None:
        print("  can't get.")
        return

    counts = ", ".join(f"{k} {len(v)}" for k, v in found.items())
    print(f"  {counts}")

    for kind in ("stack", "tight", "decoded"):
        strings = found[kind]
        if not strings:
            continue
        print(f"  {kind} strings ({len(strings)}):")
        for s in strings[:limit]: #limit in args to stop flooding
            print(f"    {s}")


"""
ADDING FLOSS

This runs my installed floss.exe as a child process and then reads the JSON instead of a file on disk

"""
def run_floss(path, min_len=4):
    """
    1. make sure floss.exe is in tools\
    2. run it with -j so the output is JSON
    3. bail (None) if it failed or timed out
    4. pull the 4 string lists out of the JSON
    """
    if not os.path.exists(floss_exe):
        print("FLOSS: tools\\floss.exe not there, install first.")
        return None

    #one list element / arg
    cmd = [floss_exe, "-j", "-n", str(min_len), path]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600, stdin=subprocess.DEVNULL)
        #DEVNULL = empty input so floss's promtpts for .NET will take the default
    except subprocess.TimeoutExpired:
        print("FLOSS: timeout > 600s")
        return None

    #non-zero = floss errors out
    #.NET files don't go here, floss exits 0 and returns static strings...
    if result.returncode != 0:
        print("FLOSS can't run:", result.stderr.strip().splitlines()[-1])
        return None

    #on on eof my first passes with FLOSS< it warned me that the string extraction isn't supported
    #And it warns that it won't deobfuscate.
    #Adding this for clarity in the returns
    for line in result.stderr.splitlines():
        if "WARNING" in line:
            print("FLOSS:", line.strip())

    data = json.loads(result.stdout)
    found = {}
    for kind in ("static", "stack", "tight", "decoded"):
        #each entry = dict, the text is under "string"
        found[kind] = [s["string"] for s in data["strings"].get(kind + "_strings", [])]
    return found



#============================================================================

def main():
    if len(sys.argv) != 2:
        print("python triage.py <file>")
        sys.exit(1) #error

    path = sys.argv[1]

    with open(path, "rb") as f: #read the whole file as bytes
        data = f.read()

    print_hashes(path, data)
    print_pe_info(data)
    floss = run_floss(path)
    print_floss(floss)

    

if __name__ == "__main__":
    main()