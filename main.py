'''
CS4238 Homework 3
Lau Jun Hao Benjamin
A0184084B
'''
import sys
import hashlib
import math
import pefile
import peutils

sig_db = peutils.SignatureDatabase('signatures_long.txt')

def find_entry_point_section(pe, eop_rva):
    for section in pe.sections:
        if section.contains_rva(eop_rva):
            return section
    return None

def rawToRva(pe, Raw):
    sections = [s for s in pe.sections if s.contains_offset(Raw)]
    if sections:
        section = sections[0]
        return (Raw - section.PointerToRawData) + section.VirtualAddress
    else:
        return 0

def getSectionInfo(pe, Va):
    sec = pe.get_section_by_rva(Va - pe.OPTIONAL_HEADER.ImageBase)
    if sec:
        # Get section number ..
        sn = 0
        for i in range(pe.FILE_HEADER.NumberOfSections):
            if pe.sections[i] == sec:
                sn = i + 1
                break
        # Get section name ..
        name = ""
        for j in range(7):
            # Only until first null ..
            if sec.Name[j] == chr(0):
                break
            name = "%s%s" % (name, sec.Name[j])
        # If name is not blank then set name string to ', "<name>"'' ..
        if name != "":
            name = ", \"%s\"" % name
        # Return section number and name (if exist) ..
        return " (section #%02d%s)" % (sn, name)
    return " (not in a section)"

def getEntropy(data):
    """Calculate the entropy of a chunk of data."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(list(data).count(chr(x)))/len(data)
        if p_x > 0:
          entropy += - p_x*math.log(p_x, 2)
    return entropy

def get_packers(pe):
    EP_Only = True
    e = getEntropy( pe.__data__ )
    a = is_packed(e)
    '''
    if EP_Only == 1:
        print("  o %d EntryPoint sigs to scan .." % sig_db.signature_count_eponly_true)
        print("  o Scanning Entrypoint ..")
    else:
        print("  o %d sigs to scan in hardcore mode .." % sig_db.signature_count_eponly_false)
        print("  o Scanning whole file ..")
    '''
    # Force update now or user will not know any info until scan finished ..
    # Which can take minutes for a large file scanned with -a option ..
    # Do the scan, EP only or hardcore mode ..
    ret = sig_db.match( pe, EP_Only == 1 )
    # Display results of scan ..
    if not ret:
        return "Nothing found .."
    if EP_Only == 1:
        # If EP detection then result is a string and we know EP address ..
        va = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        addr = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        return "Found \"%s\" at 0x%08X %s" % (ret[0], addr, getSectionInfo(pe, va))
    else:
        # If more than 1 returned detection, then display all possibilities ..
        if len(ret) > 1:
            a = 1
            output = ""
            for (addr, name) in ret:
                va = pe.OPTIONAL_HEADER.ImageBase + rawToRva(pe, addr)
                output = output + ('\n  %02d : \"%s\" at offset 0x%08X %s' % (a, name[0], addr, getSectionInfo(pe, va)))
                a += 1
            return "Found %d possible matches .. %s" % (len(ret), output)
        else:
            # If only 1 detection then display result ..
            for (addr, name) in ret:
                va = pe.OPTIONAL_HEADER.ImageBase + rawToRva(pe, addr)
                return "Found \"%s\" at 0x%08X %s" % (ret[0], addr, getSectionInfo(pe, va))

def is_packed(e):
    if e < 6.0:
        return "Not packed"
    elif e < 7.0:
        return "Maybe packed"
    else:  # 7.0 .. 8.0
        return "Packed"

def main(file_path):
    print("===========================================\nOpening {}".format(file_path))

    try:
        pe = pefile.PE(file_path, fast_load=True)
        x = pe.FILE_HEADER
        characteristics = x.dump_dict()['Characteristics']['Value']
        IMAGE_FILE_EXECUTABLE_IMAGE = 0x0100
        IMAGE_FILE_DLL = 0x2000
        IMAGE_FILE_SYSTEM = 0x1000
        if (characteristics & IMAGE_FILE_DLL):
            print("2a. File is DLL")
        elif (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE):
            print("2a. File is EXE")
        elif (characteristics & IMAGE_FILE_SYSTEM):
            print("2a. File is SYS")
        else:
            print("2a. File is neither EXE, DLL nor SYS")
        # print("Machine : " + hex(pe.FILE_HEADER.Machine))
        # Check if it is a 32-bit or 64-bit binary
        #if hex(pe.FILE_HEADER.Machine) == '0x14c':
        #    print("This is a 32-bit binary")
        #else:
        #    print("This is a 64-bit binary")
        # print("NumberOfSections : " + hex(pe.FILE_HEADER.NumberOfSections))
        # print("Characteristics flags : " + hex(pe.FILE_HEADER.Characteristics))
        pe.parse_data_directories()

        dllCount = 0
        functionCount = 0
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            # print(entry.dll)
            dllCount = dllCount + 1
            for imp in entry.imports:
                functionCount = functionCount + 1
                # print('\t', hex(imp.address), imp.name)

        print("2b. Total DLLs: %d" % dllCount)
        print("2c. Total Functions: %d" % functionCount)
        print("3.  Compile Time: " + pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1])
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        # print("Entry Point: 0x%X" % ep)
        allowed_sections = [".text", ".code", "CODE", "INIT"]
        for section in pe.sections:
            section_name = section.Name.decode("utf-8").rstrip('\x00')
            # print(section_name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData)
            if (ep > section.VirtualAddress and ep <= section.VirtualAddress + section.Misc_VirtualSize):
                if section_name in allowed_sections:
                    print("4.  EP is in Allowed Section %s" % section_name)
                else:
                    print("4.  EP is in Disallowed Section %s" % section_name)
        print("5.  Packer Used: %s" % get_packers(pe))
        print("6.  Entropy by Section")
        for section in pe.sections:
            section_name = section.Name.decode("utf-8").rstrip('\x00')
            e = section.get_entropy()
            print("       Entropy for section %8s: %.2f (%s)" % (section_name, e, is_packed(e)))
        print("7.  Zero sized sections: ", end="")
        empty = True
        for section in pe.sections:
            if section.Misc_VirtualSize == 0:
                empty = False
                section_name = section.Name.decode("utf-8").rstrip('\x00')
                e = section.get_entropy()
                print("\n       Zero sized section %9s: %.2f" % (section_name, section.Misc_VirtualSize))
        if empty:
            print("None")
        pe_checksum = hex(pe.OPTIONAL_HEADER.CheckSum)
        act_checksum = hex(pe.generate_checksum())
        print("8.  Checksums %s" % ("Match" if pe_checksum == act_checksum else "Mismatch!!!"))
        print("       PE Optional Header Checksum : ", pe_checksum)
        print("       Actual Checksum             : ", act_checksum)
        
        # Dump Resources
        print("9.  Dump Resources")
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.name is not None:
                    name = "%s" % resource_type.name
                else:
                    name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
                if name == None:
                    name = "%d" % resource_type.struct.Id
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                resource_md5 = str(hashlib.md5(data).hexdigest())
                                resource_filename = file_path + "-RESOURCE-" + name + "-" + resource_md5 + ".rsrc"
                                resource_dump = open(resource_filename, "wb+")
                                resource_dump.write(data)
                                resource_dump.close()
                                print("       Dumped Resource Section %s into %s" % (name, resource_filename))
        else:
            print("No resource sections found")
        x = "done"
    except pefile.PEFormatError as pe_err:
        print("[-] Error while parsing PE file {}:\n\t{}".format(file_path, pe_err))

if __name__ == '__main__':
    n = len(sys.argv)
    if n == 1:
        print("No file(s) specified. Please enter the path to the file(s) you would like to analyse.")
        print("e.g. python main.py samples/calc.exe samples/packed.exe")
    for i in range(1, n):
        main(sys.argv[i])