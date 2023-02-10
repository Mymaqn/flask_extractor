import argparse

parser = argparse.ArgumentParser(prog = 'flask_dumper', description = 'Dumps the memory of a process to use with flask_extractor')

parser.add_argument('-p', '--pid', type=int, help="PID of process to dump",required=True)
parser.add_argument('-o', '--output', type=str, help="Optional output file prefix, if none specified uses flaskdmp.dmp and flaskdmp.maps. No matter what filename specified it will always end in .dmp and .maps", default="flaskdmp")

args = parser.parse_args()


def dump(pid):
    with open(f"/proc/{pid}/maps") as fd:
        maps = fd.readlines()
    to_dump = []
    for entry in maps:
        if "[vdso]" in entry:
            continue
        if "[stack]" in entry:
            continue
        if "[vvar]" in entry:
            continue
        if "[vsyscall]" in entry:
            continue
        start_addr = int(entry.split("-")[0],16)
        end_addr = int(entry.split("-")[1].split(" ")[0],16)
        size = end_addr - start_addr
        
        tmp_dict = {
            "entry":entry,
            "start":start_addr,
            "end":end_addr,
            "size":size
        }
        to_dump.append(tmp_dict)
    dump = b''
    memfd = open(f"/proc/{pid}/mem","rb")
    print("DUMPING:")
    for dumpable in to_dump:
        print(dumpable["start"])
        print(dumpable["entry"],end="")
        memfd.seek(dumpable["start"])

        dump+=memfd.read(dumpable["size"])
    return dump, maps

full_dmp = dump(args.pid)
with open(f"{args.output}.dmp","wb") as f:
    f.write(full_dmp[0])

with open(f"{args.output}.maps","w") as f:
    f.writelines(full_dmp[1])


