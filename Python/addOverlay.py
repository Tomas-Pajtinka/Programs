import argparse, os, struct, pefile


def getSize(file):
    pe = pefile.PE(file,fast_load=True)
    return pe.get_overlay_data_start_offset()

def addOverlay(file, target, output):
    overlay_data_start_offset = getSize(target) #if target file already conatains overlay, we will get its offset
    with open(target, "rb") as t:
        with open(output,"wb") as o:
            o.write(t.read(overlay_data_start_offset)) #write new file without overlay
            o.write(struct.pack("<I",os.path.getsize(file))) #overlay will start with size of overlay data
            o.write(open(file, "rb").read())

def main():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--file",  required=True, help="File which will be added as overlay to target")
    parser.add_argument("--output",  required=True, help="Output filename")
    parser.add_argument("--target",  required=True)
    args, leftovers = parser.parse_known_args()

    addOverlay(args.file, args.target, args.output)


if __name__ == "__main__":
    main()
