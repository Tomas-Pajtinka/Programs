import argparse, os, base64

listOfFiles = {}
fileString = "import base64; files={"

def addToList(file):
    f = open(file, 'rb')
    listOfFiles[file] = base64.b64encode(f.read())


def dumpToFile():
    for file in listOfFiles:
        if len(globals()['fileString']) > 22:
            globals()['fileString'] += ","
        globals()['fileString'] += "\'{file}\':{" + listOfFiles[file].decode("utf-8") + "}"

    globals()['fileString'] += "};"
    print(globals()['fileString'])

def createFile(args):
    direcotry = args.input_directory
    start = args.start_filename

    for root, dirs, files in os.walk(direcotry):
        for file in files:
            addToList(root+ '\\' + file)

    dumpToFile()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_directory")
    parser.add_argument("--start_filename")
    args = parser.parse_args()
    createFile(args)

if __name__ == "__main__":
    main()
