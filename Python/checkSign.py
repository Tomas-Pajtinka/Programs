import sys, os, subprocess, argparse

extensions = [".exe", ".dll", ".sys"]
signTool = "C:/Program Files (x86)/Windows Kits/10/bin/10.0.17763.0/x64/signtool.exe"

def checkFile(file):
    for extension in extensions:
        if file.endswith(extension):
            output = subprocess.run([signTool, "verify", "/pa", file], capture_output=True)
            if b"Successfully verified" not in output.stdout:
                print(file)
            break

def checkFilesSignature(input):
    if os.path.isdir(input):
        for root, dir, files in os.walk(input):
            for file in files:
                checkFile(root + "\\" + file)
    else:
        checkFile(input)

def main():
    parser = argparse.ArgumentParser(description="Tool to verify certificates of multiple files.\nTool print out files, which certificate could not be verified.")
    parser.add_argument("--path_to_signtool", action="store", help="Path to signtool.exe.")
    parser.add_argument("--input", action="store", required=True,  help="Path to file or directory.")
    args, leftovers = parser.parse_known_args()
    if args.path_to_signtool is not None:
        globals()['signTool'] = args.path_to_signtool
    input = args.input
    checkFilesSignature(input)

if __name__ == "__main__":
    main()
