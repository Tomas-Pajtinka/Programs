import argparse, os

def walkDir(input):
    with open("dirs2.txt", "a") as output:
        #recursively walk through directory
        for root, dir, files in os.walk(input):
            for file in files:
                output.write(root + "\\" + file)
                print(root + "\\" + file)


def main():
    parser = argparse.ArgumentParser(description="Tool to scan multiple files in VirusTotal.")
    parser.add_argument("--input", action="store", required=True,  help="Path to file or directory.")
    args, leftovers = parser.parse_known_args()

    walkDir(args.input)


if __name__ == "__main__":
    main()
