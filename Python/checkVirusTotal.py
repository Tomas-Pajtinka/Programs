import argparse, os, vt, hashlib, datetime 
from calendar import monthrange


min_first_submit = round(datetime.datetime.strptime(datetime.date.today().strftime("%d/%m/%Y"), "%d/%m/%Y").timestamp()) #get today UNIX timestamp
extensions = [".exe", ".dll", ".sys", ".pdf", ".xls", ".doc", ".xlsm", ".docm"]
ignore_extensions = False
client = None


def getFiles(input):
    out = []
    #recursively walk through directory
    for root, dir, files in os.walk(input):
        for file in files:
            out.append(root + "\\" + file)
    return out

#function from stackoverflow
def sha256sum(filename):
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        for n in iter(lambda : f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()

def printSus(file, analysis):
    print("Detected >> " + file)
    print("\tMalicious > " + str(analysis['attributes']['last_analysis_stats']['malicious']))
    print("\tSuspicious > " + str(analysis['attributes']['last_analysis_stats']['suspicious']))
    print("\tTimeout > " + str(analysis['attributes']['last_analysis_stats']['timeout']))
    print("\tConfirmed timeout > " + str(analysis['attributes']['last_analysis_stats']['confirmed-timeout']))
    print("\tHarmless > " + str(analysis['attributes']['last_analysis_stats']['harmless']))
    print("\tUndetected > " + str(analysis['attributes']['last_analysis_stats']['undetected']))
    print("\tFailure > " + str(analysis['attributes']['last_analysis_stats']['failure']))
    print("\tType unsupported > " + str(analysis['attributes']['last_analysis_stats']['type-unsupported']))


def printTime(file, analysis):
    print("New file >> " + file + "\t" +  datetime.datetime.utcfromtimestamp(analysis['attributes']['first_submission_date']).strftime("%d/%m/%Y"))


def getFileInfo(file):
    hash = sha256sum(file)
    try:
        vtInfo = client.get_object("/files/" + hash)
    except Exception as e:
        if e.code == "NotFoundError":
            print("Not found >> "+ file)
        else:
            print("Error >> " + file )
            print(e)
        return
    analysis = vtInfo.to_dict()

    if analysis['attributes']['last_analysis_stats']['malicious'] > 0 or analysis['attributes']['last_analysis_stats']['suspicious'] > 0 or analysis['attributes']['last_analysis_stats']['timeout'] > 0 or analysis['attributes']['last_analysis_stats']['confirmed-timeout'] > 0:
        printSus(file, analysis)
        return
    if analysis['attributes']['first_submission_date'] > min_first_submit:
        printTime(file, analysis)
    return

    
def getFilesInfo(input):
    if os.path.isdir(input):
        files = getFiles(input)
    else:
        files = [input]
    
    for file in files:
        if globals()['ignore_extensions'] == False:  #if ignore_extensions switch was not used
            for extension in globals()['extensions']:
                if file.endswith(extension):
                    getFileInfo(file)
        else:
            getFileInfo(file)
    
    client.close()


def setMinFirstSubmit(days):
    today = datetime.date.today()
    later = datetime.date(today.year, today.month, monthrange(today.year, today.month)[1]) - datetime.timedelta(int(days)) #substract specified numbers of day from current date
    globals()['min_first_submit'] = round(datetime.datetime.strptime(later.strftime("%d/%m/%Y"), "%d/%m/%Y").timestamp())
    

def main():
    parser = argparse.ArgumentParser(description="Tool to scan multiple files in VirusTotal.")
    parser.add_argument("--min_first_submit", action="store", help="If first submit of file is older then specified and is clean, than it will not be print out.")
    parser.add_argument("--ignore_extensions", action="store_true", help="Scan files with every extension.")
    parser.add_argument("--input", action="store", required=True,  help="Path to file or directory.")
    parser.add_argument("--api_key", action="store", required=True,  help="VirusTotal API key.")
    args, leftovers = parser.parse_known_args()

    if args.min_first_submit is not None:
        setMinFirstSubmit(args.min_first_submit)
    print("Submission threshold is set to " + datetime.datetime.utcfromtimestamp(globals()['min_first_submit']).strftime("%d/%m/%Y"))

    if args.ignore_extensions == True:
        globals()['ignore_extensions'] = True

    input = args.input
    globals()['client'] = vt.Client(args.api_key)
    
    getFilesInfo(input)

if __name__ == "__main__":
    main()