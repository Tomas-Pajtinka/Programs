import argparse, os, vt, hashlib, datetime, time
from calendar import monthrange


min_first_submit = round(datetime.datetime.strptime(datetime.date.today().strftime("%d/%m/%Y"), "%d/%m/%Y").timestamp()) #get today UNIX timestamp
min_last_analysis = 0
extensions = [".exe", ".dll", ".sys"] #, ".pdf", ".xls", ".doc", ".xlsm", ".docm"]
ignore_extensions = False
client = None

def logging(log_msg):
    with open("vt_log.txt", "a") as log:
        log.write(log_msg + "\n")

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

def submitFile(file, hash):
    with open(file, "rb") as f:
        analysis = client.scan_file(f, wait_for_completion=True)

    time.sleep(15)
    return client.get_object("/files/" + hash)

def getFileInfo(file):
    try:
        hash = sha256sum(file)
    except Exception as e:
        print("Error >> " + file )
        print(e)
        return
    try:
        vtInfo = client.get_object("/files/" + hash)
    except Exception as e:
        if e.code == "NotFoundError":
            print("Not found >> "+ file)
            vtInfo = submitFile(file, hash)
        else:
            print("Error >> " + file )
            print(e)
            client.close()
            exit()
    analysis = vtInfo.to_dict()

    try:
        if analysis['attributes']['last_analysis_stats']['malicious'] > 0 or analysis['attributes']['last_analysis_stats']['suspicious'] > 0 or analysis['attributes']['last_analysis_stats']['timeout'] > 25 or analysis['attributes']['last_analysis_stats']['confirmed-timeout'] > 25:
            printSus(file, analysis)
            return
            
        if analysis['attributes']['first_submission_date'] > min_first_submit:
            printTime(file, analysis)
            return

        if analysis['attributes']['last_analysis_date'] < min_last_analysis:
            vtInfo = submitFile(file, hash)
            analysis = vtInfo.to_dict()
            if analysis['attributes']['last_analysis_stats']['malicious'] > 0 or analysis['attributes']['last_analysis_stats']['suspicious'] > 0 or analysis['attributes']['last_analysis_stats']['timeout'] > 25 or analysis['attributes']['last_analysis_stats']['confirmed-timeout'] > 25:
                printSus(file, analysis)
            return
    except Exception as e:
        print("Error >> " + file )
        print(e)
    return

    
def getFilesInfo(input):
    if os.path.isdir(input):
        files = getFiles(input)
    else:
        files = [input]
    
    for file in files:
        logging(file)
        if globals()['ignore_extensions'] == False:  #if ignore_extensions switch was not used
            for extension in globals()['extensions']:
                if file.endswith(extension):
                    getFileInfo(file)
                    time.sleep(16) #to do not exceded limit quota for free api key
        else:
            getFileInfo(file)
            time.sleep(16) #to do not exceded limit quota for free api key
          
    client.close()

def listInputFile(input):
    with open(input, "r") as file:
        while True:
            line = file.readline()
            if line == "":
                break
            getFilesInfo(line.rstrip())


def setMinTime(days):
    today = datetime.date.today()
    later = datetime.date(today.year, today.month, monthrange(today.year, today.month)[1]) - datetime.timedelta(int(days)) #substract specified numbers of day from current date
    return round(datetime.datetime.strptime(later.strftime("%d/%m/%Y"), "%d/%m/%Y").timestamp())
    

def main():
    parser = argparse.ArgumentParser(description="Tool to scan multiple files in VirusTotal.")
    parser.add_argument("--min_last_analysis", action="store", help="If last analysis of file is older then specified file will be analyze")
    parser.add_argument("--min_first_submit", action="store", help="If first submit of file is older then specified and is clean, than it will not be print out.")
    parser.add_argument("--ignore_extensions", action="store_true", help="Scan files with every extension.")
    parser.add_argument("--input", action="store", help="Path to file or directory.")
    parser.add_argument("--input_file", action="store",  help="Path to file containing list of files to scan.")
    parser.add_argument("--api_key", action="store", required=True,  help="VirusTotal API key.")
    args, leftovers = parser.parse_known_args()

    globals()['client'] = vt.Client(args.api_key)

    if args.min_first_submit is not None:
        globals()['min_first_submit'] = setMinTime(args.min_first_submit)
    print("Minimal fisrt submission threshold is set to " + datetime.datetime.utcfromtimestamp(globals()['min_first_submit']).strftime("%d/%m/%Y"))

    if args.min_last_analysis is not None:
        globals()['min_last_analysis'] = setMinTime(args.min_last_analysis)
    print("Minimal last analysis threshold is set to " + datetime.datetime.utcfromtimestamp(globals()['min_last_analysis']).strftime("%d/%m/%Y"))

    if args.ignore_extensions == True:
        globals()['ignore_extensions'] = True

    if args.input is not None:
        getFilesInfo(args.input)
    
    if args.input_file is not None:
        listInputFile(args.input_file)


if __name__ == "__main__":
    main()
