"""
Created by Nicholas Venis 25/06/19
Inspired by Sooty (https://github.com/TheresAFewConors/Sooty), changed for Python 2.7

"""

import re
import csv
import subprocess
import os
import urllib2
from Tkinter import *
import Tkinter, Tkconstants, tkFileDialog
import hashlib
import json
import socket
from ipwhois import IPWhois
try:
    import email
    from email.parser import HeaderParser
except ImportError:
    print("Please install the ipwhois package via pip before running.")
    print("To install 'pip install ipwhois'")
    exit(0)
VT_API_KEY = ''
deleted = False

try:
    if os.path.exists("vtkeys.txt"):
        r = open("vtkeys.txt", "r")
        VT_API_KEY = r.read()
        r.close()
except Exception as e:
    print(e)


def switchMenu(option):
    if option == "1":
        nslookup()
    if option == "2":
        domainExtract()
    if option == "3":
        sanitise()
    if option == "4":
        vtReport()
    if option == "5":
        hashMenu()
    if option == "6":
        hibp()
    if option == "7":
        dnsMenu()
    if option == "8":
        emailMenu()
    if option == "9":
        settingsMenu()
    if option == "0":
        exit(1)
    else:
        print("Please enter a valid option or 0 to exit\n")
        mainMenu()


def mainMenu():
    print("\n  ___ ______  ___  _________  ___  ___  ")
    print(" / _ \|  _  \/ _ \ | ___ \  \/  | / _ \ ")
    print('/ /_\ \ | | / /_\ \| |_/ / .  . |/ /_\ \\')
    print("|  _  | | | |  _  ||    /| |\/| ||  _  |")
    print("| | | | |/ /| | | || |\ \| |  | || | | |")
    print("\_| |_/___/ \_| |_/\_| \_\_|  |_/\_| |_/")
    print("\n\nWhat would you like to do?")
    print("\nOPTION 1: Nslookup")
    print("OPTION 2: Extract domains")
    print("OPTION 3: Sanitise URLs")
    print("OPTION 4: Reputation check")
    print("OPTION 5: Hash suite")
    print("OPTION 6: Have i been pwned?")
    print("OPTION 7: Ip/DNS tools")
    print("OPTION 8: Email tools")
    print("OPTION 9: Settings\n")
    print("OPTION 0: Exit\n")
    switchMenu(raw_input())


def nslookup():
    print("\n--------------------------------- ")
    print(" \t\tN S L O O K U P ")
    print("--------------------------------- ")
    try:
        inp = str(raw_input("Enter an IP or hostname\n"))

        out = subSystem(inp)
        host = out.split()

        if str(host[5]) == "answer:":
            print("\nDevice not in estate")
        elif str(host[5]) == "name":
            print('\nAsset:')
            print("ip: " + str(host[1]))
            print("hostname:  " + str(host[7]) + "\n")
            print('\nFull output:\n')
            print(str(out))
        else:
            print('\nAsset:')
            print("ip: " + str(host[7]))
            print("hostname:  " + str(host[5]) + "\n")
            print('\nFull output:\n')
            print(str(out))

        mainMenu()
    except Exception as e:
        print(e)
        mainMenu()


def subSystem(ip):
    proc = subprocess.Popen('nslookup ' + ip, shell=True, stdout=subprocess.PIPE)
    tmp = proc.stdout.read()
    return tmp


def domainExtract():
    root = Tk()
    root.filename = tkFileDialog.askopenfilename(initialdir="/", title="Select file")
    fileName = root.filename
    urls = []
    header = False

    try:
        with open(fileName) as csvfile:
            readCSV = csv.reader(csvfile, delimiter=',')
            for row in readCSV:
                url = row[0]
                urls.append(url)

        for index, item in enumerate(urls):
            m = re.search('h[a-z]{2}ps?://([A-Za-z_0-9.-]+).*', urls[index])
            if m is None:
                print("Header:" + urls[index])
                header = True
                continue
            urls[index] = m.group(1)

        fileName = fileName.replace(".csv", "")
        fileName += "-DOMAINS.csv"

        if header is False:
            urls.insert(0, "url")

        with open(fileName, "wb") as newcsv:
            wr = csv.writer(newcsv, delimiter=",")
            for url in urls:
                wr.writerow([url])
            print("Created csv: " + fileName + " successfully!")
    except Exception as e:
        print(e)
    root.destroy()
    mainMenu()


def sanitise():
    print("Enter URL to sanitize: ")
    url = raw_input()
    x = re.sub("\.", "[.]", url)
    x = re.sub("http://", "hxxp://", x)
    x = re.sub("https://", "hxxps://", x)
    print("\n" + x)
    mainMenu()


def vtReport():
    global VT_API_KEY
    ip = str(raw_input("\nEnter ip or URL to check\n"))


    print("VirusTotal report for: " + ip)
    apiKey = "apikey=" + VT_API_KEY
    res = "&ip=" + ip
    site = "https://www.virustotal.com/vtapi/v2/ip-address/report?" + apiKey + res

    hdr = {
        "User-Agent": "'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36",
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}

    pos = 0
    tot = 0

    try:
        req = urllib2.Request(site, headers=hdr)
        response = urllib2.urlopen(req)
        page = json.load(response)
        if response.getcode() == 200:
            try:
                try:
                    for i in page['detected_urls']:
                        tot = tot + 1
                        pos = pos + i['positives']

                    if tot != 0:
                        print("   No of Reportings: " + str(tot))
                        print("   Average Score:    " + str(pos / tot))
                        print("   VirusTotal Report Link: " + "https://www.virustotal.com/gui/ip-address/" + str(ip))
                    else:
                        print("   No of Reportings: " + str(tot))

                except:
                    site = "https://www.virustotal.com/vtapi/v2/url/report?" + apiKey + "&resource=" + ip
                    req = urllib2.Request(site, headers=hdr)
                    response = urllib2.urlopen(req)
                    page = json.load(response)

                    print("\n VirusTotal Report:")
                    print("   URL Malicious Reportings: " + str(page['positives']) + "/" + str(page['total']))
                    print("   VirusTotal Report Link: " + str(page['permalink']))
            except:
                print("IP or URL not found in VT database")
        else:
            print(" There's been an error - check your API key, or VirusTotal is possibly down")
            mainMenu()
    except:
        print("Unable to connect to VirusTotal, check connection and api key is present")
    site = "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"

    hdr = {
        "User-Agent": "'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36",
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}

    req = urllib2.Request(site, headers=hdr)
    try:
        page = urllib2.urlopen(req)
        print("\n TOR Exit Node Report: ")
        if page.status_code == 200:
            tl = page.text.split('\n')
            c = 0
            for i in tl:
                if ip == i:
                    print("  " + i + " is a TOR Exit Node")
                    c = c + 1
            if c == 0:
                print("  " + ip + " is NOT a TOR Exit Node")
        else:
            print("   TOR LIST UNREACHABLE")
    except:
        print('\nTor list unreachable!')

    print("\nChecking BadIP's... ")
    try:
        site = 'https://www.badips.com/get/info/' + ip

        hdr = {
            "User-Agent": "'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36",
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}

        req = urllib2.Request(site, headers=hdr)
        page = urllib2.urlopen(req)
        if page.status_code == 200:
            result = json.load(page)

            sc = result['Score']['ssh']
            print("  " + str(result['suc']))
            print("  Score: " + str(sc))
        else:
            print('  Error reaching BadIPs')
    except:
        print('  IP not found')

    mainMenu()


def hashMenu():
    print("\n--------------------------------- ")
    print(" \t  H A S H  S U I T E ")
    print("--------------------------------- ")
    print("\nWhat would you like to do?")
    print("\nOPTION 1: Generate file hash")
    print("OPTION 2: Check file hash in VT")
    print("OPTION 3: Return to menu")
    hashSwitch(raw_input())


def hashSwitch(option):
    if option == "1":
        hashGen()
    if option == "2":
        vtHashCheck()
    if option == "3":
        mainMenu()


def hashGen():
    root = Tk()
    root.filename = tkFileDialog.askopenfilename(initialdir="/", title="Select file")
    hasher = hashlib.md5()
    with open(root.filename, 'rb') as r:
        buf = r.read()
        hasher.update(buf)
    print(" MD5 Hash: " + hasher.hexdigest())
    root.destroy()
    hashMenu()


def dnsMenu():
    print("\n --------------------------------- ")
    print("         D N S    T O O L S        ")
    print(" --------------------------------- ")
    print(" What would you like to do? ")
    print(" OPTION 1: Reverse DNS Lookup")
    print(" OPTION 2: DNS Lookup")
    print(" OPTION 3: WHOIS Lookup")
    print(" OPTION 4: Exit to Main Menu")
    dnsSwitch(raw_input())


def dnsSwitch(option):
    if option == "1":
        revDNS()
    if option == "2":
        dnsLookup()
    if option == "3":
        whoIs()
    if option == "4":
        mainMenu()


def revDNS():
    d = raw_input("Enter IP to check:\n")
    try:
        s = socket.gethostbyaddr(d)
        print('\n ' + s[0])
    except:
        print(" Hostname not found")
    dnsMenu()


def dnsLookup():
    d = raw_input("Enter Domain Name to check:\n")
    d = re.sub("http://", "", d)
    d = re.sub("https://", "", d)
    try:
        s = socket.gethostbyname(d)
        print('\n ' + s)
    except:
        print("Website not found")
    dnsMenu()


def whoIs():
    ip = raw_input(' Enter IP: ')
    try:
        w = IPWhois(ip)
        w = w.lookup_whois()
        addr = str(w['nets'][0]['address'])
        addr = addr.replace('\n', ', ')
        print("\n WHO IS REPORT:")
        print("  CIDR:      " + str(w['nets'][0]['cidr']))
        print("  Name:      " + str(w['nets'][0]['name']))
        # print("  Handle:    " + str(w['nets'][0]['handle']))
        print("  Range:     " + str(w['nets'][0]['range']))
        print("  Descr:     " + str(w['nets'][0]['description']))
        print("  Country:   " + str(w['nets'][0]['country']))
        print("  State:     " + str(w['nets'][0]['state']))
        print("  City:      " + str(w['nets'][0]['city']))
        print("  Address:   " + addr)
        print("  Post Code: " + str(w['nets'][0]['postal_code']))
        # print("  Emails:    " + str(w['nets'][0]['emails']))
        print("  Created:   " + str(w['nets'][0]['created']))
        print("  Updated:   " + str(w['nets'][0]['updated']))
    except:
        print(" IP Not Found")

    dnsMenu()


def vtHashCheck():
    global VT_API_KEY
    hash = raw_input("\nEnter hash of file for lookup:\n")
    apiKey = "apikey=" + VT_API_KEY
    res = "&resource=" + hash
    site = "https://www.virustotal.com/vtapi/v2/file/report?" + apiKey + res

    hdr = {
        "User-Agent": "'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36",
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}

    req = urllib2.Request(site, headers=hdr)

    count = 0
    try:
        page = json.load(urllib2.urlopen(req))
        try:
            if page['positives'] != 0:
                print("\n Malware Detection")
                for key, value in page['scans'].items():
                    if value['detected'] == True:
                        count = count + 1
            print(" VirusTotal Report: " + str(count) + " detections found")
            print("   Report Link: " + "https://www.virustotal.com/gui/file/" + hash + "/detection")
        except:
            print("No positives found for hash")
    except Exception as e:
        print(e)
    hashMenu()


def hibp():
    acc = raw_input("\nPlease enter an email address to check\n")
    url = "https://haveibeenpwned.com/api/v2/breachedaccount/" + acc

    hdr = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36"}

    try:
        req = urllib2.Request(url, headers=hdr)
        response = urllib2.urlopen(req)
        page = json.load(response)
        if response.getcode() == 200:
            le = len(page)

            for i in range(le):
                dc = str(page[i]['DataClasses'])
                dc = re.sub('\[(?:[^\]|]*\|)?([^\]|]*)\]', r'\1', dc)
                dc = dc.replace("'", '')

                print("\n")
                print("Name:     " + str(page[i]['Title']))
                print("Domain:   " + str(page[i]['Domain']))
                print("Breached: " + str(page[i]['BreachDate']))
                print("Details:  " + str(dc))
                print("Verified: " + str(page[i]['IsVerified']))
        else:
            print("Email not found in database")
        mainMenu()
    except Exception as e:
        print(e)
        mainMenu()


def emailMenu():
    print("\n --------------------------------- ")
    print("       E M A I L    T O O L S        ")
    print(" --------------------------------- ")
    print(" What would you like to do? ")
    print(" OPTION 1: Get headers")
    print(" OPTION 4: Exit to Main Menu")
    emailSwitch(raw_input())


def emailSwitch(option):
    if option == "1":
        getHeaders()
    if option == "2":
        mainMenu()


def getHeaders():
    root = Tk()
    root.filename = tkFileDialog.askopenfilename(initialdir="/", title="Select file")
    buf = open(root.filename, "rb")
    msg = email.message_from_file(buf)

    try:
        parser = HeaderParser()
        h = parser.parsestr(str(msg))

        for i in h.items():
            for p in i:
                print (p + "\n")
    except Exception as e:
        print(e)

    root.destroy()
    emailMenu()


def settingsMenu():
    global VT_API_KEY
    global deleted
    vtTemp = ""
    found = False
    if VT_API_KEY != "":
        vtTemp = VT_API_KEY[-4:]
        found = True
    print("\n--------------------------------- ")
    print(" \t\tS E T T I N G S ")
    print("--------------------------------- ")
    if found == True and deleted == False:
        print("VT API key found, ends in: " + vtTemp)
    else:
        print("No VT API key found")
    print("\nWhat would you like to do?")
    print("\nOPTION 1: Add api key")
    print("OPTION 2: Remove api key")
    print("OPTION 3: Check connectivity")
    print("OPTION 4: Return to menu")
    settingsSwitch(raw_input())


def settingsSwitch(option):
    if option == "1":
        addKey()
    if option == "2":
        delKey()
    if option == "3":
        checkConnect()
    if option == "4":
        mainMenu()


def checkConnect():
    global VT_API_KEY
    try:
        global VT_API_KEY
        if VT_API_KEY != "":
            apiKey = "apikey=" + VT_API_KEY
            site = "https://www.virustotal.com/vtapi/v2/file/report?" + apiKey
            hdr = {
                "User-Agent": "'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36",
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}

            req = urllib2.Request(site, headers=hdr)

            try:
                page = urllib2.urlopen(req)
                if page.getcode() == 200:
                    print("\nAPI Working correctly")
                    settingsMenu()
                else:
                    print(page.getcode())
                    settingsMenu()
            except Exception as e:
                print(e)
        else:
            print("No VT api key found, please add one.")
            settingsMenu()
    except Exception as e:
        print(e)


def addKey():
    global VT_API_KEY, deleted
    print("\nPlease enter a valid VirusTotal API key\n")
    VT_API_KEY = raw_input()
    try:
        if os.path.exists("vtkeys.txt"):
            w = open("vtkeys.txt", "w")
            w.truncate(0)
            w.write(VT_API_KEY)
            w.close()
            vtTemp = VT_API_KEY[-4:]
            print("Successfully written key ending in: " + vtTemp)
            deleted = False
            settingsMenu()
        else:
            w = open("vtkeys.txt", "w")
            w.write(VT_API_KEY)
            w.close()
            vtTemp = VT_API_KEY[-4:]
            print("Successfully written key ending in: " + vtTemp)
            deleted = False
            settingsMenu()
    except Exception as e:
        print(e)


def delKey():
    global deleted
    if os.path.exists("vtkeys.txt"):
        os.remove("vtkeys.txt")
        print("API key removed successfully")
        deleted = True
        settingsMenu()
    else:
        settingsMenu()


if __name__ == '__main__':
    mainMenu()
