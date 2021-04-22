#!/usr/bin/env python
# coding: utf-8

# In[1]:


import config
import urllib.request
from urllib.request import urlopen
import os,sys
import pandas as pd
import hashlib
import math
import subprocess
import dns.resolver
import dns.reversename
from threading import Thread
import multiprocessing
import datetime as dt
from ipwhois import IPWhois
import requests,json


# In[2]:


resolver = dns.resolver.Resolver()
#resolver.lifetime = 1
odrDB = config.DB()
odrDB.init()
headers = {
    'Accept': 'application/json',
}
#odrDB.close()


# In[3]:


# Function that allows you to download the file of AFRINIC's IP blocks
def download_delegated_latest(delegated_latest_url, download_file):
    with open(download_file, 'wb') as f:
        response = requests.get(delegated_latest_url, stream=True)
        total = response.headers.get('content-length')
        if total is None:
            f.write(response.content)
        else:
            downloaded = 0
            total = int(total)
            for data in response.iter_content(chunk_size=max(int(total / 1000), 1024 * 1024)):
                downloaded += len(data)
                f.write(data)
                done = int(50 * downloaded / total)
                sys.stdout.write('\r[{}{}]'.format('█' * done, '.' * (50 - done)))
                sys.stdout.flush()
    sys.stdout.write('\n')


# In[4]:


def download_rir_database(rir_database_url,rir_database_path):
    global dataDir,dataDelegated
    try:
        os.mkdir(dataDir)
        os.mkdir(dataDelegated)
    except FileExistsError:
        pass
    try:
        download_delegated_latest(rir_database_url,rir_database_path)
    except IOError:
        pass


# In[5]:


#Function that get asn of ip address using ripe atlas
def getAsnFromRipe(bloc: str,cidr:int):
    try:
        ip_addr = "{}/{}".format(bloc,cidr)
        ripe_url = 'https://stat.ripe.net/data/network-info/data.json?sourceapp=afrinic-internship-research&resource='
        get_request = requests.get(ripe_url + ip_addr).content
        get_req = json.loads(get_request)
        if get_req['data']['asns']:
            result = get_req['data']['asns'][0]
        else:
            result = "Unknown"
    except KeyError:
        result = "Unknown"
    return result


# In[6]:


# Function to get Organisation Name form IP Block Address
def getIPblockOrgName(bloc: str,cidr:int):
    ripe_url = 'https://rdap.afrinic.net/rdap/ip/{}/{}'.format(bloc,cidr)
    get_request = requests.get(ripe_url).content
    get_req = json.loads(get_request)
    orgname = get_req
    return orgname['name']


# In[7]:


# Function to get Organisation Description form orgname
def getDescOrgName(orgname: str):
    ripe_url = 'https://rdap.afrinic.net/rdap/entity/'
    get_request = requests.get(ripe_url + orgname).content
    get_req = json.loads(get_request)
    descorgname = get_req['vcardArray'][1][2][3]
    return descorgname


# In[8]:


# Function that will retrieve the global file of AFRINIC's IP blocks and provide the list of IPV4 blocks
def gen_ipv4_file(download_file,dateTest):
    global dataIPV4
    try:
        os.mkdir(dataIPV4)
    except FileExistsError:
        pass
    try:
        saveDateIpv4 = os.path.join(dataIPV4, 'ipv4.txt') + "-" + dateTest
        headers = ['Registry', 'Country Code', 'Type', 'Start', 'Value', 'Date', 'Status', 'Extensions']
        rir_database = pd.read_csv(download_file, delimiter='|', comment='#', names=headers, dtype=str, keep_default_na=False, na_values=[''], encoding='utf-8')[4:]
        ipv4_databaseA = rir_database[(rir_database['Type'] == 'ipv4')]
        
        ipv4_database = ipv4_databaseA.head()
        
        #ipv4_database.to_csv(saveDateIpv4, header=None, index=None, sep='|', mode='a')
        #print('ipv4 File Created successful')

        tbl = 'ipv4T' #ipv4 table with organisation name and asn number
        col = ['ipStart','cidr','cc','blocStatus','numAsn','orgName','descOrg','dateSave']
        for index, row in ipv4_database.iterrows():
            data_cc = row["Country Code"]
            data_ipStart = row["Start"]
            data_cidr = int(gencidr(row["Value"]))
            data_blocStatus = row["Status"]
            data_orgName = getIPblockOrgName(data_ipStart,data_cidr)
            data_numAsn = getAsnFromRipe(data_ipStart,data_cidr)
            data_descOrg = getDescOrgName(data_orgName)
            data_dateSave = dateTest
        
            data = [data_ipStart,data_cidr,data_cc,data_blocStatus,data_numAsn,data_orgName,data_descOrg,data_dateSave]
        
            odrDB.insert(tbl, col, data)
        
        print('ipv4 data inserted successful in database')
    except IOError:
        pass


# In[9]:


# Function that generate cidr value
def gencidr(n):
    return (32 - math.log2(int(n)))


# In[10]:


# Function to check if IPV4 DNS Resolver is open
def checkopenresolver(host, testhostname="test.openresolver.com", testreg="TXT"):
    resolver.nameservers = [host]
    openResolver = False
    try:
        for rdata in resolver.query(testhostname, testreg):
            openResolver = True
    except:
        pass
    return openResolver


# In[11]:


def zmapTest(bloc, cidr):
    global  zmapDir
    try:
        os.mkdir(zmapDir)
    except FileExistsError:
        pass
    ipnet = "{}/{}".format(bloc, cidr)
    filename = "zmapoutput-{}-{}.txt".format(bloc, cidr)
    zmapoutput_path = os.path.join(zmapDir, filename)
    os.mknod(zmapoutput_path)
    port = 53
    #cmd = "zmap -B 10M  -p{0} -o {1} {2}".format(port, zmapoutput_path, IPNetwork(ipnet))
    cmd = "zmap -B 10M -p{} -o {} {}".format(port, zmapoutput_path, ipnet)
    subprocess.call(cmd.split(), shell=False)
    zmap = []
    with open(zmapoutput_path, "r") as f:
        for line in f.readlines():
            zmap.append(line.strip())

    return zmap


# In[24]:


def odrTestIPV4(zmap : list, bloc, cidr, datetest):
    n = 0
    openresolver = []
    tbl = 'opendnsv4'
    col = ['bloc', 'cidr', 'zmap', 'openresolver', 'datetest']

    if zmap:
        for i in zmap:
            odrx = checkopenresolver(i)
            if odrx is True:
                openresolver.append(i)
                n += 1
            else:
                pass
            resultData = [bloc, cidr, i, odrx, datetest]
            odrDB.insert(tbl, col, resultData)
    else:
        pass

    return [n,openresolver]


# In[25]:


#odrTestIPV4(zmap, '41.78.208.0', 22, '2020-08-23')


# In[26]:


def getTestDate():
    return dt.datetime.now()


# In[27]:


def getTestDuration(a,b):
    return b-a


# In[28]:


def zmpt(bloc, cidr):
    #testDate = dt.datetime.now().strftime("%d-%m-%Y")
    re = zmapTest(bloc, cidr)
    return re


# In[29]:


def loadodrTest(tablename,datetest):
    records = odrDB.select(tablename)
    ipv4block_count = 0
    for i in records:
        y = zmapTest(i[1], int(i[2]))
        r = odrTestIPV4(y, i[1], int(i[2]), datetest)
        ipv4block_count += 1
    return [ipv4block_count,r[0]]


# In[ ]:


if __name__ == '__main__':
    print("---------------------------- START EXECUTION ----------------------------")
    #starting time
    dateTestLoaded = getTestDate()
    dateTest = str(dateTestLoaded).split(' ')[0]

    #initialisation
    projDir = os.getcwd()
    dataDirName = 'data'
    try:
        os.mkdir(dataDirName)
    except FileExistsError:
        pass
    dataDirNameTestDay = dateTestLoaded.strftime("%Y%m%d-%H%M%S")
    dirName = dataDirName+'/'+dataDirNameTestDay
    dataDir = os.path.join(projDir, dirName)
    dataDelegated = os.path.join(dataDir, 'delegated-latest')
    dataIPV4 = os.path.join(dataDir, 'ipv4')
    dataSummary = os.path.join(dataDir, 'summary')
    zmapDir = os.path.join(dataDir, 'zmap_database')
    resultDir = os.path.join(dataDir, 'result')
    rir_database_url = 'http://ftp.afrinic.net/stats/afrinic/delegated-afrinic-extended-latest'
    rir_database_path = os.path.join(dataDelegated, rir_database_url.split('/')[-1]) + "-" + dateTest
    summary = os.path.join(dataSummary, 'summary.txt')+ "-" + dateTest

    #Download Delagated files
    print("- START:: Download Delagated files -")
    download_file = download_rir_database(rir_database_url,rir_database_path)
    print("- END:: Download files -")
    print("\n")
    
    #Generating ip* data
    print("- START:: Generate IPV4 in file -")
    ipv4D = gen_ipv4_file(rir_database_path,dateTest)
    print("- End:: Generate IPV4  Block in file -")
    print("\n")
    
    loadingTest = loadodrTest('ipv4T',dateTest)
    #ending time
    dateTestEnded = getTestDate()
    
    #test time 
    duration = getTestDuration(dateTestLoaded, dateTestEnded)
    
    
    
    colu = ['startDate','endDate','testDuration','numBlocIPV4','numODRIPV4']
    summaryR = [dateTestLoaded.strftime("%Y-%m-%d %H:%M:%S"),dateTestEnded.strftime("%Y-%m-%d %H:%M:%S"),str(duration),loadingTest[0],loadingTest[1]]
    odrDB.insert('summaryTest',colu,summaryR)
    
    #write summary in summary.txt
    try:
        os.mkdir(dataSummary)
    except FileExistsError:
        pass
    with open(summary, 'a') as f:
        f.write("Summary of programm excution\n")
        f.write("Start Time : {} \nEnd Time : {}\n".format(dateTestLoaded.strftime("%Y-%m-%d %H:%M:%S"), dateTestEnded.strftime("%Y-%m-%d %H:%M:%S")))
        f.write("Total time of execution is  : --- %s seconds ---".format(duration))
        f.close()

    print(duration)
    
    print("---------------------------- TEST DONE ------------------------------\n")
    print("---------------------------- END EXECUTION ----------------------------")


# In[ ]:





# In[ ]: