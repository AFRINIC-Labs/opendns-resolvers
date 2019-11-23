#
# Desc: Script for Testing Open DNS Resolvers in Afrinic IP Space
#
# Import Modules
import time
import pandas as pd
import datetime as DT
import math
import os
import urllib
import dns.resolver
import dns.name
from dns import reversename, resolver
import subprocess
from multiprocessing import Process, Pool
import hashlib
import psycopg2
import requests, json
from ipwhois import IPWhois
try:
    from urllib.request import urlopen, urlretrieve
except ImportError:
    from urllib import urlopen, urlretrieve
print("Imported Modules successfully!")


# Define DB connection details and object
db_connection = psycopg2.connect(user="postgres", host="127.0.0.1", port="5432", database="****")
db_connection.autocommit = True
db_cursor = db_connection.cursor()

# Define Function to insert data into DB
def db_insert_func(tablename:str, colums:list, data:list):
    try:
        datal = data.__str__().replace('[', '').replace(']', '')
        col = colums.__str__().replace('[', '').replace(']', '').replace("'", "")
        sql_statement = """INSERT INTO {} ({}) VALUES ({});""".format(tablename, col, datal)
        db_cursor.execute(sql_statement)
        res = True
    except Exception as err:
        res = False
        print(err)
    return res

# Define Function to select data from DB
def db_select_func(tablename:str):
    try:
        #sql_statement1 = """SELECT * FROM {} WHERE id>1587;""".format(tablename)
        sql_statement1 = """SELECT * FROM {} ;""".format(tablename)
        db_cursor.execute(sql_statement1)
        res = db_cursor.fetchall()
    except Exception as err:
        pass
        print(err)
    return res

# Function that allows you to download the file of AFRINIC's IP blocks
def download_delegated_latest(delegated_latest_url, download_file):
    req = urllib.request.Request(delegated_latest_url)
    # Get file from Afrinic repo
    with urllib.request.urlopen(req) as res:
        with open(download_file, "w") as f:
            for line in res:
                print(line.decode("utf-8").strip(), file=f)

def update_rir_database(rir_database_url):
    global dataDir
    try:
        os.mkdir(dataDir)
    except FileExistsError:
        pass
    rir_database_path = os.path.join(dataDir, rir_database_url.split('/')[-1])
    try:
        if os.path.isfile(rir_database_path):
            hash_md5 = hashlib.md5()
            calculate_hash(hash_md5, rir_database_path)
            md5_text = urlopen(rir_database_url + '.md5').read().decode('utf-8')
            print('md5 on afrinic website',md5_text[-32:])
            calculated_md5 = hash_md5.hexdigest()
            print('md5 calculated', calculated_md5)
            if not (calculated_md5 == md5_text[-32:]):
                print('no ok')
                print(rir_database_path)
                os.remove(rir_database_path)
                print("Downloading up-to-date RIR database {}".format(rir_database_path))
                download_delegated_latest(rir_database_url,rir_database_path)
                #urlretrieve(rir_database_url, filename=rir_database_path)
                #download_delegated_latest(rir_database_url,rir_database_path)
                print("RIR database downloaded: {}".format(rir_database_url))
            else:
                print("RIR database is up-to-date: {}".format(rir_database_path))
                print('ok')
                #print("Updating RIR database: {}".format(rir_database_url))

                #print("RIR database updated: {}".format(rir_database_url))
        else:
            print("Downloading RIR database {}".format(rir_database_path))
            download_delegated_latest(rir_database_url,rir_database_path)
            #urlretrieve(rir_database_url, filename=rir_database_path)
            print("RIR database downloaded: {}".format(rir_database_url))
    except IOError:
        pass
    return rir_database_path


def calculate_hash(hash_md5, path):
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_md5.update(chunk)


# Function that will retrieve the global file of AFRINIC's IP blocks and provide the list of IPV4 blocks
def gen_ipv4_file(download_file):
    global dataDir
    saveDateIpv4 = os.path.join(dataDir, 'ipv4.txt')
    headers = ['Registry', 'Country Code', 'Type', 'Start', 'Value', 'Date', 'Status', 'Extensions']
    rir_database = pd.read_csv(download_file, delimiter='|', comment='#', names=headers, dtype=str,
                                keep_default_na=False, na_values=[''], encoding='utf-8')[4:]
    ipv4_database = rir_database[(rir_database['Type'] == 'ipv4')]
    ipv4_database.to_csv(saveDateIpv4, header=None, index=None, sep='|', mode='a')
    #print('ipv4 File Created successful')

    return ipv4_database

# Function that will retrieve the global file of AFRINIC's IP blocks and provide the list of IPV6 blocks
def gen_ipv6_file(download_file):
    global dataDir
    saveDateIpv6 = os.path.join(dataDir, 'ipv6.txt')
    headers = ['Registry', 'Country Code', 'Type', 'Start', 'Value', 'Date', 'Status', 'Extensions']
    rir_database = pd.read_csv(download_file, delimiter='|', comment='#', names=headers, dtype=str,
                                keep_default_na=False, na_values=[''], encoding='utf-8')[4:]
    ipv6_database = rir_database[(rir_database['Type'] == 'ipv6')]
    ipv6_database.to_csv(saveDateIpv6, header=None, index=None, sep='|', mode='a')
    #print('ipv6 File Created successful')

    return ipv6_database

#insert data into ipv4 table
def insert_data_ipv4(ipv4Data):
    tbl = 'ipv4'
    co = ['cc','start','cidr','blocStatus']
    for index, row in ipv4Data.iterrows():
        #print ("{} | {} | {} | ASN | {} ".format(row["Country Code"],row["Start"], int(gencidr(row["Value"])), row["Status"]))
        a1 = [row["Country Code"],row["Start"], int(gencidr(row["Value"])), row["Status"]]
        db_insert_func(tbl, co, a1)

#insert data into ipv6 table
def insert_data_ipv6(ipv6Data):
    tbl = 'ipv6'
    co = ['cc','start','cidr','blocStatus']
    for index, row in ipv6Data.iterrows():
        #print ("{} | {} | {} | ASN | {} ".format(row["Country Code"],row["Start"], int(gencidr(row["Value"])), row["Status"]))
        a2 = [row["Country Code"],row["Start"], row["Value"], row["Status"]]
        db_insert_func(tbl, co, a2)

#insert data into opendns table
def insert_data_opendns(resultData):
    tbl = 'opendns'
    col = ['bloc','cidr','zmap','openresolver','datetest']
    db_insert_func(tbl, col, resultData)

#insert data into opendnsv6 table
def insert_data_opendnsv6(resultData):
    tbl = 'opendnsv6'
    col = ['bloc','cidr','zmap','reverseDNS','addrv6','openresolver','datetest']
    db_insert_func(tbl, col, resultData)

# Function that generate cidr value
def gencidr(n):
    return (32 - math.log2(int(n)))

#Function that get asn of ip address using ripe atlas
def get_asn_ripe(ip_addr: str):
    try:
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

#Function that get asn of ip address using whois
def get_asn_whois(ip_addr: str):
    a = IPWhois(ip_addr).lookup_whois()
    return a['asn']

# Function to check if IPV4 DNS Resolver is open
def checkopenresolver(host, testhostname="test.openresolver.com", testreg="TXT"):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [host]
    openResolver = False
    try:
        for rdata in resolver.query(testhostname, testreg):
            openResolver = True
    except:
        pass
    return openResolver


# Function to check if IPV6 DNS Resolver is open
def checkopenresolveripv6 (host, testhostname="test.openresolver.com", testreg="AAAA"):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [host]
    openResolver = False
    try:
        for rdata in resolver.query(testhostname, testreg):
            openResolver = True
    except:
        pass
    return openResolver

def reverseDns(ip):
  try: 
    rev_name = reversename.from_address(ip)
    reversed_dns = str(resolver.query(rev_name,"PTR")[0])
    return reversed_dns
  except: 
    return 'N/A'

def getipv6(reverseName):
    try:
        answers_IPv6 = dns.resolver.query(reverseName, 'AAAA')
        for rdata in answers_IPv6:
            return rdata.address
    except:
        pass

def verifyipv6(zmapIP):
    ipv6 = []
    for line in zmapIP:
            i6 = getipv6(reverseDns(line))
            if i6 is not None:
                ipv6.append(i6)
            else :
                pass
    return ipv6

def zmaptest(blockIP):
    global zmapDir
    try:
        os.mkdir(zmapDir)
    except FileExistsError:
        pass
    block_ip = blockIP.split("/")
    filename = "zmapoutput-{}-{}.txt".format(block_ip[0], block_ip[1])
    zmapoutput_path = os.path.join(zmapDir, filename)    
    port = 53
    cmd = "sudo zmap -p{0} -o {1} {2}".format(port, zmapoutput_path, blockIP)
    subprocess.call(cmd.split(), shell=False)
    zmap = []
    with open(zmapoutput_path, "r") as f:
        for line in f.readlines():
            zmap.append(line.strip())
    
    return zmap

def processv4(re, block, cidr, date):
    for i in re:
        resultData = [block, cidr, i, checkopenresolver(i), date]
        print(resultData)
        insert_data_opendns(resultData)

def processv6(re, block, cidr, date):
    for i in re:
        reverseDNS = reverseDns(i)
        if reverseDNS != 'N/A':
            addrv6 = getipv6(reverseDNS)
            if addrv6 is not None:
                x = checkopenresolveripv6(addrv6)
            else:
                addrv6 = '-'
                x = '-'
        else :
            reverseDNS = '-'
            addrv6 = '-'
            x = '-'
        resultData1 = [block, cidr, i, reverseDNS, addrv6, x, date]
        insert_data_opendnsv6(resultData1)
        print(resultData1)

def runInParallel(*fns):
  proc = []
  for fn in fns:
    p = Process(target=fn)
    p.start()
    proc.append(p)
  for p in proc:
    p.join()

def zmpt(bloc, cidr):
    global dateTestLoaded
    ipnet = "{}/{}".format(bloc, cidr)
    re = zmaptest(ipnet)
    #runInParallel(processv4(re,bloc,cidr,dateTestLoaded), processv6(re,bloc,cidr,dateTestLoaded))
    print('Table for open dns on ipv4 bloc')
    processv4(re,bloc,cidr,dateTestLoaded)
    print('Table for ipv4 bloc with ipv6 connectivity')
    processv6(re,bloc,cidr,dateTestLoaded)
    print('Test is completed')

def loadzmp(tableName):
    records = db_select_func(tableName)
    for i in records:
        zmpt(i[2],i[3])

if __name__ == "__main__":
    #initialisation
    projDir = os.getcwd(),
    dataDir = os.path.abspath('data')
    zmapDir = os.path.join(dataDir, 'zmap_database')
    resultDir = os.path.join(dataDir, 'result')
    rir_database_url = 'http://ftp.afrinic.net/stats/afrinic/delegated-afrinic-extended-latest'
    summary = os.path.join(dataDir, 'summary.txt')
    dateTestLoaded = DT.datetime.now().strftime("%d-%m-%Y")
    #dateTestLoaded = '2019-11-01'


    start_time = DT.datetime.now()
    download_file = update_rir_database(rir_database_url)
    ipv4D = gen_ipv4_file(download_file)
    ipv6D = gen_ipv6_file(download_file)
    insert_data_ipv4(ipv4D)
    insert_data_ipv6(ipv6D)
    tableName = 'ipv4'
    loadzmp(tableName)
    end_time = DT.datetime.now()

    f = open(summary, "a")
    #print("--- %s seconds ---" % (time.time() - start_time))
    f.write("Summary of programm excution\n")
    f.write("Start Time : {} \nEnd Time : {}\n".format(start_time.strftime("%Y-%m-%d %H:%M:%S"), end_time.strftime("%Y-%m-%d %H:%M:%S")))
    f.write("Total time of execution is  : --- %s seconds ---" % (end_time - start_time))
    f.close()
    print("DONE")
