from neo4j import GraphDatabase
import pyshark
from datetime import datetime, timedelta
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import csv
import whois
import pydig
import ipaddress
import socket

"""
1. Read each packet from pcap file
2. Convert each packet to python dict
3. Create nodes and relationships in Neo4j for each dict
4. Connect nodes from each packet
"""
# graph = Graph(password="mis4900")

# Loads the official Neo4j Python driver
uri = "bolt://localhost:7687"
# driver = GraphDatabase.driver(uri, auth=("neo4j", "mis4900"), encrypted=False)
driver = GraphDatabase.driver(uri, auth=("neo4j", "test"), encrypted=False)


# Creates nodes and relationships in Neo4j
def create_nodes(tx, cap):
    # print(cap['registrar'])
    tx.run("MERGE (d:Domain {name: $host, blacklisted: $in_blacklists, whitelisted: $whitelisted}) ",
           {"host": cap['host'], "src": cap['src'], "in_blacklists": cap['in_blacklists'],
            "whitelisted": cap['whitelisted']})
    if cap['cname'] is not None:
        tx.run("MATCH (d:Domain {name: $host}) "
               "MERGE (a:Domain {name: $cname}) "
               "MERGE (d)-[:HAS_ALIAS]->(a)",
               {"host": cap['host'], "cname": cap['cname']})
    if cap['ns'] is not None:
        tx.run("MATCH (d:Domain {name: $host}) "
               "MERGE (n:Domain {name: $ns}) "
               "MERGE (n)-[:IS_AUTHORITATIVE_FOR]->(d)",
               {"host": cap['host'], "ns": cap['ns']})
    if cap['src'] is not None:
        tx.run("MATCH (d:Domain {name: $host}) "
               "MERGE (i_src:IP_HOST {ip: $src}) "
               "MERGE (i_src)-[p:HAS_QUERY]->(d)",
               {"src": cap['src'], "host": cap['host']})
    if cap['txt'] is not None:
        tx.run("MATCH (d:Domain {name: $host}) "
               "MERGE (t:TXT {content: $txt})"
               "MERGE (d)-[:HAS_DESCRIPTION]->(t)",
               {"host": cap['host'], "txt": cap['txt']})
        """
    if cap['dst'] is None:
        tx.run("MATCH (d:Domain {name: $host}) "
               "MERGE (n:NXDOMAIN) "
               "MERGE (d)-[:NOT_EXIST]->(n)",
               {"host": cap['host']})
        """
    if cap['dst'] is not None:
        tx.run("MATCH (d:Domain {name: $host}) "
               "MERGE (i:IP {ip: $dst, blacklisted: $blacklisted}) "
               "MERGE (d)-[:RESOLVES_TO]->(i) "
               "MERGE (i)-[:IN_NETWORK]->(a:AS) "
               "MERGE (adm:ISP)-[:ADMINISTERS]->(a)",
               {"host": cap['host'], "dst": cap['dst'], "blacklisted": check_ip(cap['dst'])})
        if cap['dst'] is not None:
            tx.run("MATCH (d:Domain {name: $host}) "
                   "MATCH (i:IP {ip: $dst}) "
                   "MATCH (d)-[p:RESOLVES_TO]->(i) "
                   "SET p.time = $time",
                   {"host": cap['host'], "dst": cap['dst'], "time": cap['time']})
    if cap['ptr'] is not None:
        tx.run("MATCH (i:IP {ip: $ip}) "
               "MERGE (d:Domain {name: $ptr}) "
               "MERGE (i)-[:POINTS_TO]->(d)",
               {"ip": cap['dst'], "ptr": cap['ptr']})
    if cap['registrar'] is not None:
        tx.run("MATCH (d:Domain {name: $host}) "
               "MERGE (r:Registrar {name: $registrar}) "
               "MERGE (d)-[p:REGISTERED_BY]->(r) "
               "SET p.creation_date = $creation_date "
               "SET p.last_updated = $last_updated",
               {"registrar": cap['registrar'], "host": cap['host'], "creation_date": cap['creation_date'],
                "last_updated": cap['last_updated']})
    if cap['mx'] is not None:
        tx.run("MATCH (d:Domain {name: $host}) "
               "MERGE (m:Mail_Server {name: $mx}) "
               "MERGE (d)-[:HAS_MAIL_SERVER]->(m)",
               {"host": cap['host'], "mx": cap['mx']})
    if cap['timestamp'] is not None:
        tx.run("MATCH (d:Domain {name: $host}) "
               "MATCH (i:IP_HOST {ip: $src}) "
               "MATCH (i)-[p:HAS_QUERY]->(d) "
               "SET p.last_seen = $time",
               {"host": cap['host'], "src": cap['src'], "time": cap['timestamp']})
        tx.run("MATCH (d:Domain {name: $host}) "
               "MATCH (i:IP_HOST {ip: $src}) "
               "MATCH (i)-[p:HAS_QUERY]->(d) WHERE NOT EXISTS(p.first_seen) "
               "SET p.first_seen = $time",
               {"host": cap['host'], "src": cap['src'], "time": cap['timestamp']})


# Performs cypher transaction
def update_db(transaction, package):
    with driver.session() as session:
        session.write_transaction(transaction, package)


# Creates dictionary with values from log file and passes it to create_nodes
def pcap_to_dict(filename):
    cap = pyshark.FileCapture(filename)
    filetype = filename.split(".")[1]
    if filetype == 'pcap':
        for packet in cap:
            if 'DNS' in packet:
                src = None
                if packet.dns.flags_response == '0':
                    src = packet.ip.src
                whois_result = check_whois(packet.dns.qry_name)
                packet_dict = {'trans_id': packet.dns.id, 'src': src, 'dst': None,
                               'host': packet.dns.qry_name,
                               'qry_type': packet.dns.qry_type, 'qry_class': packet.dns.qry_class,
                               'registrar': None, 'creation_date': None,
                               'last_updated': None, 'in_blacklists': check_blacklist(packet.dns.qry_name),
                               'whitelisted': check_whitelist(packet.dns.qry_name), 'ns': None, 'mx': None,
                               'cname': None, 'txt': None, 'time': None, 'ptr': None, 'timestamp': None}
                try:
                    packet_dict.update({'dst': packet.dns.a})
                    packet_dict.update({'ns': packet.dns.ns})
                    packet_dict.update({'mx': packet.dns.mx_mail_exchange})
                    packet_dict.update({'cname': packet.dns.cname})
                    packet_dict.update({'txt': packet.dns.txt})
                    packet_dict.update({'ptr': packet.dns.ptr_domain_name})
                    packet_dict.update({'time': packet.dns.time})
                except AttributeError:
                    print("Resource type not found in packet")
                if whois_result:
                    packet_dict.update({'registrar': whois_result['registrar']})
                    packet_dict.update({'creation_date': whois_result['creation_date']})
                    packet_dict.update({'last_updated': whois_result['last_updated']})
                update_db(create_nodes, packet_dict)
    elif filetype == 'txt':
        logfile = open(filename, "r")
        for line in logfile:
            fields = line.split(" ")
            domain_name = remove_chars(fields[4])
            whois_result = None
            try:
                packet_dict = {'timestamp': fields[0] + ' ' + fields[1], 'src': fields[3], 'host': domain_name,
                               'in_blacklists': check_blacklist(domain_name), 'registrar': None, 'creation_date': None,
                               'last_updated': None, 'whitelisted': check_whitelist(domain_name), 'ns': None,
                               'mx': None,
                               'cname': None, 'txt': None, 'time': None, 'ptr': None, 'dst': None}
                if whois_result:
                    packet_dict.update({'registrar': whois_result['registrar']})
                    packet_dict.update({'creation_date': whois_result['creation_date']})
                    packet_dict.update({'last_updated': whois_result['last_updated']})
                update_db(create_nodes, packet_dict)
            except AttributeError:
                print("Resource type not found in packet")
    else:
        print("Filetype not supported")


# Deletes database, if necessary
def delete_db(tx):
    tx.run("MATCH (n) DETACH DELETE n")


# Checks if domain names in log files are known legitimate domains
def check_whitelist(domain_name):
    in_list = False
    whitelist = csv.reader(open("Whitelists/majestic_1000.csv", "r"), delimiter=",")
    for line in whitelist:
        if line[2] == domain_name or ('www.' + line[2]) == domain_name:
            in_list = True
            break
    return in_list


# Checks if domain names are found in any malicious domain blacklists
def check_blacklist(domain_name):
    in_list = False
    malwaredomainlist = open("Blacklists/malwaredomainlist_hosts.txt", "r")
    urlhaus = open("Blacklists/urlhaus.txt", "r")
    phishtank = csv.reader(open("Blacklists/verified_online(phishtank).csv", "r"), delimiter=",")
    cybercrime_tracker = open("Blacklists/CYBERCRiME-06-03-20.txt", "r")
    blacklists = [malwaredomainlist, urlhaus]
    for bl in blacklists:
        domains = []
        for line in bl:
            # print(line)
            line = line.split("  ")
            # print(line[1][:-1])
            if line[0] == '127.0.0.1':
                domains.append(line)
        for line in domains:
            # print("line[0] is: " + line[0])
            if line[1] == domain_name or ('www.' + line[1]) == domain_name:
                in_list = True
                break
    for line in phishtank:
        variations = [str(domain_name) + "/", "www." + str(domain_name), domain_name[4:]]
        if line[1][7:] in variations or line[1][8:] in variations:
            in_list = True
            break
    for line in cybercrime_tracker:
        variations = [str(domain_name) + "/", "www." + str(domain_name), domain_name[4:]]
        if line in variations:
            in_list = True
            break
    for f in blacklists:
        f.close()
    cybercrime_tracker.close()
    return in_list


# Finds registrar info for a specific domain name
def check_whois(domain):
    try:
        whois_query = whois.query(domain)
        if whois_query is not None:
            if whois_query.registrar is not '':
                return {"registrar": whois_query.registrar,
                        "creation_date": whois_query.creation_date,
                        "last_updated": whois_query.last_updated}
    except whois.exceptions.UnknownTld:
        print("Unknown TLD")
    except whois.exceptions.WhoisCommandFailed:
        print("Command timed out")
    except whois.exceptions.FailedParsingWhoisOutput:
        print("Error in output")
    except KeyError:
        print("Key error")


# Checks if a resolved IP address is found in any IP blacklists
def check_ip(ip):
    in_list = False
    firehol = open("Blacklists/firehol_level1.netset", "r")
    malwaredomainlist_ip = open("Blacklists/malwaredomainlist_ip.txt", "r")
    cinsscore = open("Blacklists/ci-badguys.txt", "r")
    blacklists = [firehol, malwaredomainlist_ip, cinsscore]
    for blacklist in blacklists:
        for line in blacklist:
            if line[0] is not '#':
                if line is ip or ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(line.strip('\n')):
                    in_list = True
                    break
    for file in blacklists:
        file.close()
    return in_list


# Strips unwanted characters from domain names
def remove_chars(string):
    chars = [')', '(', ':']
    delete_dict = {sp_character: '' for sp_character in chars}
    delete_dict[' '] = ''
    table = str.maketrans(delete_dict)
    string = string.translate(table)
    return str(string)


# Prints content of log files, packet by packet
def print_pcap(filename):
    filetype = filename.split(".")[1]

    if filetype == 'pcap':
        cap = pyshark.FileCapture(filename, display_filter='dns')
        i = 0
        for packet in cap:
            try:
                print(packet)
                print(packet.dns.field_names)
                print(packet.dns.time)
                print(packet.dns.resp_type)
                print(packet.dns.resp_name)
                print(packet.dns.ns)
                print(packet.dns.mx_mail_exchange)
                print(packet.dns.a)
                print(packet.dns.aaaa)

                """
                if packet.dns.qry_type == '12' and packet.dns.flags_response == '1':
                    print(packet)
                    print(packet.dns.field_names)
                    print(packet.dns.qry_name)
                    print(packet.dns.qry_type)
                    print(packet.dns.ptr_domain_name)
                    print(packet.dns.response_to)
                    print(packet.dns.time)
                """
                if check_whitelist(packet):
                    print(packet.dns.qry_name + " Found in whitelist")
                    print(i)
                if check_blacklist(packet):
                    print(packet.dns.qry_name + " Found in blacklist")
                    print(i)
                i += 1
            except AttributeError:
                print("Missing attribute")
    elif filetype == 'txt':
        f = open(filename, "r")
        for line in f:
            print(line)
            fields = line.split(" ")
            for entry in fields:
                print(entry)
    else:
        print("Unsupported filetype")

    event_handler = MyHandler()
    observer = Observer()
    observer.schedule(event_handler, path='.', recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


# Checks if any files have been modified
class MyHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_modified = datetime.now()

    def on_modified(self, event):
        if datetime.now() - self.last_modified < timedelta(seconds=1):
            return
        else:
            self.last_modified = datetime.now()
        print(f'Event type: {event.event_type}  path : {event.src_path}')
        print(event.is_directory)


def load_csv():
    with driver.session() as session:
        session.run("USING PERIODIC COMMIT "
                    "LOAD CSV WITH HEADERS FROM $file AS row "
                    "MERGE (src:IP_Host {ip: row.src}) "
                    "MERGE (d:Domain {name: row.domain_name}) "
                    "MERGE (src)-[query:HAS_QUERY]->(d) "
                    "SET query.last_seen = row.time",
                    {"file": "file:///eidsiva.csv"})
        """"
        tx.run("LOAD CSV WITH HEADERS FROM $file AS row "
               "MERGE (d:Domain {name: row.domain_name})",
               {"file": "file:///eidsiva.csv"})
        tx.run("LOAD CSV WITH HEADERS FROM $file AS row "
               "MATCH (src:IP_Host {ip: row.src}) "
               "MATCH (d:Domain {name: row.domain_name} "
               "MERGE (src)-[query:HAS_QUERY]->(d)",
                {"file": "file:///eidsiva.csv"})
    """
    """
        tx.run("LOAD CSV WITH HEADERS FROM $file AS row "
               "WITH row LIMIT 100 "
               "MATCH (src:IP_Host {ip: row.src}) "
               "MATCH (d:Domain {name: row.domain_name}) "
               "MATCH (src)-[p:HAS_QUERY]->(d) WHERE NOT EXISTS(p.first_seen) "
               "SET p.first_seen = row.time",
               {"file": "file:///eidsiva.csv"})
         
        print(result)
          """


"""
def query_db(self):
    with driver.session() as session:
        session.run(load_csv)
"""

# print_pcap('botnet-capture-20110810-neris.pcap')
# print(check_whois("google.com"))
# check_blacklist()
start_time = time.time()
# pcap_to_dict('anon_dns_records.txt')

# update_db(delete_db, "test")
# print(check_ip('5.44.208.0'))
"""
with open('datasets/eidsiva_test.csv', newline='') as csvfile:
    reader = csv.reader(csvfile, delimiter=',')
    for row in reader:
        for field in row:
            if '"' in field:
                print(row)
"""

load_csv()
"""
for line in query_db(csv_load):
    print(line)
"""
print("--- %s seconds ---" % round(time.time() - start_time, 2))
