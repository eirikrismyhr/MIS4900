from neo4j import GraphDatabase
import pyshark
from datetime import datetime, timedelta
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import csv
import whois
import pydig

"""
1. Read each packet from pcap file
2. Convert each packet to python dict
3. Create nodes and relationships in Neo4j for each dict
4. Connect nodes from each packet
"""
# graph = Graph(password="mis4900")


uri = "bolt://localhost:7687"
driver = GraphDatabase.driver(uri, auth=("neo4j", "mis4900"), encrypted=False)


def create_nodes(tx, cap):
    print(cap['registrar'])
    tx.run("CREATE (d:Domain {name: $host, in_blacklist: $in_blacklists}) "
           "CREATE (i_src:IP {ip: $src}) "
           "CREATE (i_dst:IP {ip: $dst}) "
           "CREATE (i_src)-[:HAS_QUERY]->(d) "
           "CREATE (d)-[:RESOLVED_TO]->(i_dst) "
           "CREATE (i_dst)-[:IN_NETWORK]->(a:AS)",
           {"host": cap['host'], "src": cap['src'], "dst": cap['dst'], "in_blacklists": cap['in_blacklists']})
    if cap['registrar'] is not None:
        tx.run("MATCH (d:Domain {name: $host}) "
               "MERGE (r:Registrar {name: $registrar}) "
               "MERGE (d)-[:REGISTERED_BY]->(r)",
               {"registrar": cap['registrar'], "host": cap['host']})


def update_db(transaction, package):
    with driver.session() as session:
        session.write_transaction(transaction, package)


def pcap_to_dict(filename):
    cap = pyshark.FileCapture(filename)
    for packet in cap:
        if packet.dns.flags_response == '1':
            #print(packet.dns.qry_name)
            #print(check_blacklist(packet))
            packet_dict = {'trans_id': packet.dns.id, 'src': packet.ip.src, 'dst': pydig.query(packet.dns.qry_name, 'A'),
                           'host': packet.dns.qry_name,
                           'qry_type': packet.dns.qry_type, 'qry_class': packet.dns.qry_class,
                           'registrar': check_whois(packet.dns.qry_name), 'in_blacklists': check_blacklist(packet)}
            update_db(create_nodes, packet_dict)


def delete_db(tx):
    tx.run("MATCH (n) DETACH DELETE n")


def check_whitelist(packet):
    in_list = False
    whitelist = csv.reader(open("majestic_1000.csv", "r"), delimiter=",")
    domain = packet.dns.qry_name
    for line in whitelist:
        if line[2] == domain or ('www.' + line[2]) == domain:
            in_list = True
            break
    return in_list


def check_blacklist(packet):
    in_list = False
    malwaredomains = open("hosts.txt", "r")
    urlhaus = open("urlhaus.txt", "r")
    blacklists = [malwaredomains, urlhaus]
    domain_name = packet.dns.qry_name
    for bl in blacklists:
        domains = []
        for line in bl:
            #print(line)
            line = line.split("  ")
            #print(line[1][:-1])
            if line[0] == '127.0.0.1':
                domains.append(line)
        for line in domains:
            #print("line[0] is: " + line[0])
            if line[1] == domain_name or ('www.' + line[1]) == domain_name:
                in_list = True
                break
    return in_list


def check_whois(domain):
    try:
        whois_query = whois.query(domain)
        if whois_query is not None:
            if whois_query.registrar is not '':
                return whois_query.registrar
    except whois.exceptions.UnknownTld:
        print("Unknown TLD")
    except whois.exceptions.WhoisCommandFailed:
        print("Command timed out")
    except whois.exceptions.FailedParsingWhoisOutput or KeyError:
        print("Error in output")


def print_pcap(filename):
    cap = pyshark.FileCapture(filename, display_filter='dns')
    i = 0
    for packet in cap:
        try:
            if packet.dns.flags_response == '1':
                print(packet)
            if check_whitelist(packet):
                print(packet.dns.qry_name + " Found in whitelist")
                print(i)
            if check_blacklist(packet):
                print(packet.dns.qry_name + " Found in blacklist")
                print(i)
            i += 1
        except AttributeError:
            print("Missing attribute")

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


class MyHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_modified = datetime.now()

    def on_modified(self, event):
        if datetime.now() - self.last_modified < timedelta(seconds=1):
            return
        else:
            self.last_modified = datetime.now()
        print(f'Event type: {event.event_type}  path : {event.src_path}')
        print(event.is_directory)  # This attribute is also available


#print_pcap('maccdc2012_00000.pcap')
# print(check_whois("google.com"))
# check_blacklist()
pcap_to_dict('dns.cap')
# update_db(delete_db, "test")
