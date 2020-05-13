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


uri = "bolt://localhost:7687"
driver = GraphDatabase.driver(uri, auth=("neo4j", "mis4900"), encrypted=False)


def create_nodes(tx, cap):
    print(cap['registrar'])
    tx.run("MERGE (d:Domain {name: $host, in_blacklist: $in_blacklists}) ",
           {"host": cap['host'], "src": cap['src'], "dst": cap['dst'], "in_blacklists": cap['in_blacklists']})
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
               "MERGE (i_src)-[:HAS_QUERY]->(d)",
               {"src": cap['src'], "host": cap['host']})
    if cap['txt'] is not None:
        tx.run("MATCH (d:Domain {name: $host}) "
               "MERGE (t:TXT {content: $txt})"
               "MERGE (d)-[:HAS_DESCRIPTION]->(t)",
               {"host": cap['host'], "txt": cap['txt']})
    if cap['dst'] is None:
        tx.run("MATCH (d:Domain {name: $host}) "
               "MERGE (n:NXDOMAIN) "
               "MERGE (d)-[:NOT_EXIST]->(n)",
               {"host": cap['host']})
    if cap['dst'] is not None:
        tx.run("MATCH (d:Domain {name: $host}) "
               "MERGE (i:IP {ip: $dst}) "
               "MERGE (d)-[:RESOLVES_TO]->(i) "
               "MERGE (i)-[:IN_NETWORK]->(a:AS) "
               "MERGE (adm:ISP)-[:ADMINISTERS]->(a)",
               {"host": cap['host'], "dst": cap['dst']})
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
               "MERGE (d)-[:REGISTERED_BY]->(r)",
               {"registrar": cap['registrar'], "host": cap['host']})
    if cap['mx'] is not None:
        tx.run("MATCH (d:Domain {name: $host}) "
               "MERGE (m:Mail_Server {name: $mx}) "
               "MERGE (d)-[:HAS_MAIL_SERVER]->(m)",
               {"host": cap['host'], "mx": cap['mx']})


def update_db(transaction, package):
    with driver.session() as session:
        session.write_transaction(transaction, package)


def pcap_to_dict(filename):
    cap = pyshark.FileCapture(filename)
    for packet in cap:
        if 'DNS' in packet:
            src = None
            if packet.dns.flags_response == '0':
                src = packet.ip.src
            packet_dict = {'trans_id': packet.dns.id, 'src': src, 'dst': None,
                           'host': packet.dns.qry_name,
                           'qry_type': packet.dns.qry_type, 'qry_class': packet.dns.qry_class,
                           'registrar': check_whois(packet.dns.qry_name), 'in_blacklists': check_blacklist(packet),
                           'whitelisted': check_whitelist(packet), 'ns': None, 'mx': None, 'cname': None, 'txt': None,
                           'time': None, 'ptr': None}
            try:
                packet_dict.update({'dst': packet.dns.a})
                packet_dict.update({'ns': packet.dns.ns})
                packet_dict.update({'mx': packet.dns.mx_mail_exchange})
                packet_dict.update({'cname': packet.dns.cname})
                packet_dict.update({'txt': packet.dns.txt})
                packet_dict.update({'ptr': packet.dns.ptr})
                packet_dict.update({'time': packet.dns.time})
            except AttributeError:
                print("Resource type not found in packet")
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


def check_ip(ip):
    in_list = False
    blacklist = open("firehol_level1.netset", "r")
    for line in blacklist:
        if line[0] is not '#':
            if line is ip or ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(line.strip('\n')):
                in_list = True
    return in_list


def print_pcap(filename):
    cap = pyshark.FileCapture(filename, display_filter='dns')
    i = 0
    for packet in cap:
        try:
            print(packet)
            print(packet.dns.field_names)
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
        print(event.is_directory)


#print_pcap('botnet-capture-20110810-neris.pcap')
# print(check_whois("google.com"))
# check_blacklist()
pcap_to_dict('botnet-capture-20110810-neris.pcap')
# update_db(delete_db, "test")
# print(check_ip('5.44.208.0'))
