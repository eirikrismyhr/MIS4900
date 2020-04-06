from neo4j import GraphDatabase
import pyshark
from datetime import datetime, timedelta
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import csv


"""
1. Read each packet from pcap file
2. Convert each packet to python dict
3. Create nodes and relationships in Neo4j for each dict
4. Connect nodes from each packet
"""
#graph = Graph(password="mis4900")


uri = "bolt://localhost:7687"
driver = GraphDatabase.driver(uri, auth=("neo4j", "mis4900"), encrypted=False)


def create_nodes(tx, cap):
    result = tx.run("CREATE (d:DNS {trans_id: $trans_id})-[:RESOLVED_TO]->(i:IP) "
                    "CREATE (h:HOST {host: $host}) "
                    "CREATE (i_src:IP {ip: $src}) "
                    "CREATE (i_dst:IP {ip: $dst}) "
                    "CREATE (d)-[:HAS_QUERY]->(h) "
                    "CREATE (h)-[:RESOLVED_TO]->(i) "
                    "CREATE (i_src)-[:HAS_DNS_REQUEST]->(d) "
                    "CREATE (i_dst)-[:HAS_DNS_RESPONSE]->(d)",
                     {"host": cap['host'], "src": cap['src'], "dst": cap['dst'], "trans_id": cap['trans_id']})


def update_db(transaction, package):
    with driver.session() as session:
        session.write_transaction(transaction, package)


def check_whitelist(packet):
    in_list = False
    whitelist = csv.reader(open("majestic_1000.csv", "r"), delimiter=",")
    for line in whitelist:
        if line[2] == packet.dns.qry_name:
            in_list = True
    return in_list


def check_blacklist(packet):
    in_list = False
    blacklist = open("hosts.txt", "r")
    domains = []
    for line in blacklist:
        #print(line)
        line = line.split("  ")
        domains.append(line)
    for line in domains:
        if line[1] == packet.dns.qry_name:
            in_list = True
    return in_list


def print_pcap(filename):
    cap = pyshark.FileCapture(filename, display_filter='dns')
    i = 0
    for packet in cap:
        #print(packet)
        if check_whitelist(packet):
            print(packet.dns.qry_name + "Found in whitelist")
            print(i)
        if check_blacklist(packet):
            print(packet.dns.qry_name + "Found in blacklist")
            print(i)
        i += 1

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


def pcap_to_dict(filename):
    cap = pyshark.FileCapture(filename)
    for packet in cap:
        packet_dict = {'trans_id': packet.dns.id, 'src': packet.ip.src, 'dst': packet.ip.dst, 'host': packet.dns.qry_name,
                       'qry_type': packet.dns.qry_type, 'qry_class': packet.dns.qry_class}
        update_db(create_nodes, packet_dict)


def delete_db(tx):
    result = tx.run("MATCH (n) DETACH DELETE n")


class MyHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_modified = datetime.now()

    def on_modified(self, event):
        if datetime.now() - self.last_modified < timedelta(seconds=1):
            return
        else:
            self.last_modified = datetime.now()
        print(f'Event type: {event.event_type}  path : {event.src_path}')
        print(event.is_directory) # This attribute is also available


print_pcap('maccdc2012_00000.pcap')
#check_blacklist()
#pcap_to_dict('dns-local.pcap')
#update_db(delete_db, "test")

#pcap_to_dict('dns.cap')
#update_db("test")
