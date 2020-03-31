from neo4j import GraphDatabase
import pyshark
from py2neo import Graph
from datetime import datetime, timedelta
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time


"""
1. Read each packet from pcap file
2. Convert each packet to python dict
3. Create nodes and relationships in Neo4j for each dict
4. Connect nodes from each packet
"""
#graph = Graph(password="mis4900")

uri = "bolt://localhost:7687"
driver = GraphDatabase.driver(uri, auth=("neo4j", "mis4900"), encrypted=False)

domains = ['google.com', 'facebook.com', 'youtube.com']


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


def print_pcap(filename):
    cap = pyshark.FileCapture(filename)
    print(len(cap))
    print(type(cap))
    i = 0
    #print(cap[0])
    print(cap[0].dns.field_names)
    #print(cap[5].dns.id)

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

"""
    for packet in cap:
        print(packet)
        print(i)
        i += 1
"""

def pcap_to_dict(filename):
    cap = pyshark.FileCapture(filename)
    for packet in cap:
        packet_dict = {'trans_id': packet.dns.id, 'src': packet.ip.src, 'dst': packet.ip.dst, 'host': packet.dns.qry_name,
                       'qry_type': packet.dns.qry_type, 'qry_class': packet.dns.qry_class}
        update_db(create_nodes, packet_dict)


def delete_db(tx):
    result = tx.run("MATCH (n) DETACH DELETE n")


def add2neo(pcap):
    graph = Graph("bolt://localhost:7687", password="mis4900")

    tx = graph.begin()
    #tx.append(
     #   "MATCH (u1:User) WHERE u1.id = {A} MERGE (i1:IP {id:{B}, title:{C}, created_at:{D}}) CREATE UNIQUE (u1)-[:CREATED_PLAYLIST]->(p1)",
      #  {"A": "test", "B": pcap['src'], "C": pcap['dest'], "D": pcap['host']})
    graph.run("CREATE(d: DNS)-[: RESOLVED_TO]->(i:IP) "
                "CREATE (h:HOST) "
                "SET h.domain_url = host "
                "CREATE (d)-[:HAS_QUERY]->(h) "
                "CREATE (h)-[:RESOLVED_TO]->(i)",
              {"host": pcap['host']})
    tx.process()
    tx.commit()


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


print_pcap('dns-local.pcap')
#pcap_to_dict('dns-local.pcap')
#update_db(delete_db, "test")

#pcap_to_dict('dns.cap')
#update_db("test")
