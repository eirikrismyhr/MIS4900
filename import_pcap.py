from neo4j import GraphDatabase
import pyshark
from py2neo import Graph

"""
1. Read each packet from pcap file
2. Convert each packet to python dict
3. Create nodes and relationships in Neo4j for each dict
4. Connect nodes from each packet
"""
#graph = Graph(password="mis4900")

uri = "bolt://localhost:7687"
driver = GraphDatabase.driver(uri, auth=("neo4j", "mis4900"))

domains = ['google.com', 'facebook.com', 'youtube.com']


def create_nodes(tx, cap):
    result = tx.run("CREATE (d:DNS)-[:RESOLVED_TO]->(i:IP) "
                    "CREATE (h:HOST) "
                    "CREATE (i_src:IP) "
                    "CREATE (i_dst:IP) "
                    "SET d.trans_id = $trans_id "
                    "SET h.domain_url = $host "
                    "SET i_src.ip = $src "
                    "SET i_dst.ip = $dst "
                    "CREATE (d)-[:HAS_QUERY]->(h) "
                    "CREATE (h)-[:RESOLVED_TO]->(i) "
                    "CREATE (i_src)-[:HAS_DNS_REQUEST]->(d) "
                    "CREATE (i_dst)-[:HAS_DNS_RESPONSE]->(d)",
                     {"host": cap['host'], "src": cap['src'], "dst": cap['dst'], "trans_id": cap['trans_id']})


def update_db(transaction, package):
    with driver.session() as session:
        session.write_transaction(transaction, package)


def print_pcap():
    cap = pyshark.FileCapture('dns.cap')
    i = 0
    print(cap[0])
    print(cap[0].dns.field_names)
    print(cap[5].dns.id)

    for packet in cap:
        print(packet)
        print(i)
        i += 1
    """
    
    packet1 = cap[3]
    print(packet1)
    print(packet1.ip.src)
    print(packet1.dns.qry_name)
    print(len(cap))
    """


def pcap_to_dict(filename):
    cap = pyshark.FileCapture(filename)
    for packet in cap:
        packet_dict = {'trans_id': packet.dns.id, 'src': packet.ip.src, 'dst': packet.ip.dst, 'host': packet.dns.qry_name}
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


#print_pcap()
pcap_to_dict('dns.cap')
#update_db(delete_db, "test")

#pcap_to_dict('dns.cap')
#update_db("test")
