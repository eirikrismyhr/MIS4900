from neo4j import GraphDatabase
import pyshark
from py2neo import Graph

"""
1. Read each packet from pcap file
2. Convert each packet to python dict
3. Create nodes and relationships in Neo4j for each dict
"""
graph = Graph(password="mis4900")

uri = "bolt://localhost:7687"
driver = GraphDatabase.driver(uri, auth=("neo4j", "mis4900"))

domains = ['google.com', 'facebook.com', 'youtube.com']


def acted_in(tx, name):
    for record in tx.run("MATCH (a:Person)-[:ACTED_IN]->(f) "
                         "RETURN f.title"):
        print(record["f.title"])


def create_nodes(tx, cap):
    result = tx.run("UNWIND $cap AS pcap"
                    "CREATE (d:DNS)-[:RESOLVED_TO]->(i:IP)"
                    "CREATE (h:HOST)"
                    "SET h.domain_url = $pcap[host]"
                    "CREATE (d)-[:HAS_QUERY]->(h)"
                    "CREATE (h)-[:RESOLVED_TO]->(i)"
                    "RETURN d.domain_url + ', from node ' + id(d)", cap=cap, parameters={'dict_param': cap})



"""
"CREATE (d:DNS)-[:RESOLVED_TO]->(i:IP)"
                    "CREATE (h:HOST)"
                    "SET h.domain_url = dict_param[host]"
                    "CREATE (d)-[:HAS_QUERY]->(h)"
                    "CREATE (h)-[:RESOLVED_TO]->(i)"
                    "RETURN d.domain_url + ', from node ' + id(d)", cap=cap, parameters={'dict_param': cap})

"""
def update_db(package):
    with driver.session() as session:
        # session.write_transaction(acted_in, "The Matrix")
        session.read_transaction(create_nodes, package)


def print_pcap():
    cap = pyshark.FileCapture('dns.cap')
    i = 0
    print(cap[0])
    print(cap[0].ip.field_names)
    print(cap[0].ip.dst)
    """
    for packet in cap:
        print(packet)
        print(i)
        i += 1
    
    packet1 = cap[3]
    print(packet1)
    print(packet1.ip.src)
    print(packet1.dns.qry_name)
    print(len(cap))
    """


def pcap_to_dict(filename):
    cap = pyshark.FileCapture(filename)
    for packet in cap:
        packet_dict = {'src': packet.ip.src, 'dest': packet.ip.dst, 'host': packet.dns.qry_name}
        update_db(packet_dict)


def delete_db(tx):
    result = tx.run(statement="CREATE (x) SET x = {dict_param}")


#print_pcap()
#update_db()

#pcap_to_dict('dns.cap')
#update_db("test")
