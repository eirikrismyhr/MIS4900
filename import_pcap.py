from neo4j import GraphDatabase

uri = "bolt://localhost:7687"
driver = GraphDatabase.driver(uri, auth=("neo4j", "mis4900"))

domains = ['google.com', 'facebook.com', 'youtube.com']


def acted_in(tx, name):
    for record in tx.run("MATCH (a:Person)-[:ACTED_IN]->(f) "
                         "RETURN f.title"):
        print(record["f.title"])


def create_nodes(tx, domain_url):
    result = tx.run("CREATE (i:IP)-[:RESOLVES_TO]->(d:Domain)"
                    "SET d.domain_url = $domain_url "
                    "RETURN d.domain_url + ', from node ' + id(d)", domain_url=domain_url)
    return result.single()[0]


with driver.session() as session:
    session.write_transaction(acted_in, "The Matrix")
    for item in domains:
        session.read_transaction(create_nodes, item)
