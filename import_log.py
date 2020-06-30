from neo4j import GraphDatabase
import pyshark
import time
import csv
import whois
import ipaddress

"""
1. Read each packet from log file
2. Convert each packet to python dict
3. Create nodes and relationships in Neo4j for each dict
4. Connect nodes from each packet
"""

# Loads the official Neo4j Python driver
uri = "bolt://localhost:7687"
driver = GraphDatabase.driver(uri, auth=("neo4j", "mis4900"), encrypted=False)

# Reset WHOIS cache
f = open("datasets/whois_cache.csv", "w")
f.close()


# Creates nodes and relationships in Neo4j
def create_graph(tx, cap):
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
    if cap['nxdomain'] is not None:
        tx.run("MATCH (d:Domain {name: $host}) "
               "MERGE (n:NXDOMAIN) "
               "MERGE (d)-[:NOT_EXIST]->(n)",
               {"host": cap['host']})
    if cap['dst'] is not None:
        tx.run("MATCH (d:Domain {name: $host}) "
               "MERGE (i:IP {ip: $dst, blacklisted: $blacklisted}) "
               "MERGE (d)-[:RESOLVES_TO]->(i)",
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
               "SET p.creation_date = $creation_date",
               {"registrar": cap['registrar'], "host": cap['host'], "creation_date": cap['creation_date']})
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
    if cap['asn'] is not None:
        tx.run("MATCH (i:IP {ip: $dst}) "
               "MERGE (as:AS {number: $asn}) "
               "MERGE (i)-[:IN_NETWORK]->(as) "
               "MERGE (isp:ISP {name: $isp}) "
               "MERGE (isp)-[:ADMINISTERS]->(as)",
               {"dst": cap['dst'], "asn": cap['asn'], "isp": cap['isp']})


# Performs cypher transaction
def update_db(transaction, package):
    with driver.session() as session:
        session.write_transaction(transaction, package)


# Creates dictionary with values from log file and passes it to create_graph
def log_to_dict(filename):
    cap = pyshark.FileCapture(filename)
    filetype = filename.split(".")[1]
    if filetype == 'pcap':
        for packet in cap:
            if 'DNS' in packet:
                src = None
                if packet.dns.flags_response == '0':
                    src = packet.ip.src
                whois_result = check_whois(packet.dns.qry_name)
                geo_result = None
                packet_dict = {'trans_id': packet.dns.id, 'src': src, 'dst': None,
                               'host': packet.dns.qry_name,
                               'qry_type': packet.dns.qry_type, 'qry_class': packet.dns.qry_class,
                               'registrar': None, 'creation_date': None, 'in_blacklists':
                                   check_blacklist(packet.dns.qry_name),
                               'whitelisted': check_whitelist(packet.dns.qry_name), 'ns': None, 'mx': None,
                               'cname': None, 'txt': None, 'time': None, 'ptr': None, 'timestamp': None, 'asn': None,
                               'isp': None, 'nxdomain': None}
                try:
                    geo_result = check_geo(packet.dns.a)
                    packet_dict.update({'dst': packet.dns.a})
                    packet_dict.update({'ns': packet.dns.ns})
                    packet_dict.update({'mx': packet.dns.mx_mail_exchange})
                    packet_dict.update({'cname': packet.dns.cname})
                    packet_dict.update({'txt': packet.dns.txt})
                    packet_dict.update({'ptr': packet.dns.ptr_domain_name})
                    packet_dict.update({'time': packet.dns.time})
                    packet_dict.update({'nxdomain': packet.dns.nxdomain})
                except AttributeError:
                    print("Resource type not found in packet")
                if whois_result:
                    packet_dict.update({'registrar': whois_result['registrar']})
                    packet_dict.update({'creation_date': whois_result['creation_date']})
                if geo_result:
                    packet_dict.update({'asn': geo_result['asn']})
                    packet_dict.update({'isp': geo_result['isp']})
                update_db(create_graph, packet_dict)
    elif filetype == 'txt':
        with open(filename, "r") as logfile:
            i = 0
            for line in logfile:
                fields = line.split(" ")
                domain_name = remove_chars(fields[4])
                whois_result = check_whois(domain_name)
                try:
                    packet_dict = {'timestamp': fields[0] + ' ' + fields[1], 'src': fields[3], 'host': domain_name,
                                   'in_blacklists': check_blacklist(domain_name), 'registrar': None,
                                   'creation_date': None, 'whitelisted': check_whitelist(domain_name), 'ns': None,
                                   'mx': None, 'cname': None, 'txt': None, 'time': None, 'ptr': None, 'dst': None,
                                   'nxdomain': None, 'asn': None, 'isp': None}
                    if whois_result:
                        packet_dict.update({'registrar': whois_result['registrar']})
                        packet_dict.update({'creation_date': whois_result['creation_date']})
                    update_db(create_graph, packet_dict)
                except AttributeError:
                    print("Resource type not found in packet")
    elif filetype == 'csv':
        load_csv()
    else:
        print("Filetype not supported")


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
            line = line.split("  ")
            if line[0] == '127.0.0.1':
                domains.append(line)
        for line in domains:
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
    result = None
    try:
        whois_query = whois.query(domain)
        cached = False
        if whois_query is not None:
            if whois_query.registrar is not '':
                with open('datasets/whois_cache.csv', 'r') as cache:
                    reader = csv.reader(cache, delimiter=',')
                    for line in reader:
                        if domain == line[0]:
                            cached = True
                            result = {"registrar": line[1],
                                      "creation_date": line[2]}
                            break
                    if not cached:
                        with open('datasets/whois_cache.csv', 'a') as out_file:
                            writer = csv.writer(out_file)
                            writer.writerow((domain, whois_query.registrar, whois_query.creation_date))
                        result = {"registrar": whois_query.registrar,
                                  "creation_date": whois_query.creation_date}
    except whois.exceptions.UnknownTld:
        print("Unknown TLD")
    except whois.exceptions.WhoisCommandFailed:
        print("Command timed out")
    except (whois.exceptions.FailedParsingWhoisOutput, ValueError):
        print("Error in output")
    except KeyError:
        print("Key error")
    except whois.exceptions.UnknownDateFormat:
        print("Unknown date format")
    return result


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


# Finds ASN and ISP for each IP
def check_geo(ip):
    ip_version = ipaddress.ip_address(str(ip))
    if ip_version.version == 4:
        with open('datasets/GeoLite2-ASN-Blocks-IPv4.csv', newline='') as ipv4_list:
            reader = csv.reader(ipv4_list, delimiter=',')
            next(reader, None)
            for line in reader:
                if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(line[0]):
                    return {"asn": line[1], "isp": line[2]}
    else:
        with open('datasets/GeoLite2-ASN-Blocks-IPv6.csv', newline='') as ipv6_list:
            reader = csv.reader(ipv6_list, delimiter=',')
            next(reader, None)
            for line in reader:
                if ipaddress.IPv6Address(ip) in ipaddress.IPv6Network(line[0]):
                    return {"asn": line[1], "isp": line[2]}


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
                print(i)
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
    elif filetype == 'csv':
        with open(filename, 'r') as in_file:
            reader = csv.reader(in_file, delimiter=',')
            i = 0
            for line in reader:
                print(i)
                i += 1
                if check_blacklist(line[8]):
                    print(line[8], " Found in blacklist")
    else:
        print("Unsupported filetype")


def load_csv():
    with driver.session() as session:
        session.run("USING PERIODIC COMMIT 10000 "
                             "LOAD CSV WITH HEADERS FROM 'file:///eidsiva.csv' AS row "
                             "MERGE (d:Domain {name: row.domain_name}) "
                             "MERGE (src:IP_Host {ip: row.src}) "
                             "MERGE (src)-[query:HAS_QUERY]->(d) "
                             "ON CREATE SET query.first_seen = row.time "
                             "ON CREATE SET query.date = row.date "
                             "SET query.last_seen = row.time "
                             "RETURN row.domain_name")


# print_pcap('botnet-capture-20110810-neris.pcap')
start_time = time.time()
log_to_dict('datasets/botnet-capture-20110810-neris.pcap')

print("--- %s seconds ---" % round(time.time() - start_time, 2))
