MIS4900 - Master Thesis Project
This repository contains all files used in my Master thesis projects.
Python functions
  * import.log.py - Imports log data from TXT and PCAP files into Neo4j
  * txt_to_csv.py - Used to convert the Eidsiva dataset from TXT to CSV format (only for testing)
  * dataset_info.py - Returns metadata for the Eidsiva dataset
  
The databases folder contains Neo4j database dump files with a subset of the content used in the testing phase of this project.
The dump files can be loaded into Neo4j using the following command:
'''
$neo4j-home> bin/neo4j-admin load --from=/backups/neo4j/database.dump --database=neo4j --force
'''
