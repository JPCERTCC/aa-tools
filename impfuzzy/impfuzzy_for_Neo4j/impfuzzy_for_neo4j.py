#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/aa-tools/
#

import os
import sys
import csv
import re
import json
import argparse
import hashlib

# password = {Your neo4j password}
NEO4J_PASSWORD = "{password}"
# neo4j user name
NEO4J_USER = "neo4j"
# neo4j listen port
NEO4J_PORT = "7474"

try:
    from pylouvain import PyLouvain
    has_pylouvain = True
except ImportError:
    has_pylouvain = False

try:
    import pyimpfuzzy
    has_pyimpfuzzy = True
except ImportError:
    has_pyimpfuzzy = False

try:
    from py2neo import Graph
    has_py2neo = True
except ImportError:
    has_py2neo = False

statement_c = """
  MERGE (m:Malware{ id:{id} }) set m.name={name}, m.impfuzzy={impfuzzy}, m.md5={md5},
                                   m.sha1={sha1}, m.sha256={sha256}, m.cluster={cluster}

  RETURN m
  """

statement_r = """
  MATCH (m1:Malware { id:{id1} })
  MATCH (m2:Malware { id:{id2} })
  CREATE (m1)-[s1:same]->(m2) set s1.value={value}

  RETURN m1, m2
  """

parser = argparse.ArgumentParser(description="impfuzzy for neo4j")
parser.add_argument("-l", "--list", dest="listname", action="store", metavar="LIST",
                    help="Hash List (File Name, impfuzzy hash, md5, sha1, sha256)")
parser.add_argument("-d", "--directory", dest="directory", action="store", metavar="DIRECTORY",
                    help="Malware Directory")
parser.add_argument("-f", "--file", dest="file", action="store", metavar="FILE",
                    help="Windows Executable File (EXE, DLL)")
parser.add_argument("-t", "--threshold", dest="threshold", action="store", type=int, metavar="THRESHOLD",
                    help="Impfuzzy hashing threshold (Default 30)")
parser.add_argument("--delete", action="store_true", default=False,
                    help="Delete all nodes and relationships from this Neo4j database. (default: False)")
parser.add_argument("--nocluster", action="store_true", default=False,
                    help="Not clustering the malware. (default: False)")
args = parser.parse_args()


# Calculate hash
def get_digest(file):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    try:
        impfuzzy = pyimpfuzzy.get_impfuzzy(file)
    except:
        impfuzzy = ""

    with open(file, "rb") as f:
        while True:
            buf = f.read(2047)
            if not buf:
                break
            md5.update(buf)
            sha1.update(buf)
            sha256.update(buf)

    return impfuzzy, md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


# Compare impfuzzy
def impfuzzy_comp(list, list_new):
    ssdeep = re.compile("^[0-9]{1,5}:[0-9a-zA-Z\/\+]+:[0-9a-zA-Z\/\+]+$", re.DOTALL)
    complist = []
    list_len = len(list_new)
    i = 0
    for item_new in list_new:
        i += 1
        if re.search(ssdeep, item_new[2]) and len(item_new[2]) < 150:
            for j in range(i, list_len):
                if re.search(ssdeep, list_new[j][2]) and len(list_new[j][2]) < 150:
                    complist.append([item_new[0], list_new[j][0], pyimpfuzzy.hash_compare(item_new[2], list_new[j][2])])
                else:
                    ("[!] This impfuzzy hash is not ssdeep format: %s" % item_new[2])

    if list:
        for item_new in list_new:
            if re.search(ssdeep, item_new[2]) and len(item_new[2]) < 150:
                for item in list:
                    if re.search(ssdeep, item[2]) and len(item[2]) < 150:
                        complist.append([item_new[0], item[0], pyimpfuzzy.hash_compare(item_new[2], item[2])])
                    else:
                        ("[!] This impfuzzy hash is not ssdeep format: %s" % item[2])
            else:
                ("[!] This impfuzzy hash is not ssdeep format: %s" % item_new[2])

    return complist


def main():
    if not has_pyimpfuzzy:
        sys.exit("[!] pyimpfuzzy must be installed for this script.")

    if not has_py2neo:
        sys.exit("[!] py2neo must be installed for this script.")

    if not has_pylouvain and not args.nocluster:
        sys.exit("[!] Please download the pylouvain from https://github.com/patapizza/pylouvain.")

    try:
        graph_http = "http://" + NEO4J_USER + ":" + NEO4J_PASSWORD +"@:" + NEO4J_PORT + "/db/data/"
        GRAPH = Graph(graph_http)
    except:
        sys.exit("[!] Can't connect Neo4j Database.")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

    hashlist = []
    hashlist_new = []
    nodes = []
    edges = []
    relationships = []

    # This is a impfuzzys threshold
    if args.threshold:
        ss_threshold = args.threshold
    else:
        ss_threshold = 30
    print("[*] Impfuzzy threshold is %i." % ss_threshold)

    # Delete database data
    if args.delete:
        GRAPH.delete_all()
        print("[*] Delete all nodes and relationships from this Neo4j database.")

    # Load database data
    database = GRAPH.data("MATCH (m:Malware) RETURN m.id, m.name, m.impfuzzy, m.md5, m.sha1, m.sha256")

    if database:
        print("[*] Database nodes %d." % len(database))
        for d in database:
            hashlist.append([d["m.id"], d["m.name"], d["m.impfuzzy"], d["m.md5"], d["m.sha1"], d["m.sha256"]])

    nodes_count = len(database)
    # Load relationships
    relation_data = GRAPH.data("MATCH (m1:Malware)-[s:same]-(m2:Malware) RETURN m1.id,m2.id,s.value")
    if relation_data:
        print("[*] Database relationships %d." % len(relation_data))
        for r in relation_data:
            relationships.append([r["m1.id"], r["m2.id"], r["s.value"]])

    for x in range(nodes_count):
        nodes.append(x)

    print("[*] Creating a graph data.")

    # Import data from EXE or DLL
    if args.file:
        if os.path.isfile(args.file):
            i = nodes_count
            impfuzzy, md5, sha1, sha256 = get_digest(args.file)
            query = "MATCH (m:Malware) WHERE m.sha256=\"%s\" RETURN m" % sha256
            if impfuzzy:
                if not GRAPH.data(query):
                    nodes.append(i)
                    hashlist_new.append([i, args.file, impfuzzy, md5, sha1, sha256])
                else:
                    print("[!] This malware is registered already. sha256: %s" % sha256)
            else:
                print("[!] Can't calculate the impfuzzy hash. sha256: %s" % sha256)
        else:
            sys.exit("[!] Can't open file {0}.".format(args.file))

    # Import data from directory
    if args.directory:
        try:
            files = os.listdir(args.directory)
        except OSError:
            sys.exit("[!] Can't open directory {0}.".format(args.directory))

        outf = args.directory + "_hash.csv"
        fl = open(outf, "w")
        i = nodes_count
        for file in files:
            filename = args.directory + "/" + file
            impfuzzy, md5, sha1, sha256 = get_digest(filename)
            fl.write("%s,%s,%s,%s,%s\n" % (file, impfuzzy, md5, sha1, sha256))
            query = "MATCH (m:Malware) WHERE m.sha256=\"%s\" RETURN m" % sha256
            if impfuzzy:
                if not GRAPH.data(query):
                    nodes.append(i)
                    hashlist_new.append([i, file, impfuzzy, md5, sha1, sha256])
                    i += 1
                else:
                    print("[!] This malware is registered already. sha256: %s" % sha256)
            else:
                print("[!] Can't calculate the impfuzzy hash. sha256: %s" % sha256)
        print("[*] Created hash list %s." % outf)
        fl.close()

    # Import data from csv file
    if args.listname:
        print("[*] Parse file %s." % args.listname)
        try:
            csvfile = csv.reader(open(args.listname), delimiter=",")
        except IOError:
            sys.exit("[!] Can't open file {0}.".format(args.listname))

        i = nodes_count
        for array in csvfile:
            query = "MATCH (m:Malware) WHERE m.sha256=\"%s\" RETURN m" % array[4]
            if array[1]:
                if not GRAPH.data(query):
                    nodes.append(i)
                    array.insert(0, i)
                    hashlist_new.append(array)
                    i += 1
                else:
                    print("[!] This malware is registered already. sha256: %s" % array[4])
            else:
                print("[!] Impfuzzy hash is blank. sha256: %s" % array[4])

    # Compare impfuzzy
    print("[*] The total number of malware is %i." % i)
    result_list = impfuzzy_comp(hashlist, hashlist_new)

    if len(database) != len(nodes):
        # Clustering
        if not args.nocluster:
            for edge in result_list + relationships:
                if edge[2] > ss_threshold:
                    edges.append([[edge[0], edge[1]], edge[2]])
                else:
                    edges.append([[edge[0], edge[1]], 0])
            pyl = PyLouvain(nodes, edges)
            partition, modularity = pyl.apply_method()
            print("[*] The number of clusters is %i." % (len(partition) - 1))
        else:
            print("[*] No clustering option.")

        # Create node
        tx = GRAPH.begin()
        if args.nocluster:
            for hash in hashlist_new:
                tx.append(statement_c, {"id": hash[0], "name": hash[1], "impfuzzy": hash[2],
                                        "md5": hash[3], "sha1": hash[4], "sha256": hash[5],
                                        "cluster": "NULL"})
        else:
            for hash in hashlist_new + hashlist:
                i=0
                for a in partition:
                    i=i+1
                    if hash[0] in a:
                        tx.append(statement_c, {"id": hash[0], "name": hash[1], "impfuzzy": hash[2],
                                                "md5": hash[3], "sha1": hash[4], "sha256": hash[5],
                                                "cluster": i})

        # Create relationship
        for result in result_list:
            if result[2] > ss_threshold:
                tx.append(statement_r, {"id1": result[0], "id2": result[1], "value": result[2]})

        tx.process()
        tx.commit()
        print("[*] Created a graph data.\n")
    else:
        print("[*] Not find a new malware.\n")

    print("  Access to http://localhost:7474 via Web browser.")
    print("  Use Cypher query. You can see the graph.\n")
    print("  == Cypher Query Examples ==")
    print("  [Visualizing the all clusters]")
    print("  $ MATCH (m:Malware) RETURN m\n")
    print("  [Visualizing the clusters that matches the MD5 hash]")
    print("  $ MATCH (m1:Malware)-[s]-() WHERE m1.md5 = \"[MD5]\"")
    print("    MATCH (m2:Malware) WHERE m2.cluster = m1.cluster")
    print("    RETURN m2\n")
    print("  [Visualizing the clusters that matches the threshold more than 90]")
    print("  $ MATCH (m:Malware)-[s:same]-() WHERE s.value > 90 RETURN m,s")
    print("  ===========================\n")


if __name__ == "__main__":
    main()
