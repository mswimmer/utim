import rdflib
from rdflib.plugins.sparql.processor import prepareQuery
"""
Check the resulting ontologies for things we may have not covered properly
"""

# lists of entities we have checked in the ontology already
checked_predicates = [
    "http://ontologies.ti-semantics.com/core#referenceSource",
    "http://ontologies.ti-semantics.com/core#externalID",
    "http://ontologies.ti-semantics.com/cti#uses",
    "http://ontologies.ti-semantics.com/core#reference",
    "http://ontologies.ti-semantics.com/cti#label",
    "http://ontologies.ti-semantics.com/cti#mitigates",
    "http://ontologies.ti-semantics.com/core#referenceURL",
    "http://ontologies.ti-semantics.com/platform#platform",
    "http://ontologies.ti-semantics.com/cti#revoked",
    "http://ontologies.ti-semantics.com/cti#revokedBy",
    "http://ontologies.ti-semantics.com/cti#tactic"
    ]
qprds = prepareQuery(
        """SELECT DISTINCT ?e
        WHERE {
          ?sub ?e ?obj .
        FILTER(STRSTARTS(STR(?e), ?base))
        }""")

checked_objects = checked_predicates + [
    "http://ontologies.ti-semantics.com/cti#AttackPattern",
    "http://ontologies.ti-semantics.com/core#Reference",
    "http://ontologies.ti-semantics.com/cti#IntrusionSet",
    "http://ontologies.ti-semantics.com/cti#Malware",
    "http://ontologies.ti-semantics.com/cti#CourseOfAction",
    "http://ontologies.ti-semantics.com/cti#Tool",
    "http://ontologies.ti-semantics.com/score#CVSSv3HighPrivilegesRequired",
    "http://ontologies.ti-semantics.com/score#CVSSv3LowPrivilegesRequired",
    "http://ontologies.ti-semantics.com/cti#Matrix",
    "http://ontologies.ti-semantics.com/core#Platform"
    ]

qobjs = prepareQuery(
        """SELECT DISTINCT ?e
        WHERE {
          ?sub ?prd ?e .
        FILTER(STRSTARTS(STR(?e), ?base))
        }""")

checked_subjects = []

qsubs = prepareQuery(
        """SELECT DISTINCT ?e
        WHERE {
          ?e ?prd ?obj .
        FILTER(STRSTARTS(STR(?e), ?base))
        }""")

###

g = rdflib.Graph()
g.parse("enterprise-attack.ttl", format="turtle")

def check_graph(g):
    print("Unchecked Subjects")
    for row in g.query(qsubs, initBindings={'base': rdflib.Literal("http://ontologies.ti-semantics.com")}):
        if not str(row[0]) in checked_subjects:
            print(row[0])
    print("Unchecked Predicates")
    for row in g.query(qprds, initBindings={'base': rdflib.Literal("http://ontologies.ti-semantics.com")}):
        if not str(row[0]) in checked_predicates:
            print(row[0])
    print("Unchecked Objects")
    for row in g.query(qobjs, initBindings={'base': rdflib.Literal("http://ontologies.ti-semantics.com")}):
        if not str(row[0]) in checked_objects:
            print(row[0])


def check(basename):
    print("Checking", basename)
    g = rdflib.Graph()
    g.parse(basename+".ttl", format="turtle")
    check_graph(g)
    print()

check("enterprise-attack")
check("mobile-attack")
check("pre-attack")
