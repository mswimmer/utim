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
    "http://ontologies.ti-semantics.com/cti#tactic",
    "http://ontologies.ti-semantics.com/cti#alias",
    # some version that isn't normative but we might include anyway
    "http://ti-semantics.com/attack#mitreVersion",
    "http://ontologies.ti-semantics.com/cti#killChainPhase",
    "http://ontologies.ti-semantics.com/cti#observedData",
    "http://ontologies.ti-semantics.com/cti#detectionBypassed",
    "http://ontologies.ti-semantics.com/cti#hasDetection",
    "http://ti-semantics.com/attack#mitreRemoteSupport" # I don't know what this means
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
    "http://ontologies.ti-semantics.com/core#Platform",
    "http://ontologies.ti-semantics.com/cti#Tactic",
    "http://ontologies.ti-semantics.com/cti#KillChainPhase",
    "http://ontologies.ti-semantics.com/cti#EnterpriseMatrix",
    "http://ontologies.ti-semantics.com/cti#MobileMatrix",
    "http://ontologies.ti-semantics.com/cti#PreMatrix",
    "http://ontologies.ti-semantics.com/cti#LogAnalysis",
    "http://ontologies.ti-semantics.com/cti#WindowsUserAccountControl",
    "http://ontologies.ti-semantics.com/cti#ObservedData",
    "http://ontologies.ti-semantics.com/cti#SignatureBasedDetection",
    "http://ontologies.ti-semantics.com/cti#HostForensicAnalysis",
    "http://ontologies.ti-semantics.com/cti#HostIntrusionPreventionSystems",
    "http://ontologies.ti-semantics.com/cti#FilePathWhitelisting",
    "http://ontologies.ti-semantics.com/cti#DigitalCertificateValidation",
    "http://ontologies.ti-semantics.com/cti#AntiVirus",
    "http://ontologies.ti-semantics.com/cti#ApplicationWhitelisting",
    "http://ontologies.ti-semantics.com/cti#UserModeSignatureValidation",
    "http://ontologies.ti-semantics.com/cti#BinaryAnalysis",
    "http://ontologies.ti-semantics.com/cti#ProcessWhitelisting",
    "http://ontologies.ti-semantics.com/cti#Firewall",
    "http://ontologies.ti-semantics.com/cti#FileSystemAccessControls",
    "http://ontologies.ti-semantics.com/cti#AutorunsAnalysis",
    "http://ontologies.ti-semantics.com/cti#SystemAccessControls",
    "http://ontologies.ti-semantics.com/cti#NetworkIntrusionDetectionSystem",
    "http://ontologies.ti-semantics.com/cti#StaticFileAnalysis",
    "http://ontologies.ti-semantics.com/cti#FileMonitoring",
    "http://ontologies.ti-semantics.com/cti#HeuristicDetection",
    "http://ontologies.ti-semantics.com/cti#ExploitPrevention",
    "http://ontologies.ti-semantics.com/cti#DefensiveNetworkServiceScanning",
    "http://ontologies.ti-semantics.com/cti#DataExecutionPrevention",
    "http://ontologies.ti-semantics.com/core#WindowsAdministrator",
    "http://ontologies.ti-semantics.com/core#LocalUser",
    "http://ontologies.ti-semantics.com/core#WindowsSystemUser",
    "http://ontologies.ti-semantics.com/core#UnixRoot",
    "http://ontologies.ti-semantics.com/cti#Detection"
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

def suppressed(e, filter_url, prefixes):
    #print(prefixes)
    for prefix in prefixes:
        #print(filter_url+prefix)
        if e.startswith(filter_url+prefix):
            return True
    return False
    
def check_graph(g, filter_url, suppression_list=[]):
    print("Unchecked Subjects")
    for row in g.query(qsubs, initBindings={'base': rdflib.Literal(filter_url)}):
        if not str(row[0]) in checked_subjects and not suppressed(row[0], filter_url, suppression_list):
            print(row[0])
    print("Unchecked Predicates")
    for row in g.query(qprds, initBindings={'base': rdflib.Literal(filter_url)}):
        if not str(row[0]) in checked_predicates and not suppressed(row[0], filter_url, suppression_list):
            print(row[0])
    print("Unchecked Objects")
    for row in g.query(qobjs, initBindings={'base': rdflib.Literal(filter_url)}):
        if not str(row[0]) in checked_objects and not suppressed(row[0], filter_url, suppression_list):
            print(row[0])


def check(basename, filter_url, suppression_list=[]):
    print("Checking", basename, "with filter", filter_url)
    g = rdflib.Graph()
    g.parse(basename+".ttl", format="turtle")
    check_graph(g, filter_url, suppression_list)
    print()

check("enterprise-attack", "http://ontologies.ti-semantics.com")
check("mobile-attack", "http://ontologies.ti-semantics.com")
check("pre-attack", "http://ontologies.ti-semantics.com")

suppression_list = [
    "/attack#ref_",
    "/attack#detection_",
    "/attack#requirement_",
    "/attack#x-mitre-tactic--",
    "/attack#attack-pattern--",
    "/attack#intrusion-set--",
    "/attack#course-of-action--",
    "/attack#malware--",
    "/attack#marking-definition--",
    "/attack#tool--",
    "/attack#identity--",
    "/attack#x-mitre-matrix--",
    "/attack#mitre-contributor--",
    "/attack#mitre-pre-attack__",
    "/attack#mitre-mobile-attack__",
    "/attack#kill-chain-phase__",
    "/attack#platform--",
    "/attack#mitre-data-source--"
    ]

check("enterprise-attack", "http://ti-semantics.com", suppression_list)
check("mobile-attack", "http://ti-semantics.com", suppression_list)
check("pre-attack", "http://ti-semantics.com", suppression_list)
