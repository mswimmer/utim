import json
import rdflib
from rdflib import URIRef, BNode, Literal, Graph, Namespace
from rdflib.namespace import RDF

def read_file():
    with open('cache/enterprise-attack.json', 'r') as f:
        return json.loads(f.read())

def do_default_e(n, s, o):
    g = Graph()
    return g

def do_attack_pattern(n, o):
    g = Graph()
    if 'id' in o:
        s = n[o['id']]
        if 'type' in o:
            g.add( (s, RDF.type, n[o['type']]) )
        for k in o.keys():
            if not k in ['id', 'type']:
                g = g + xe[k](n, s, o[k])
    return g

def do_default_o(n, o):
    #print(o.keys())
    g = Graph()
    return g

def do_course_of_action(n, o):
    print(o.keys())
def do_identity(n, o):
    print(o.keys())
def do_intrusion_set(n, o):
    print(o.keys())
def do_malware(n, o):
    print(o.keys())
def do_marking_definition(n, o):
    print(o.keys())
def do_relationship(n, o):
    print(o.keys())
def do_tool(n, o):
    print(o.keys())
def do_x_mitre_matrix(n, o):
    print(o.keys())
def do_x_mitre_tactic(n, o):
    print(o.keys())

xe = {
    "id":                           lambda n, s, o: do_default_e(n, s, o),
    "created_by_ref":               lambda n, s, o: do_default_e(n, s, o),
    "name":                         lambda n, s, o: do_default_e(n, s, o),
    "description":                  lambda n, s, o: do_default_e(n, s, o),
    "external_references":          lambda n, s, o: do_default_e(n, s, o),
    "object_marking_refs":          lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_version":              lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_data_sources":         lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_detection":            lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_permissions_required": lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_platforms":            lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_contributors":         lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_effective_permissions":lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_system_requirements":  lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_remote_support":       lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_network_requirements": lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_defense_bypassed":     lambda n, s, o: do_default_e(n, s, o),
    "type":                         lambda n, s, o: do_default_e(n, s, o),
    "kill_chain_phases":            lambda n, s, o: do_default_e(n, s, o),
    "modified":                     lambda n, s, o: do_default_e(n, s, o),
    "created":                      lambda n, s, o: do_default_e(n, s, o)
}
    
xo = {
    'attack-pattern':     lambda n, o: do_attack_pattern(n, o),
    'course-of-action':   lambda n, o: do_default_o(n, o),
    'identity':           lambda n, o: do_default_o(n, o),
    'intrusion-set':      lambda n, o: do_default_o(n, o),
    'malware':            lambda n, o: do_default_o(n, o),
    'marking-definition': lambda n, o: do_default_o(n, o),
    'relationship':       lambda n, o: do_default_o(n, o),
    'tool':               lambda n, o: do_default_o(n, o),
    'x-mitre-matrix':     lambda n, o: do_default_o(n, o),
    'x-mitre-tactic':     lambda n, o: do_default_o(n, o),
}
    
def parse():
    doc = read_file()
    n = Namespace("http://ti-semantics.com/attack#")
    g = Graph()
    #print(doc["type"], doc["spec_version"])
    if doc["type"] == "bundle" and doc["spec_version"] == "2.0" and 'objects' in doc:
        #print(len(doc['objects']))
        for ao in doc['objects']:
            print(ao['type'])
            g = g + xo[ao['type']](n, ao)
    print(g.serialize(format='turtle').decode('utf-8'))
    
parse()

