import json
import rdflib
from rdflib import URIRef, BNode, Literal, Graph, Namespace
from rdflib.namespace import RDF, RDFS, XSD, DC, DCTERMS
import hashlib
import urllib

CORE = Namespace("http://ontologies.ti-semantics.com/core#")
CTI = Namespace("http://ontologies.ti-semantics.com/cti#")
PLATFORM = Namespace("http://ontologies.ti-semantics.com/platform#")
SCORE = Namespace("http://ontologies.ti-semantics.com/score#")

def read_file(filename):
    with open(filename, 'r') as f:
        return json.loads(f.read())

##### ELEMENTS #####

def do_default_e(n, s, o):
    g = Graph()
    return g

def do_s_p_l(n, s, p, o):
    g = Graph()
    g.add( (s, p, Literal(o)) )
    return g

def do_s_p_lt(n, s, p, o, t):
    g = Graph()
    g.add( (s, p, Literal(o, datatype=t)) )
    return g

def do_aliases(n, s, o):
    g = Graph()
    for i in o:
        g.add( (s, DCTERMS.alternative, Literal(i)) )
    return g

def do_kill_chain_phase(n, s, o):
    g = Graph()
    for i in o:
        g.add( (s, n['killChainPhase'], n[i["kill_chain_name"]+'__'+i["phase_name"]]) )
    return g

def do_tactic_refs(n, s, o):
    g = Graph()
    for i in o:
        refnode = n[i]
        g.add( (s, CTI.tactic, refnode) )
        g.add( (refnode, RDF.type, CTI.Tactic ) )
    return g
    
def do_external_references(n, s, o):
    g = Graph()
    for i in o:
        m = hashlib.sha256()
        for k in sorted(i.keys()):
            m.update((k+i[k]).encode('utf-8'))
        refnode = n['ref_'+m.hexdigest()]
        g.add( (s, CORE['reference'], refnode) )
        g.add( (refnode, RDF.type, CORE.Reference) )
        if "url" in i:
            g.add( (refnode, CORE.referenceURL, Literal(i['url'], datatype=XSD.anyURI)) )
        if "source_name" in i:
            g.add( (refnode, CORE.referenceSource, Literal(i['source_name'], datatype=XSD.token)) )
        if "external_id" in i:
            g.add( (refnode, CORE.externalID, Literal(i['external_id'], datatype=XSD.token)) )
        if "description" in i:
            g.add( (refnode, DCTERMS.description, Literal(i['description'])) )
    return g

def do_x_mitre_permissions_required(n, s, o):
    g = Graph()
    for i in o:
        refnode = n[urllib.parse.quote_plus(i)]
        g.add( (s, SCORE['hasPrivilegesRequired'], refnode) )
        if i in ["User", "Remote Desktop Users"]:
            g.add( (refnode, RDF.type, SCORE.CVSSv3LowPrivilegesRequired) )
        elif i in ["Administrator", "root", "SYSTEM"]:
            g.add( (refnode, RDF.type, SCORE.CVSSv3HighPrivilegesRequired) )
        else:
            print("WARNING: unknown privileges type '{}'".format(i))
    return g

def do_created_by_ref(n, s, o):
    g = Graph()
    refnode = n[o]
    g.add( (s, DCTERMS['creator'], refnode) )
    g.add( (refnode, RDF.type, DCTERMS.Agent) )
    return g

def do_x_mitre_platforms(n, s, o):
    g = Graph()
    for i in o:
        refnode = n[i]
        g.add( (s, PLATFORM['platform'], refnode) )
        g.add( (refnode, RDF.type, CORE.Platform) )
    return g

def do_object_marking_refs(n, s, o):
    g = Graph()
    for i in o:
        refnode = n[i]
        g.add( (s, DCTERMS.rights, refnode) )
        g.add( (refnode, RDF.type, DCTERMS.RightsStatement) )
    return g

def process_element(n, s, o, exclusion=['id', 'type']):
    g = Graph()
    for k in o.keys():
        if not k in exclusion:
            if k in xe:
                g += xe[k](n, s, o[k])
            else:
                print("WARNING: Don't know how to process data element '{}'".format(k))
    return g

xe = {
    "created_by_ref":               lambda n, s, o: do_created_by_ref(n, s, o),
    "name":                         lambda n, s, o: do_s_p_l(n, s, DCTERMS.title, o),
    "description":                  lambda n, s, o: do_s_p_l(n, s, DCTERMS.description, o),
    "external_references":          lambda n, s, o: do_external_references(n, s, o),
    "object_marking_refs":          lambda n, s, o: do_object_marking_refs(n, s, o),
    "x_mitre_version":              lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_data_sources":         lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_detection":            lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_permissions_required": lambda n, s, o: do_x_mitre_permissions_required(n, s, o),
    "x_mitre_platforms":            lambda n, s, o: do_x_mitre_platforms(n, s, o),
    "x_mitre_contributors":         lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_effective_permissions":lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_system_requirements":  lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_remote_support":       lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_network_requirements": lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_defense_bypassed":     lambda n, s, o: do_default_e(n, s, o),
    "kill_chain_phases":            lambda n, s, o: do_kill_chain_phase(n, s, o),
    "modified":                     lambda n, s, o: do_s_p_lt(n, s, DCTERMS.modifed, o, XSD.dateTime),
    "created":                      lambda n, s, o: do_s_p_lt(n, s, DCTERMS.created, o, XSD.dateTime),
    "source_ref":                   lambda n, s, o: do_default_e(n, s, o),
    'relationship_type':            lambda n, s, o: do_default_e(n, s, o),
    "target_ref":                   lambda n, s, o: do_default_e(n, s, o),
    "identity_class":               lambda n, s, o: do_default_e(n, s, o),
    "aliases":                      lambda n, s, o: do_aliases(n, s, o),
    "revoked":                      lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_shortname":            lambda n, s, o: do_s_p_l(n, s, DCTERMS.alternative, o),
    "definition_type":              lambda n, s, o: do_default_e(n, s, o),
    "definition":                   lambda n, s, o: do_default_e(n, s, o),
    "tactic_refs":                  lambda n, s, o: do_tactic_refs(n, s, o),
    "labels":                       lambda n, s, o: do_default_e(n, s, o),
    "x_mitre_aliases":              lambda n, s, o: do_default_e(n, s, o)
}

##### OBJECTS ######

def do_default_o(n, o):
    g = Graph()
    if 'id' in o:
        s = n[o['id']]
        if 'type' in o:
            g.add( (s, RDF.type, n[o['type']]) )
        g += process_element(n, s, o)
    return g

def do_marking_definition(n, o):
    g = Graph()
    if 'id' in o:
        s = n[o['id']]
        if 'type' in o:
            g.add( (s, RDF.type, DCTERMS.RightsStatement) )
        g += process_element(n, s, o)
    return g

def do_identity(n, o):
    g = Graph()
    if 'id' in o:
        s = n[o['id']]
        if 'type' in o:
            g.add( (s, RDF.type, DCTERMS.Agent) )
        g += process_element(n, s, o, exclusion=['id', 'type', 'identity_class'])
    return g

def do_relationship(n, o):
    g = Graph()
    sub = n[o['source_ref']]
    if o['relationship_type'] == 'mitigates':
        prd = CTI.mitigates
    elif o['relationship_type'] == 'revoked-by':
        prd = CTI.revokedBy
    elif o['relationship_type'] == 'uses':
        prd = CTI.uses
            
    prd = n[o['relationship_type']]
    obj = n[o['target_ref']]
    # non-reified version:
    g.add( (sub, prd, obj) )
    # reified version:
    statementId = BNode()
    g.add( (statementId, RDF.type, RDF.Statement) )
    g.add( (statementId, RDF.subject, sub) )
    g.add( (statementId, RDF.predicate, prd) )
    g.add( (statementId, RDF.object, obj) )
    # and now we can make statements about this relationship
    g.add ( (statementId, DCTERMS.creator, n[o['created_by_ref']]) )
    g.add ( (statementId, DCTERMS.created, Literal(o['created'], datatype=XSD.dateTime)) )
    g.add ( (statementId, DCTERMS.modified, Literal(o['modified'], datatype=XSD.dateTime)) )
    g.add ( (statementId, DCTERMS.identifier, Literal(o['id'])) )
    for i in o['object_marking_refs']:
        g.add ( (statementId, DCTERMS.rights, n[i]) )
    return g

xo = {
    'attack-pattern':     lambda n, o: do_default_o(n, o),
    'course-of-action':   lambda n, o: do_default_o(n, o),
    'identity':           lambda n, o: do_identity(n, o),
    'intrusion-set':      lambda n, o: do_default_o(n, o),
    'malware':            lambda n, o: do_default_o(n, o),
    'marking-definition': lambda n, o: do_marking_definition(n, o),
    'relationship':       lambda n, o: do_relationship(n, o),
    'tool':               lambda n, o: do_default_o(n, o),
    'x-mitre-matrix':     lambda n, o: do_default_o(n, o),
    'x-mitre-tactic':     lambda n, o: do_default_o(n, o),
}

#####
    
def parse():
    doc = read_file('cache/enterprise-attack.json')
    n = Namespace("http://ti-semantics.com/attack#")
    g = Graph()
    #print(doc["type"], doc["spec_version"])
    if doc["type"] == "bundle" and doc["spec_version"] == "2.0" and 'objects' in doc:
        #print(len(doc['objects']))
        for ao in doc['objects']:
            # print(ao['type'])
            g = g + xo[ao['type']](n, ao)
    g.bind('dcterms', DCTERMS)
    g.bind('dc', DC)
    g.bind('core', CORE)
    g.bind('score', SCORE)
    g.bind('plat', PLATFORM)
    g.bind('rdf', RDF)
    g.bind('cti', CTI)
    g.bind('attack', n)
    #print(g.serialize(format='turtle').decode('utf-8'))
    with open('cache/enterprise-attack.ttl', 'w') as f:
        f.write(g.serialize(format='turtle', encoding='utf-8').decode('utf-8'))
parse()

