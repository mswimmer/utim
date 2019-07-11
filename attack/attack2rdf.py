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

missed = {}
missed_e = {}

##### ELEMENTS #####

def do_default_e(n, g, s, o):
    pass

def do_s_p_l(n, g, s, p, o):
    g.add( (s, p, Literal(o)) )

def do_s_p_lt(n, g, s, p, o, t):
    g.add( (s, p, Literal(o, datatype=t)) )

def do_aliases(n, g, s, o):
    for i in o:
        g.add( (s, DCTERMS.alternative, Literal(i)) )

def do_kill_chain_phase(n, g, s, o):
    for i in o:
        g.add( (s, n['killChainPhase'], n[i["kill_chain_name"]+'__'+i["phase_name"]]) )

def do_tactic_refs(n, g, s, o):
    """
    This only seems to exist once in the file and is used like this:
    {
      "type": "x-mitre-matrix",
      "id": "x-mitre-matrix--eafc1b4c-5e56-4965-bd4e-66a6a89c88cc",
      "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "created": "2018-10-17T00:14:20.652Z",
      "modified": "2018-11-06T19:05:34.143Z",
      "name": "Enterprise ATT&CK",
      "description": "The full ATT&CK Matrix ... ",
      "tactic_refs": [
        "x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca",
        "x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5",
        ...
        ]
    ...
    """
    for i in o:
        refnode = n[i]
        g.add( (s, CTI.tactic, refnode) )
        g.add( (refnode, RDF.type, CTI.Tactic ) )

def do_external_reference(n, g, s, o, i):
    """
    looks like this:         
    {
      "url": "https://...",
      "source_name": "...",
      "external_id": "...",
      "description": "..."
    }
    """
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
    
def do_external_references(n, g, s, o):
    """
    Could look like this:
    "external_references": [
        { ... }, ...
      ],
    """
    for i in o:
        do_external_reference(n, g, s, o, i)

def do_x_mitre_permissions_required(n, g, s, o):
    """
      "x_mitre_permissions_required": [
        "Administrator",
        "SYSTEM"
      ],
    Out of this we create something like:
    attack:s score:hasPrivilegesRequired attack:Administrstor .
    attack:Administrstor a score:CVSSv3HighPrivilegesRequired .
    ...
    """
    for i in o:
        refnode = n[urllib.parse.quote_plus(i)]
        g.add( (s, SCORE['hasPrivilegesRequired'], refnode) )
        if i in ["User", "Remote Desktop Users"]:
            g.add( (refnode, RDF.type, SCORE.CVSSv3LowPrivilegesRequired) )
        elif i in ["Administrator", "root", "SYSTEM"]:
            g.add( (refnode, RDF.type, SCORE.CVSSv3HighPrivilegesRequired) )
        else:
            print("WARNING: unknown privileges type '{}'".format(i))
            
def do_created_by_ref(n, g, s, o):
    """
    Like:
      "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
    """
    refnode = n[o]
    g.add( (s, DCTERMS['creator'], refnode) )
    g.add( (refnode, RDF.type, DCTERMS.Agent) )

def do_x_mitre_platforms(n, g, s, o):
    """
    Like:
      "x_mitre_platforms": [
        "Linux",
        "macOS",
        "Windows"
      ],
    """
    for i in o:
        refnode = n[i]
        g.add( (s, PLATFORM['platform'], refnode) )
        g.add( (refnode, RDF.type, CORE.Platform) )

def do_object_marking_refs(n, g, s, o):
    """
      "object_marking_refs": [
        "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
      ],
    """
    for i in o:
        refnode = n[i]
        g.add( (s, DCTERMS.rights, refnode) )
        g.add( (refnode, RDF.type, DCTERMS.RightsStatement) )

xer = {
    "external_references":          lambda n, g, s, o: do_external_references(n, g, s, o),
    "x_mitre_permissions_required": lambda n, g, s, o: do_x_mitre_permissions_required(n, g, s, o),
    "created_by_ref":               lambda n, g, s, o: do_created_by_ref(n, g, s, o),
    "x_mitre_platforms":            lambda n, g, s, o: do_x_mitre_platforms(n, g, s, o),
    "object_marking_refs":          lambda n, g, s, o: do_object_marking_refs(n, g, s, o),
    "x_mitre_version":              lambda n, g, s, o: do_default_e(n, g, s, o),
    "x_mitre_data_sources":         lambda n, g, s, o: do_default_e(n, g, s, o),
    "x_mitre_detection":            lambda n, g, s, o: do_default_e(n, g, s, o),
    "x_mitre_contributors":         lambda n, g, s, o: do_default_e(n, g, s, o),
    "x_mitre_effective_permissions":lambda n, g, s, o: do_default_e(n, g, s, o),
    "x_mitre_system_requirements":  lambda n, g, s, o: do_default_e(n, g, s, o),
    "x_mitre_remote_support":       lambda n, g, s, o: do_default_e(n, g, s, o),
    "x_mitre_network_requirements": lambda n, g, s, o: do_default_e(n, g, s, o),
    "x_mitre_defense_bypassed":     lambda n, g, s, o: do_default_e(n, g, s, o),
    "source_ref":                   lambda n, g, s, o: do_default_e(n, g, s, o),
    'relationship_type':            lambda n, g, s, o: do_default_e(n, g, s, o),
    "target_ref":                   lambda n, g, s, o: do_default_e(n, g, s, o),
    "identity_class":               lambda n, g, s, o: do_default_e(n, g, s, o),
    "revoked":                      lambda n, g, s, o: do_default_e(n, g, s, o),
    "definition_type":              lambda n, g, s, o: do_default_e(n, g, s, o),
    "definition":                   lambda n, g, s, o: do_default_e(n, g, s, o),
    "labels":                       lambda n, g, s, o: do_default_e(n, g, s, o),
    "x_mitre_aliases":              lambda n, g, s, o: do_default_e(n, g, s, o),
    "name":                         lambda n, g, s, o: do_s_p_l(n, g, s, DCTERMS.title, o),
    "description":                  lambda n, g, s, o: do_s_p_l(n, g, s, DCTERMS.description, o),
    "kill_chain_phases":            lambda n, g, s, o: do_kill_chain_phase(n, g, s, o),
    "modified":                     lambda n, g, s, o: do_s_p_lt(n, g, s, DCTERMS.modifed, o, XSD.dateTime),
    "created":                      lambda n, g, s, o: do_s_p_lt(n, g, s, DCTERMS.created, o, XSD.dateTime),
    "aliases":                      lambda n, g, s, o: do_aliases(n, g, s, o),
    "x_mitre_shortname":            lambda n, g, s, o: do_s_p_l(n, g, s, DCTERMS.alternative, o),
    "tactic_refs":                  lambda n, g, s, o: do_tactic_refs(n, g, s, o),
}
    

##### OBJECTS ######


def do_default_o(n, g, o):
    if 'id' in o:
        s = n[o['id']]
        if 'type' in o:
            missed[o['type']] = missed.get(o['type'], 0) + 1
            g.add( (s, RDF.type, n[o['type']]) )
        g += process_element(n, s, o)

def do_marking_definition(n, g, o):
    """
    {
      "type": "marking-definition",
      "id": "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168",
      "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "created": "2017-06-01T00:00:00Z",
      "definition_type": "statement",
      "definition": {
        "statement": "Copyright 2017, The MITRE Corporation"
      }
    }
    """
    if 'id' in o:
        s = n[o['id']]
        if 'type' in o:
            g.add( (s, RDF.type, DCTERMS.RightsStatement) )
        g += process_element(n, s, o)

def do_identity(n, g, o):
    if 'id' in o:
        s = n[o['id']]
        if 'type' in o:
            g.add( (s, RDF.type, DCTERMS.Agent) )
        g += process_element(n, s, o, exclusion=['id', 'type', 'identity_class'])

def do_relationship(n, g, o):
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

xo = {
    'attack-pattern':     lambda n, g, o: do_default_o(n, g, o),
    'course-of-action':   lambda n, g, o: do_default_o(n, g, o),
    'identity':           lambda n, g, o: do_identity(n, g, o),
    'intrusion-set':      lambda n, g, o: do_default_o(n, g, o),
    'malware':            lambda n, g, o: do_default_o(n, g, o),
    'marking-definition': lambda n, g, o: do_marking_definition(n, g, o),
    'relationship':       lambda n, g, o: do_relationship(n, g, o),
    'tool':               lambda n, g, o: do_default_o(n, g, o),
    'x-mitre-matrix':     lambda n, g, o: do_default_o(n, g, o),
    'x-mitre-tactic':     lambda n, g, o: do_default_o(n, g, o),
}

def process_element(n, s, o, exclusion=['id', 'type']):
    g = Graph()
    for k in o.keys():
        if not k in exclusion:
            if k in xer:
                xer[k](n, g, s, o[k])
            else:
                print("WARNING: Don't know how to process data element '{}'".format(k))
    return g

def process_objects(n, g, objs):
    for ao in objs:
        # print(ao['type'])
        xo[ao['type']](n, g, ao)
    
#####
    
def parse():
    doc = read_file('cache/enterprise-attack.json')
    n = Namespace("http://ti-semantics.com/attack#")
    g = Graph()
    #print(doc["type"], doc["spec_version"])
    if doc["type"] == "bundle" and doc["spec_version"] == "2.0" and 'objects' in doc:
        #print(len(doc['objects']))
        process_objects(n, g, doc['objects'])
    #print(missed)
    #print(missed_e)
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

