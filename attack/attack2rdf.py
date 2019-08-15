import json
import rdflib
from rdflib import URIRef, BNode, Literal, Graph, Namespace
from rdflib.namespace import RDF, RDFS, XSD, DC, DCTERMS
import hashlib
import urllib
import argparse
import sys

CORE = Namespace("http://ontologies.ti-semantics.com/core#")
CTI = Namespace("http://ontologies.ti-semantics.com/cti#")
PLATFORM = Namespace("http://ontologies.ti-semantics.com/platform#")
SCORE = Namespace("http://ontologies.ti-semantics.com/score#")

argparser = argparse.ArgumentParser(description='Convert ATT&CK JSON files to RDF.')
argparser.add_argument('--namespace', type=str, default="http://ti-semantics.com/attack#", help='Namespace for this input file')
argparser.add_argument('infile', nargs='?', type=argparse.FileType('r'), default=sys.stdin, help='Input JSON file')
argparser.add_argument('outfile', nargs='?', type=argparse.FileType('w'), default=sys.stdout, help='Output Turtle (RDF) file')

def read_file(f):
    return json.loads(f.read())

missed = {}

##### ELEMENTS #####

def do_default_e(n, g, s, o):
    pass

def do_s_p_l(n, g, s, p, o):
    g.add( (s, p, Literal(o)) )

def do_s_p_lt(n, g, s, p, o, t):
    g.add( (s, p, Literal(o, datatype=t)) )

def do_s_p_la(n, g, s, p, o):
    for i in o:
        g.add( (s, p, Literal(i)) )
    
def do_s_p_ea(n, g, s, p, o):
    for i in o:
        g.add( (s, p, n[urllib.parse.quote_plus(i)]) )

def do_s_p_e(n, g, s, p, o):
    g.add( (s, p, n[urllib.parse.quote_plus(o)]) )

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
        g.add( (s, n.mitrePermissionsRequired, refnode) )
        if i in ["User", "Remote Desktop Users"]:
            g.add( (refnode, RDF.type, SCORE.CVSSv3LowPrivilegesRequired) )
        elif i in ["Administrator", "root", "SYSTEM"]:
            g.add( (refnode, RDF.type, SCORE.CVSSv3HighPrivilegesRequired) )
        else:
            print("WARNING: unknown privileges type '{}'".format(i))

def do_x_mitre_effective_permissions(n, g, s, o):
    for i in o:
        refnode = n[urllib.parse.quote_plus(i)]
        g.add( (s, n.mitreEffectivePermissions, refnode) )
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
        
def do_definition(n, g, s, o):
    """
      "definition": {
        "statement": "Copyright 2017, The MITRE Corporation"
      }

    """
    for i in o.keys():
        g.add( (s, n[i], Literal(o[i])) )
        
xer = {
    "external_references":          lambda n, g, s, o: do_external_references(n, g, s, o),
    "x_mitre_permissions_required": lambda n, g, s, o: do_x_mitre_permissions_required(n, g, s, o),
    "created_by_ref":               lambda n, g, s, o: do_created_by_ref(n, g, s, o),
    "x_mitre_platforms":            lambda n, g, s, o: do_x_mitre_platforms(n, g, s, o),
    "object_marking_refs":          lambda n, g, s, o: do_object_marking_refs(n, g, s, o),
    "x_mitre_version":              lambda n, g, s, o: do_s_p_l(n, g, s, n.mitreVersion, o),
    "x_mitre_data_sources":         lambda n, g, s, o: do_s_p_ea(n, g, s, n.mitreDataSource, o),
    "x_mitre_detection":            lambda n, g, s, o: do_s_p_l(n, g, s, n.mitreDetection, o),
    "x_mitre_contributors":         lambda n, g, s, o: do_s_p_la(n, g, s, n.mitreContributors, o),
    "x_mitre_effective_permissions":lambda n, g, s, o: do_x_mitre_effective_permissions(n, g, s, o),
    "x_mitre_system_requirements":  lambda n, g, s, o: do_s_p_la(n, g, s, n.mitreSystemRequirements, o),
    "x_mitre_remote_support":       lambda n, g, s, o: do_s_p_lt(n, g, s, n.mitreRemoteSupport, o, XSD.boolean),
    "x_mitre_network_requirements": lambda n, g, s, o: do_s_p_lt(n, g, s, n.mitreNetworkRequirements, o, XSD.boolean),
    "x_mitre_defense_bypassed":     lambda n, g, s, o: do_s_p_ea(n, g, s, n.mitreDefenseBypassed, o),
#    "source_ref":                   lambda n, g, s, o: do_default_e(n, g, s, o),
#    'relationship_type':            lambda n, g, s, o: do_default_e(n, g, s, o),
#    "target_ref":                   lambda n, g, s, o: do_default_e(n, g, s, o),
#    "identity_class":               lambda n, g, s, o: do_default_e(n, g, s, o),
    "revoked":                      lambda n, g, s, o: do_s_p_lt(n, g, s, CTI.revoked, o, XSD.boolean),
    "definition_type":              lambda n, g, s, o: do_s_p_e(n, g, s, n.definitionType, o),
    "definition":                   lambda n, g, s, o: do_definition(n, g, s, o),
    
    "labels":                       lambda n, g, s, o: do_s_p_ea(n, g, s, CTI.label, o), # The may be redundant with type
    "x_mitre_aliases":              lambda n, g, s, o: do_s_p_la(n, g, s, n.mitreAliases, o),
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
        process_element(n, g, s, o)

def do_identity(n, g, o):
    if 'id' in o:
        s = n[o['id']]
        if 'type' in o:
            g.add( (s, RDF.type, DCTERMS.Agent) )
        process_element(n, g, s, o, exclusion=['id', 'type', 'identity_class'])

def do_relationship(n, g, o):
    sub = n[o['source_ref']]
    if o['relationship_type'] == 'mitigates':
        prd = CTI.mitigates
    elif o['relationship_type'] == 'revoked-by':
        prd = CTI.revokedBy
    elif o['relationship_type'] == 'uses':
        prd = CTI.uses
    else:
        missed[o['relationship_type']] = missed.get(o['relationship_type'], 0) + 1
        prd = None
    obj = n[o['target_ref']]
            
    if sub and prd and obj:
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

def do_attack_pattern(n, g, o):
    """
    {
          "id": "attack-pattern--01df3350-ce05-4bdf-bdf8-0a919a66d4a8",
          "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
          "name": ".bash_profile and .bashrc",
          "description": "...",
          "external_references": [ { ... }, { ... } ],
          "object_marking_refs": [ "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168" ],
          "x_mitre_version": "1.0",
          "x_mitre_data_sources": [ ... ],
          "x_mitre_detection": "...",
          "x_mitre_permissions_required": [ "...", ...],
          "x_mitre_platforms": [ "...", ... ],
          "type": "attack-pattern",
          "kill_chain_phases": [{ ... }, ...],
          "modified": "2018-10-31T13:45:13.024Z",
          "created": "2017-12-14T16:46:06.044Z"
    }
    """
    if 'id' in o:
        s = n[o['id']]
        g.add( (s, RDF.type, CTI.AttackPattern) )
        process_element(n, g, s, o)
    else:
        print("Missing 'id'", o)
        
def do_course_of_action(n, g, o):
    """
    {
      "id": "course-of-action--4f170666-7edb-4489-85c2-9affa28a72e0",
      "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "name": ".bash_profile and .bashrc Mitigation",
      "description": "...",
      "external_references": [{ ... }],
      "object_marking_refs": [ "...", ... ],
      "x_mitre_version": "1.0",
      "type": "course-of-action",
      "modified": "2018-10-17T00:14:20.652Z",
      "created": "2018-10-17T00:14:20.652Z"
    }
    """
    if 'id' in o:
        s = n[o['id']]
        g.add( (s, RDF.type, CTI.CourseOfAction) )
        process_element(n, g, s, o)
    else:
        print("Missing 'id'", o)

def do_intrusion_set(n, g, o):
    """
    {
      "type": "intrusion-set",
      "id": "intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662",
      "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "name": "APT1",
      "description": "...",
      "object_marking_refs": [ "...", ... ],
      "x_mitre_version": "1.0",
      "external_references": [{ ... }, ... ],
      "aliases": [ "APT1", ... ],
      "modified": "2018-10-17T00:14:20.652Z",
      "created": "2017-05-31T21:31:47.955Z"
    }
    """
    if 'id' in o:
        s = n[o['id']]
        g.add( (s, RDF.type, CTI.IntrusionSet) )
        process_element(n, g, s, o)
    else:
        print("Missing 'id'", o)

def do_malware(n, g, o):
    """
    {
      "id": "malware--7bec698a-7e20-4fd3-bb6a-12787770fb1a",
      "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "name": "3PARA RAT",
      "description": "...",
      "external_references": [ {...}, ... ],
      "object_marking_refs": [ "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168" ],
      "x_mitre_version": "1.0",
      "x_mitre_aliases": [ "3PARA RAT" ],
      "x_mitre_platforms": [ "Windows" ],
      "type": "malware",
      "labels": [ "malware" ],
      "modified": "2018-10-17T00:14:20.652Z",
      "created": "2017-05-31T21:32:44.131Z"
    }
    """
    if 'id' in o:
        s = n[o['id']]
        g.add( (s, RDF.type, CTI.Malware) )
        process_element(n, g, s, o)
    else:
        print("Missing 'id'", o)

def do_tool(n, g, o):
    """
    {
      "id": "tool--30489451-5886-4c46-90c9-0dff9adc5252",
      "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "name": "Arp",
      "description": "...",
      "object_marking_refs": ["marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168" ],
      "external_references": [ { ... }, ... ],
      "x_mitre_version": "1.0",
      "x_mitre_aliases": [ ... ],
      "x_mitre_platforms": [ ... ],
      "type": "tool",
      "labels": [ ... ],
      "modified": "2018-10-17T00:14:20.652Z",
      "created": "2017-05-31T21:33:02.428Z"
    }
    """
    if 'id' in o:
        s = n[o['id']]
        g.add( (s, RDF.type, CTI.Tool) )
        process_element(n, g, s, o)
    else:
        print("Missing 'id'", o)
        
def do_x_mitre_matrix(n, g, o):
    """
    {
      "type": "x-mitre-matrix",
      "id": "x-mitre-matrix--eafc1b4c-5e56-4965-bd4e-66a6a89c88cc",
      "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "created": "2018-10-17T00:14:20.652Z",
      "modified": "2018-11-06T19:05:34.143Z",
      "name": "Enterprise ATT&CK",
      "description": "...",
      "tactic_refs": [ ... ],
      "external_references": [{ ...}, ... ],
      "object_marking_refs": [ "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168" ]
    }
    """
    if 'id' in o:
        s = n[o['id']]
        g.add( (s, RDF.type, CTI.Matrix) )
        process_element(n, g, s, o)
    else:
        print("Missing 'id'", o)
        
def do_x_mitre_tactic(n, g, o):
    """
    {
      "type": "x-mitre-tactic",
      "id": "x-mitre-tactic--d108ce10-2419-4cf9-a774-46161d6c6cfe",
      "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "created": "2018-10-17T00:14:20.652Z",
      "modified": "2018-10-17T00:14:20.652Z",
      "name": "Collection",
      "description": "...",
      "external_references": [{...}],
      "object_marking_refs": ["marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"],
      "x_mitre_shortname": "collection"
    }
    """
    if 'id' in o:
        s = n[o['id']]
        g.add( (s, RDF.type, CTI.Tactic) )
        process_element(n, g, s, o)
    else:
        print("Missing 'id'", o)

    
#####################
        
xo = {
    'attack-pattern':     lambda n, g, o: do_attack_pattern(n, g, o),
    'course-of-action':   lambda n, g, o: do_course_of_action(n, g, o),
    'identity':           lambda n, g, o: do_identity(n, g, o),
    'intrusion-set':      lambda n, g, o: do_intrusion_set(n, g, o),
    'malware':            lambda n, g, o: do_malware(n, g, o),
    'marking-definition': lambda n, g, o: do_marking_definition(n, g, o),
    'relationship':       lambda n, g, o: do_relationship(n, g, o),
    'tool':               lambda n, g, o: do_tool(n, g, o),
    'x-mitre-matrix':     lambda n, g, o: do_x_mitre_matrix(n, g, o),
    'x-mitre-tactic':     lambda n, g, o: do_x_mitre_tactic(n, g, o),
}

def process_element(n, g, s, o, exclusion=['id', 'type']):
    for k in o.keys():
        if not k in exclusion:
            if k in xer:
                xer[k](n, g, s, o[k])
            else:
                missed[k] = missed.get(k, 0) + 1
                #print("WARNING: Don't know how to process data element '{}'".format(k))

def process_objects(n, g, objs):
    for ao in objs:
        # print(ao['type'])
        xo[ao['type']](n, g, ao)
    
#####
    
def parse(infile, namespace, outfile):
    doc = read_file(infile)
    n = Namespace(namespace)
    g = Graph()
    #print(doc["type"], doc["spec_version"])
    if doc["type"] == "bundle" and doc["spec_version"] == "2.0" and 'objects' in doc:
        #print(len(doc['objects']))
        process_objects(n, g, doc['objects'])
    sys.stderr.write("unknown JSON keys: " + str(missed) + '\n')
    g.bind('dcterms', DCTERMS)
    g.bind('dc', DC)
    g.bind('core', CORE)
    g.bind('score', SCORE)
    g.bind('plat', PLATFORM)
    g.bind('rdf', RDF)
    g.bind('cti', CTI)
    g.bind('attack', n)
    #print(g.serialize(format='turtle').decode('utf-8'))
    outfile.write(g.serialize(format='turtle', encoding='utf-8').decode('utf-8'))


args = argparser.parse_args()
print(args)

parse(args.infile, args.namespace, args.outfile)

