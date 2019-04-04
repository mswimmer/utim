#!/usr/bin/env python3

"""

Worker for Mitre ATT&CK, using the STIX implementation available here:

    https://github.com/mitre/cti

    ATT&CK Property     STIX Object type        ACT object
    =========================================================
    Technique           attack-pattern          technique
    Group               intrusion-set           threatActor
    Software	        malware or tool         tool
    Mitigation	        course-of-action        n/a

"""

import argparse
import os
import sys
import traceback
from logging import error, info, warning
from typing import Any, Dict, List

import stix2
from stix2 import Filter, MemoryStore, parse

#import act
import worker
#from act.helpers import handle_fact
import json
import rdflib
from rdflib.namespace import RDF, RDFS, OWL, DCTERMS, XSD, NamespaceManager
import urllib.parse
from rdflib import Namespace, Graph, Literal, URIRef, BNode


MITRE_URLS = {
    "enterprise": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    "pre": "https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json",
    "mobile": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"
}

DEFAULT_NOTIFY_CACHE = os.path.join(os.environ["HOME"], "act-mitre-attack-notify.cache")

g = rdflib.Graph()

class NotificationError(Exception):
    """NotificationError"""

    def __init__(self, *args: Any) -> None:
        Exception.__init__(self, *args)
        
class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)
    
#def handle_fact(fact):
#    print(json.dumps(fact, cls=SetEncoder))

def add_description(individual, obj):
    if len(list(g[individual : RDFS.comment])) == 0:
        g.add( (individual, RDFS.comment, Literal(obj.description, lang='en')) )

def parseargs() -> argparse.Namespace:
    """ Parse arguments """
    parser = worker.parseargs('Mitre ATT&CK worker')
    #parser.add_argument('--smtphost', dest='smtphost', help="SMTP host used to send revoked/deprecated objects")
    #parser.add_argument('--sender', dest='sender', help="Sender address used to send revoked/deprecated objects")
    #parser.add_argument('--recipient', dest='recipient', help="Recipient address used to send revoked/deprecated objects")
    parser.add_argument('--types', default="enterprise,mobile,pre", help='Mitre attack types, comma separated. Default is "enterprise,mobile,pre"')
    parser.add_argument('--notifycache', dest='notifycache', help="Cache for revoked/deprecated objects", default=DEFAULT_NOTIFY_CACHE)
    args = parser.parse_args()

    args.types = [t.strip() for t in args.types.split(",")]

    return args

def ent(s):
    return urllib.parse.quote_plus(s)

def get_attack(url: str, proxy_string: str, timeout: int) -> MemoryStore:
    """Fetch Mitre ATT&CK JSON data in Stix2 format and return a Stix2 memory store"""
    print("starting get_attack")
    attack = worker.fetch_json(url, proxy_string, timeout)

    # Create memory store
    mem = MemoryStore()

    #print("parsing the data")
    
    #print(parse(attack, allow_custom=True))

    #print("storing the data in memory storage")
    
    # Add all objects to the memory store
    for obj in parse(attack, allow_custom=True).objects:
        #print(obj)
        mem.add(obj)

    return mem


def add_techniques(client, attack: MemoryStore, ns, attackType) -> List[stix2.AttackPattern]:
    """
        extract objects/facts related to ATT&CK techniques

    Args:
        attack (stix2):       Stix attack instance

    """

    notify = []

    # ATT&CK concept    STIX Object type        ACT object
    # =========================================================
    # Technique         attack-pattern          technique
    # Filter out ATT&CK techniques (attack-pattern) from bundle

    for technique in attack.query([Filter("type", "=", "attack-pattern")]):
        if getattr(technique, "revoked", None):
            # Object is revoked, add to notification list but do not add to facts that should be added to the platform
            notify.append(technique)
            continue

        if getattr(technique, "x_mitre_deprecated", None):
            # Object is revoked, add to notification list AND continue to add to facts that should be added to the platform
            notify.append(technique)

        # Mitre ATT&CK Tactics are implemented in STIX as kill chain phases with kill_chain_name "mitre-attack"
        for tactic in technique.kill_chain_phases:
            if tactic.kill_chain_name != "mitre-attack":
                continue

            #handle_fact(
            #    client.fact("accomplishes")
            #    .source("technique", technique.name)
            #    .destination("tactic", tactic.phase_name)
            #)
            accomplishes_property = define_object_property(
                ns,
                'accomplishes', 'accomplishes',
                'Technique', 'Tactic')
            
            technique_individual = define_individual(ns, technique.name, technique.name, attackType+'Technique')
            tactic_individual = define_individual(ns, tactic.phase_name, tactic.phase_name, attackType+'Tactic')
            g.add( (technique_individual, accomplishes_property, tactic_individual) )

            g.add( (ns[attackType+'Technique'], RDFS.label, Literal(attackType.lower()+' technique')) )
            
            g.add( (ns[attackType+'Tactic'], RDFS.label, Literal(attackType.lower()+' tactic')) )
            g.add( (ns[attackType+'Tactic'], RDFS.subClassOf, ns.Tactic) )
            
            g.add( (ns.Tactic, RDFS.label, Literal('tactic')) )

    return notify

def name_individual(ns, name):
    return ns[ent(''.join(x for x in name.title() if not x.isspace()))]

def define_individual(ns, individual, individual_label, individual_type):
    #subject = ns[ent(individual)]
    subject = name_individual(ns, individual)
    g.add( (subject, RDF.type, ns[individual_type]) )
    g.add( (subject, RDFS.label, Literal(individual_label)) )
    return subject
    
def define_object_property(ns, predicate, predicate_label, predicate_domain, predicate_range, object_properties=[] ):
    #subject = ns[predicate]
    subject = ns[''.join(x for x in predicate.title() if not x.isspace())]
    g.add( (subject, RDF.type, OWL.ObjectProperty) )
    g.add( (subject, RDFS.label, Literal(predicate_label)) )
    g.add( (subject, RDFS.domain, ns[predicate_domain]) )
    g.add( (subject, RDFS.range, ns[predicate_range]) )
    for i in object_properties:
        g.add( (subject, RDF.type, i) )
    return subject

def add_groups(client, attack: MemoryStore, ns, attackType) -> List[stix2.AttackPattern]:
    """
        extract objects/facts related to ATT&CK Groups

    Args:
        attack (stix2):       Stix attack instance

    """

    notify = []

    # ATT&CK concept    STIX Object type        ACT object
    # =========================================================
    # Group	        intrusion-set           threatActor
    #
    # Filter out ATT&CK groups (intrusion-set) from bundle

    for group in attack.query([Filter("type", "=", "intrusion-set")]):
        if getattr(group, "revoked", None):
            # Object is revoked, add to notification list but do not add to facts that should be added to the platform
            notify.append(group)
            continue

        if getattr(group, "x_mitre_deprecated", None):
            # Object is revoked, add to notification list AND continue to add to facts that should be added to the platform
            notify.append(group)

        for alias in getattr(group, "aliases", []):
            if group.name != alias:
                #handle_fact(
                #    client.fact("alias")
                #    .bidirectional("threatActor", group.name, "threatActor", alias)
                #)
                # TODO: we use alias elsewhere and should really use a different name in both cases
                
                group_individual = define_individual(ns, group.name, group.name, attackType+'ThreatActor')
                add_description(group_individual, group)

                alias_individual = define_individual(ns, alias, alias, attackType+'ThreatActor')

                g.add( (group_individual, OWL.sameAs, alias_individual) )
                
                g.add( (ns[attackType+'ThreatActor'], RDFS.label, Literal(attackType.lower()+' threat actor')) )
                g.add( (ns[attackType+'ThreatActor'], RDFS.subClassOf, ns.ThreatActor) )
                g.add( (ns.ThreatActor, RDFS.label, Literal('threat actor')) )


        #   ATT&CK concept   STIX Properties
        #   ==========================================================================
        #   Software         relationship where relationship_type == "uses",
        #                    points to a target object with type== "malware" or "tool"

        for tool in attack.related_to(group, relationship_type="uses"):
            if tool.type not in ("malware", "tool"):
                continue

            #chain = act.fact.fact_chain(
            #    client.fact("classifiedAs")
            #    .source("content", "*")
            #    .destination("tool", tool.name.lower()),
            #    client.fact("observedIn", "incident")
            #    .source("content", "*")
            #    .destination("incident", "*"),
            #    client.fact("attributedTo")
            #    .source("incident", "*")
            #    .destination("threatActor", group.name)
            #)
            #for fact in chain:
            #    handle_fact(fact)
            # Any* should probably be bnodes
            classifiedAs_property = define_object_property(
                ns,
                'classifiedAs', 'classified as',
                'Content', 'Tool')
            observedIn_property = define_object_property(
                ns,
                'observedIn', 'observed in',
                'Content', 'Incident')
            incident_property = define_object_property(
                ns,
                'incident', 'incident',
                'Content', 'Incident')
            attributedTo_property = define_object_property(
                ns,
                'attributedTo', 'attributed to',
                'Incident', 'ThreatActor')

            tool_individual = define_individual(ns, tool.name.lower(), tool.name, attackType+'Tool')
            add_description(tool_individual, tool)

            group_individual = define_individual(ns, group.name, group.name, attackType+'ThreatActor')
            add_description(group_individual, group)
            anyContent = BNode()
            anyIncident = BNode()
            g.add( (anyContent, classifiedAs_property, tool_individual) )
            g.add( (anyContent, RDF.type, ns[attackType+'Content']) )
            g.add( (anyContent, RDFS.label, Literal('Any Content')) )
            g.add( (anyContent, observedIn_property, anyIncident) )
            g.add( (anyContent, incident_property, anyIncident) )
            g.add( (anyIncident, RDF.type, ns[attackType+'Incident']) )
            g.add( (anyIncident, RDFS.label, Literal('any incident')) )
            g.add( (anyIncident, attributedTo_property, group_individual) )

            g.add( (ns[attackType+'Content'], RDFS.label, Literal(attackType.lower()+' content')) )
            g.add( (ns[attackType+'Content'], RDFS.subClassOf, ns.Content) )

            g.add( (ns[attackType+'Tool'], RDFS.label, Literal(attackType.lower()+' tool')) )
            g.add( (ns[attackType+'Tool'], RDFS.subClassOf, ns.Tool) )

            g.add( (ns[attackType+'Incident'], RDFS.label, Literal(attackType.lower()+' incident')) )
            g.add( (ns[attackType+'Incident'], RDFS.subClassOf, ns.Incident) )
            
            g.add( (ns[attackType+'ThreatActor'], RDFS.label, Literal(attackType.lower()+' threat actor')) )
            g.add( (ns[attackType+'ThreatActor'], RDFS.subClassOf, ns.ThreatActor) )

            g.add( (ns.ThreatActor, RDFS.label, Literal('threat actor')) )
            
            g.add( (ns.Content, RDFS.label, Literal('content')) )
            
            g.add( (ns.Tool, RDFS.label, Literal('tool')) )

            g.add( (ns.Incident, RDFS.label, Literal('incident')) )

            
        #   ATT&CK concept   STIX Properties
        #   ==========================================================================
        #   Technqiues       relationship where relationship_type == "uses", points to
        #                    a target object with type == "attack-pattern"

        for technique in attack.related_to(group, relationship_type="uses"):
            if technique.type != "attack-pattern":
                continue

            #chain = act.fact.fact_chain(
            #    client.fact("observedIn", "incident")
            #    .source("technique", technique.name)
            #    .destination("incident", "*"),
            #    client.fact("attributedTo")
            #    .source("incident", "*")
            #    .destination("threatActor", group.name)
            #)
            #handle_fact(chain)
            #for fact in chain:
            #    handle_fact(fact)
            anyIncident = BNode()
            observedIn_property = define_object_property(
                ns,
                'observedIn', 'observed in',
                'Content', 'Incident')
            incident_property = define_object_property(
                ns,
                'incident', 'incident',
                'Content', 'Incident')
            attributedTo_property = define_object_property(
                ns,
                'attributedTo', 'attributed to',
                'Incident', 'ThreatActor')

            group_individual = define_individual(ns, group.name, group.name, attackType+'ThreatActor')
            technique_individual = define_individual(ns, technique.name, technique.name, attackType+'Technique')
            g.add( (technique_individual, observedIn_property, anyIncident) )
            g.add( (technique_individual, incident_property, anyIncident) )
            add_description(technique_individual, technique)

            g.add( (anyIncident, attributedTo_property, group_individual) )
            g.add( (anyIncident, RDF.type, ns[attackType+'Incident']) )
            g.add( (anyIncident, RDFS.label, Literal('any incident')) )

            g.add( (ns[attackType+'Incident'], RDFS.label, Literal(attackType.lower()+' incident')) )
            g.add( (ns[attackType+'Incident'], RDFS.subClassOf, ns.Incident) )
            
            g.add( (ns[attackType+'Technique'], RDFS.label, Literal(attackType.lower()+' technique')) )
            g.add( (ns[attackType+'Technique'], RDFS.subClassOf, ns.Technique) )
            
            g.add( (ns.Technique, RDFS.label, Literal('technique')) )

            g.add( (ns.Incident, RDFS.label, Literal('incident')) )

            g.add( (ns[attackType+'Content'], RDFS.subClassOf, ns.Content) )
            g.add( (ns[attackType+'Content'], RDFS.label, Literal(attackType.lower()+' content')) )
            
            g.add( (ns[attackType+'ThreatActor'], RDFS.subClassOf, ns.ThreatActor) )
            
            g.add( (ns.ThreatActor, RDFS.label, Literal('threat actor')) )

    return notify


def add_software(client, attack: MemoryStore, ns, attackType) -> List[stix2.AttackPattern]:
    """
        extract objects/facts related to ATT&CK Software
        Insert to ACT if client.baseurl is set, if not, print to stdout

    Args:
        attack (stix2):       Stix attack instance

    """

    notify = []

    for software in attack.query([Filter("type", "in", ["tool", "malware"])]):
        if getattr(software, "revoked", None):
            # Object is revoked, add to notification list but do not add to facts that should be added to the platform
            notify.append(software)
            continue

        if getattr(software, "x_mitre_deprecated", None):
            # Object is revoked, add to notification list AND continue to add to facts that should be added to the platform
            notify.append(software)

        for alias in getattr(software, "x_mitre_aliases", []):
            if software.name.lower() != alias.lower():
                #handle_fact(
                #    client.fact("alias")
                #    .bidirectional("tool", software.name.lower(), "tool", alias.lower())
                #)
                software_individual = define_individual(ns, software.name, software.name, attackType+'Tool')
                add_description(software_individual, software)

                alias_individual = define_individual(ns, alias, alias, attackType+'Tool')

                g.add( (software_individual, OWL.sameAs, alias_individual) )
                
                g.add( (ns[attackType+'Tool'], RDFS.label, Literal(attackType.lower()+' tool')) )
                g.add( (ns[attackType+'Tool'], RDFS.subClassOf, ns.Tool) )
                                
                g.add( (ns.Tool, RDFS.label, Literal('tool')) )

        #   ATT&CK concept   STIX Properties
        #   ==========================================================================
        #   Technqiues       relationship where relationship_type == "uses", points to
        #                    a target object with type == "attack-pattern"

        for technique in attack.related_to(software, relationship_type="uses"):
            if technique.type != "attack-pattern":
                continue

            #handle_fact(
            #    client.fact("implements")
            #    .source("tool", software.name.lower())
            #    .destination("technique", technique.name)
            #)
            implements_property = define_object_property(
                ns,
                'implements', 'implements',
                'Tool', 'Technique')

            software_individual = define_individual(ns, software.name.lower(), software.name, attackType+'Tool')
            technique_individual = define_individual(ns, technique.name, technique.name, attackType+'Technique')
            add_description(technique_individual, technique)
            
            g.add( (software_individual, implements_property, technique_individual) )
            add_description(software_individual, software)
            
            g.add( (ns[attackType+'Tool'], RDFS.label, Literal(attackType.lower()+' tool')) )
            g.add( (ns[attackType+'Tool'], RDFS.subClassOf, ns.Tool) )

            g.add( (ns[attackType+'Technique'], RDFS.label, Literal(attackType.lower()+' technique')) )
            g.add( (ns[attackType+'Technique'], RDFS.subClassOf, ns.Technique) )

            g.add( (ns.Tool, RDFS.label, Literal('tool')) )

            g.add( (ns.Technique, RDFS.label, Literal('technique')) )

    return notify


def notify_cache(filename: str) -> Dict:
    """
    Read notify cache from filename
    Args:
        filename(str):      Cache filename

    """

    cache = {}

    try:
        with open(filename) as f:
            for line in f:
                if line:
                    cache[line.strip()] = True
    except FileNotFoundError:
        warning("Cache file {} not found, will be created if necessary".format(filename))

    return cache


def add_to_cache(filename: str, entry: str) -> None:
    """
    Add entry to cache

    Args:
        filename(str):      Cache filename
        entry(str):         Cache entry
    """

    with open(filename, "a") as f:
        f.write(entry.strip())
        f.write("\n")


def send_notification(
        notify: List[stix2.AttackPattern],
        smtphost: str,
        sender: str,
        recipient: str,
        url: str) -> List[str]:
    """
    Process revoked objects

    Args:
        notify(attack[]):   Array of revoked/deprecated Stix objects
        notifycache(str):   Filename of notify cache
        smtphost(str):      SMTP host used to notify of revoked/deprecated objects
        sender(str):        sender address used to notify of revoked/deprecated objects
        recipient(str):     recipient address used to notify of revoked/deprecated objects

    smtphost, sender AND recipient must be set to notify of revoked/deprecated objects

    Return list of IDs that was successfully notified

    """

    notified = []

    if not (smtphost and recipient and sender):
        error("--smtphost, --recipient and --sender must be set to send revoked/deprecated objects on email")
        return []

    body = url + "\n\n"
    warning("[{}]".format(url))

    for obj in notify:
        if getattr(obj, "revoked", None):
            text = "revoked: {}:{}".format(obj.type, obj.name)

        elif getattr(obj, "x_mitre_deprecated", None):
            text = "deprecated: {}:{}".format(obj.type, obj.name)

        else:
            raise NotificationError("object tis not deprecated or revoked: {}:{}".format(obj.type, obj.name))

        notified.append(obj.id)

        body += text + "\n"
        warning(text)

    #worker.sendmail(smtphost, sender, recipient, "Revoked/deprecated objects from MITRE/ATT&CK", body)
    info("Email sent to {}".format(recipient))

    return notified


def main() -> None:
    """ Main function """
    args = parseargs()
    #client = act.Act(
    #    args.act_baseurl,
    #    args.user_id,
    #    args.loglevel,
    #    args.logfile,
    #    "mitre-attack")
    MAJOR_VERSION = "1.0"
    with open("MINOR_VERSION", 'r') as f:
        MINOR_VERSION = float(f.read())
    print("Former MINOR_VERSION: {}".format(MINOR_VERSION))    
    MINOR_VERSION += 0.001
    MINOR_VERSION = "{0:.3f}".format(MINOR_VERSION)
    with open("MINOR_VERSION", 'w') as f:
        f.write(MINOR_VERSION)
    print("Versions major: {}, minor: {}".format(MAJOR_VERSION, MINOR_VERSION))
    namespace_manager = NamespaceManager(Graph())
    ns = Namespace("http://ontologies.ti-semantics.com/attack#")
    namespace_manager.bind('atk', ns, override=False)
    namespace_manager.bind('owl', OWL, override=False)
    namespace_manager.bind('terms', DCTERMS, override=False)
    namespace_manager.bind('xsd', XSD, override=False)
    
    g.add( (URIRef(ns), RDF.type, OWL.Ontology) )
    g.add( (URIRef(ns), OWL.versionIRI, URIRef("http://ontologies.ti-semantics.com/attack-{}-{}#".format(MAJOR_VERSION, MINOR_VERSION))) )
    g.add( (URIRef(ns), DCTERMS.license, Literal("https://creativecommons.org/licenses/by-sa/4.0/", datatype=XSD.anyURI)) )
    g.add( (URIRef(ns), RDFS.seeAlso, Literal("https://attack.mitre.org", datatype=XSD.anyURI)) )
    g.add( (URIRef(ns), RDFS.comment, Literal('This is a synthetic ontology generated from the ATT&CK framework using code derived from the ACT Platform created by Mnemonic.no.')) )
    
    client = None
    for mitre_type in args.types:
        url = MITRE_URLS.get(mitre_type.lower())
        #ns = Namespace("http://attack.mitre.org/{}#".format(mitre_type))
        
        if not url:
            error("Unknown mitre type: {}. Valid types: {}".format(mitre_type, ",".join(MITRE_URLS.keys())))
            sys.exit(2)

        cache = notify_cache(args.notifycache)

        # Get attack dataset as Stix Memory Store
        attack = get_attack(url, args.proxy_string, args.timeout)

        techniques_notify = add_techniques(client, attack, ns, mitre_type.capitalize())
        groups_notify = add_groups(client, attack, ns, mitre_type.capitalize())
        software_notify = add_software(client, attack, ns, mitre_type.capitalize())

        # filter revoked objects from those allready notified
        notify = [
            notify
            for notify in techniques_notify + groups_notify + software_notify
            if notify.id not in cache
        ]

        #if notify:
        #    notified = send_notification(notify, args.smtphost, args.sender, args.recipient, url)

        #    for object_id in notified:
        #        # Add object to cache, so we will not be notified on the same object on the next run
        #        add_to_cache(args.notifycache, object_id)
    g.namespace_manager = namespace_manager
    g.serialize(destination="../ontologies/attack.rdf", format='xml')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        error("Unhandled exception: {}".format(traceback.format_exc()))
        raise
