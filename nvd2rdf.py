from jsonpath_ng import jsonpath, parse
import json
from urllib.parse import urlparse
from rdflib import Graph, Literal, RDF, URIRef, Namespace, BNode
from rdflib.namespace import RDF, RDFS, XSD, DC, DCTERMS, FOAF
import dateutil.parser
import hashlib
from requests.utils import requote_uri
from cpe import CPE

CORE = Namespace("http://ontologies.ti-semantics.com/core#")
CTI = Namespace("http://ontologies.ti-semantics.com/cti#")
PLATFORM = Namespace("http://ontologies.ti-semantics.com/platform#")
SCORE = Namespace("http://ontologies.ti-semantics.com/score#")
VULN = Namespace("http://ontologies.ti-semantics.com/vulnerability#")
NVD = Namespace("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020/")
REFS = Namespace("https://csrc.nist.gov/publications/references/")
CPEMATCH = Namespace("https://csrc.nist.gov/schema/cpematch/feed/1.0/")

def all(q, o, fn=None):
  a = [ m.value for m in parse(q).find(o) ]
  if fn:
    for i in a:
      fn(i)
  else:
    return a

def allDateTime(p, q, o):
  return [(p, Literal(dt, datatype=XSD.dateTime)) for dt in all(q, o)]

def allFloat(p, q, o):
  return [(p, Literal(dt, datatype=XSD.decimal)) for dt in all(q, o)]

def allString(p, q, o):
  return [(p, Literal(s)) for s in all(q, o)]

def allLangString(p, q, o):
  return [ (p, Literal(all("$.value", s)[0], lang=all("$.lang", s)[0])) for s in all(q, o) ]

def allURL(p, q, o):
  return [(p, Literal(u, datatype=XSD.anyURI)) for u in all(q, o)]

def findin(jp, doc, value):
  return value in [m.value for m in parse(jp).find(doc)]

def cveURI(id):
  return URIRef('urn:X-CVE:' + id)

def cweURI(id):
  return URIRef('urn:X-CWE:' + id)

def cpeURI(id):
  return URIRef(requote_uri('urn:' + id.replace("cpe", "X-CPE").replace("\\'", "'")))

def cvssv3IRI(q, o):
  for i in all(q, o):
    return URIRef('urn:X-'+i)
  return BNode()

def cvssv2IRI(q, o):
  for i in all(q, o):
    return URIRef('urn:X-CVSS:2.0/'+i)
  return BNode()

class CPEConfiguration():
  def __init__(self, filename, baseURI, g=Graph()):
    with open(filename, 'r') as f:
      self.collection = json.load(f)
      self.g = g
      self.baseURI = baseURI

  def __init__(self, baseURI, g=Graph()):
    self.g = g
    self.baseURI = baseURI

  def convert(self):
    for config in all("$.CVE_Items.[*].configurations", self.collection):
      if '4.0' in all("$.CVE_data_version", config):
        tupels = list()
        for node in all("$.nodes.[*]", config):
          self.triples(self.configURI(node), PLATFORM.PlatformConfiguration, [(PLATFORM.hasNode, self.config_node(node))])
      else:
        print("Unknown configuration version number: ", all("$.CVE_data_version", config))
    return self.g

  def convert(self, configurations):
    return_configurations = list()
    for config in configurations:
      if '4.0' in all("$.CVE_data_version", config):
        tupels = list()
        for node in all("$.nodes.[*]", config):
          subject = self.configURI(node)
          self.triples(subject, PLATFORM.PlatformConfiguration, [(PLATFORM.hasNode, self.config_node(node))])
          return_configurations.append(subject)
      else:
        print("Unknown configuration version number: ", all("$.CVE_data_version", config))
    return return_configurations

  def config_node(self, node):
    if 'OR' in all("$.operator", node):
      nodeType = PLATFORM.ORNode
    elif 'AND' in all("$.operator", node):
      nodeType = PLATFORM.ANDNode
    else:
      raise BaseException("[config_node] Unknown operator: ", all("$.operator", node))
    subject = BNode()
    self.triples(subject, nodeType, self.children(node) + self.cpe_match(node))
    return subject

  def children(self, node):
    tupels = list()
    for i in all("$.children.[*]", node):
      tupels += self.config_child(i)
    return tupels

  def cpe_match(self, node):
    tupels = list()
    for i in all("$.cpe_match.[*]", node):
      tupels.append((PLATFORM.match, self.config_cpe_match(i)))
    return tupels

  def config_cpe_match(self, cm):
    if all("$.vulnerable", cm)[0]:
      v = PLATFORM.VulnerableConfiguration
    else:
      v = PLATFORM.NotVulnerableConfiguration
    subject = BNode()
    cveStr = all("$.cpe23Uri", cm)[0]
    self.triples(subject, v, [(PLATFORM.hasPlatform, cpeURI(cveStr))] + \
      self.versionStartExcluding(cm) + self.versionStartIncluding(cm) + self.versionEndExcluding(cm) + self.versionEndIncluding(cm))
    #print(cveStr)

    c = CPE(cveStr)

    if c.is_hardware():
      self.g.add((cpeURI(cveStr), RDF.type, PLATFORM.HardwarePlatform))
    elif c.is_application():
      self.g.add((cpeURI(cveStr), RDF.type, PLATFORM.ApplicationPlatform))
    elif c.is_operating_system():
      self.g.add((cpeURI(cveStr), RDF.type, PLATFORM.OperatingSystemPlatform))

    vendor = ""
    for i in c.get_vendor():
      self.g.add((cpeURI(cveStr), PLATFORM.vendor, self.plEnt(i, "Vendor_", cls=PLATFORM.Vendor)))
      vendor = i
    for i in c.get_product():
      self.g.add((cpeURI(cveStr), PLATFORM.product, self.plEnt(i, "Product_"+vendor+"_", cls=PLATFORM.Product)))
    for i in c.get_edition():
      self.g.add((cpeURI(cveStr), PLATFORM.edition, self.plEnt(i, "Edition_", cls=PLATFORM.Edition)))
    for i in c.get_language():
      self.g.add((cpeURI(cveStr), PLATFORM.language, self.plEnt(i, "Language_", cls=PLATFORM.Language)))
    for i in c.get_other():
      self.g.add((cpeURI(cveStr), PLATFORM.other, self.plEnt(i, "Other_", cls=PLATFORM.Other)))
    for i in c.get_software_edition():
      self.g.add((cpeURI(cveStr), PLATFORM.softwareEdition, self.plEnt(i, "SoftwareEdition_", cls=PLATFORM.SoftwareEdition)))
    for i in c.get_target_hardware():
      self.g.add((cpeURI(cveStr), PLATFORM.targetHardware, self.plEnt(i, "Hardware_", cls=CORE.Hardware)))
    for i in c.get_target_software():
      self.g.add((cpeURI(cveStr), PLATFORM.targetSoftware, self.plEnt(i, "Software_", cls=CORE.Software)))
    for i in c.get_update():
      if not i == "-":
        self.g.add((cpeURI(cveStr), PLATFORM.update, Literal(i)))
    for i in c.get_version():
      if not i == "-":
        self.g.add((cpeURI(cveStr), PLATFORM.version, Literal(i)))

    return subject

  def plEnt(self, name, prefix="", postfix="", cls=None):
    if name == "*":
      m = "Any"
    elif name == "-":
      m = "NotAvailable"
    else:
      m = name
    s = PLATFORM[requote_uri(prefix+m+postfix)]
    if cls:
      self.g.add((s, RDF.type, cls))
    if not name in ["-", "*"]:
      self.g.add((s, RDFS.label, Literal(name)))
    return s

  def config_child(self, child):
    if 'OR' in all("$.operator", child):
      tupels = list()
      for cm in all("$.cpe_match.[*]", child):
        node = BNode()
        self.triples(node, PLATFORM.ORNode, self.cpe_match(child))
        tupels += [(PLATFORM.hasNode, node) ]
      return tupels
    elif 'AND' in all("$.operator", child):
      return [(PLATFORM.andChild, self.config_child(c)) for c in all("$.children.[*]", child)]
    else:
      raise BaseException("[config_child] Unknown operator: ", all("$.operator", child))

  def triples(self, subject, rdftype, items):
    self.g.add((subject, RDF.type, rdftype))
    for (p, o) in items:
      if p and o:
        self.g.add((subject, p, o))
    return subject

  def configURI(self, config):
    hash_object = hashlib.sha1(json.dumps(config, sort_keys=True).encode('utf-8'))
    hex_dig = hash_object.hexdigest()
    return URIRef(self.baseURI + "cpematch_"+hex_dig)

  def versionStartExcluding(self, cm):
    return [(XSD.minExclusive, Literal(i)) for i in all("$.versionStartExcluding", cm)]

  def versionStartIncluding(self, cm):
    return [(XSD.minInclusive, Literal(i)) for i in all("$.versionStartIncluding", cm)]

  def versionEndExcluding(self, cm):
    return [(XSD.maxExclusive, Literal(i)) for i in all("$.versionEndExcluding", cm)]

  def versionEndIncluding(self, cm):
    return [(XSD.maxInclusive, Literal(i)) for i in all("$.versionEndIncluding", cm)]

class NVD2RDF:
  def __init__(self, filename, filedate):
    with open(filename, 'r') as f:
      self.f = f
      self.collection = json.load(f)
      # Plausibility checking
      if (findin('$.CVE_data_type', self.collection, "CVE") or findin('$.data_type', self.collection, "CVE")) and \
        (findin('$.CVE_data_format', self.collection, "MITRE") or findin('$.data_format', self.collection, "MITRE")) and \
        (findin('$.CVE_data_version', self.collection, "4.0") or findin('$.data_version', self.collection, "4.0")):
          for match in parse('$.CVE_data_timestamp').find(self.collection):
            self.ts = dateutil.parser.parse(match.value)
          self.g = Graph()
          self.filedate = filedate
      else:
          print("unknown data version")
          print([m.value for m in parse('$.CVE_data_type').find(self.collection)], [m.value for m in parse('$.CVE_data_format').find(self.collection)],[m.value for m in parse('$.CVE_data_version').find(self.collection)])
          raise(BaseException("unknown data version"))

#  def convert(self):
#    self.catalog()
#    return self.g
        
  def catalog(self):
    s = NVD[self.filedate]
    self.rdfobject(s, VULN.NVD20Catalog, [ (CORE.vulnerability, self.cve(match.value)) for match in parse('$.CVE_Items[*]').find(self.collection)])
    return self.g

  def single(self):
    self.cve(self.collection)
    return self.g

  def cve(self, o):
    if (findin('$.cve.data_type', o, "CVE") or findin('$.data_type', o, "CVE")) and \
      (findin('$.cve.data_format', o, "MITRE") or findin('$.data_format', o, "MITRE")) and \
      (findin('$.cve.data_version', o, "4.0") or findin('$.data_version', o, "4.0")):
        id = (all('$.CVE_data_meta.ID', o) + all('$.cve.CVE_data_meta.ID', o))[0]
        s = cveURI(id)
        self.rdfobject(s, CORE.Vulnerability, \
          [ (VULN.id, Literal(id)) ] + \
          allDateTime(DCTERMS.issued, "$.publishedDate", o)  + \
          allDateTime(DCTERMS.issued, "$.CVE_data_meta.DATE_PUBLIC", o)  + \
          [ (DCTERMS.publisher, Literal(i)) for i in all("$.CVE_data_meta.ASSIGNER", o) ]  + \
          [ (DCTERMS.title, Literal(i)) for i in all("$.CVE_data_meta.TITLE", o) ]  + \
          [ (DCTERMS.accessRights, Literal(i)) for i in all("$.CVE_data_meta.STATE", o) ] + \
          allDateTime(DCTERMS.modified, "$.lastModifiedDate", o)  + \
          allLangString(RDFS.comment, "$.cve.description.description_data.[*]", o) + \
          allLangString(RDFS.comment, "$.description.description_data.[*]", o) + \
          self.allReferences(DCTERMS.references, "$.cve.references.reference_data[*]", o) + \
          self.allReferences(DCTERMS.references, "$.references.reference_data[*]", o) + \
          self.allConfigurations( VULN.vulnerableConfiguration, "$.configurations", o) + \
          self.allImpacts(VULN.score, "$.impact", o) + \
          self.allCWEs(VULN.weakness, "$.cve.problemtype.[*].problemtype_data.[*].description.[*].value", o) )
        return s

  def allReferences(self, p, q, o):
    return [ (p, self.reference(r) ) for r in all(q, o) ]

  def allConfigurations(self, p, q, o):
    platform = CPEConfiguration(CPEMATCH, self.g)
    return [(p, c) for c in platform.convert(all(q, o))]
    
  def allImpacts(self, p, q, o):
    metrics = list()
    for impact in all(q, o):
      if len(impact) == 0:
        print("Empty impact in: ", o)
      else:
        cvssv3MetricGroup = self.mapCVSSv3(all("$.baseMetricV3.cvssV3", impact))
        if len(cvssv3MetricGroup) > 0:
          metrics.append((CORE.score, self.rdfobject(cvssv3IRI("$.baseMetricV3.cvssV3.vectorString", impact), SCORE.CVSSv3BaseMetricGroup, cvssv3MetricGroup)))
        cvssv2MetricGroup = self.mapCVSSv2(all("$.baseMetricV2.cvssV2", impact))
        if len(cvssv2MetricGroup) > 0:
          metrics.append((CORE.score, self.rdfobject(cvssv2IRI("$.baseMetricV2.cvssV2.vectorString", impact), SCORE.CVSSv2BaseMetricGroup, cvssv2MetricGroup)))
        allMetrics = self.mapGenCVSSv2(all("$.baseMetricV2.cvssV2", impact))
        allMetrics += self.mapGenCVSSv3(all("$.baseMetricV3.cvssV3", impact))
        if len(allMetrics) > 0:
          metrics.append((CORE.score, self.rdfobject(BNode(), SCORE.CVSSMetric, allMetrics)))
    return metrics

  def mapCVSSv3(self, impact):
    tuples = self.mapGenCVSSv3(impact)
    for i in impact:
      if "3.1" in all("$.version", i):
        tuples += allFloat(SCORE.cvss_v3_baseScore, "$.baseScore", i)
        tuples += allString(SCORE.cvss_v3_severity, "$.baseSeverity", i)
        tuples += allString(SCORE.cvss_v3_vector, "$.vectorString", i)
      else:
        print("Unknown CVSS V3 version: ", all("$.version", i))
    return tuples

  def mapGenCVSSv3(self, impact):
    tuples = list()
    for i in impact:
      if "3.1" in all("$.version", i):
        tuples += self.attackVectorV3(all("$.attackVector", i))
        tuples += self.attackComplexityV3(all("$.attackComplexity", i))
        tuples += self.privilegesRequiredV3(all("$.privilegesRequired", i))
        tuples += self.userInteractionV3(all("$.userInteraction", i))
        tuples += self.scopeV3(all("$.scope", i))
        tuples += self.confidentialityImpactV3(all("$.confidentialityImpact", i))
        tuples += self.integrityImpactV3(all("$.integrityImpact", i))
        tuples += self.availabilityImpactV3(all("$.availabilityImpact", i))
      else:
        print("Unknown CVSS V3 version: ", all("$.version", i))
    return tuples

  def mapCVSSv2(self, impact):
    tuples = self.mapGenCVSSv2(impact)
    for i in impact:
      if "2.0" in all("$.version", i):
        tuples += allFloat(SCORE.cvss_v2_baseScore, "$.baseScore", i)
        tuples += allString(SCORE.cvss_v2_vector, "$.vectorString", i)
      else:
        print("Unknown CVSS V2 version: ", all("$.version", i))
    return tuples

  def mapGenCVSSv2(self, impact):
    tuples = list()
    for i in impact:
      if "2.0" in all("$.version", i):
        tuples += self.accessComplexityV2(all("$.accessComplexity", i))
        tuples += self.accessVectorV2(all("$.accessVector", i))
        tuples += self.authenticationV2(all("$.authentication", i))
        tuples += self.availabilityImpactV2(all("$.availabilityImpact", i))
        tuples += self.confidentialityImpactV2(all("$.confidentialityImpact", i))
        tuples += self.integrityImpactV2(all("$.integrityImpact", i))
      else:
        print("Unknown CVSS V2 version: ", all("$.version", i))
    return tuples

  def mapTo(self, av, p, mapping, error):
    for i in av:
      # print(i)
      if i in mapping:
        return [(p, mapping[i])]
      else:
        raise BaseException(error)
    return []

  def attackVectorV3(self, av):
    return self.mapTo(av, SCORE.hasAttackVector, { 
      'ADJACENT_NETWORK': SCORE.CVSSv3NetworkAttackVector, 
      'LOCAL' :  SCORE.CVSSv3LocalAttackVector,
      'NETWORK': SCORE.CVSSv3NetworkAttackVector,
      'PHYSICAL': SCORE.CVSSv3PhysicalAttackVector
    }, "unknown attackVector")
    
  def attackComplexityV3(self, ac):
    return self.mapTo(ac, SCORE.hasAttackComplexity, {
      'LOW': SCORE.CVSSv3LowAttackComplexity,
      'MEDIUM': SCORE.CVSSv3MediumAttackComplexity,
      'HIGH': SCORE.CVSSv3MediumAttackComplexity
    }, "unknown attackComplexity")

  def confidentialityImpactV3(self, ci):
    return self.mapTo(ci, SCORE.hasConfidentialityImpact, {
      'LOW': SCORE.CVSSv3LowConfidentialityImpact,
      'HIGH': SCORE.CVSSv3HighConfidentialityImpact
    }, "unknown confidentialityImpact")

  def confidentialityImpactV2(self, ci):
    return self.mapTo(ci, SCORE.hasConfidentialityImpact, {
      'PARTIAL': SCORE.CVSSv2PartialConfidentialityImpact,
      'COMPLETE': SCORE.CVSSv2CompleteConfidentialityImpact,
      'NONE': SCORE.CVSSv2NoConfidentialityImpact
    }, "unknown confidentialityImpact")

  def confidentialityImpactV3(self, ci): 
    return self.mapTo(ci, SCORE.hasConfidentialityImpact, {
      'HIGH': SCORE.CVSSv3HighConfidentialityImpact,
      'LOW': SCORE.CVSSv3LowConfidentialityImpact,
      'NONE': SCORE.CVSSv3NoConfidentialityImpact
    }, "unknown confidentialityImpact")

  def privilegesRequiredV3(self, pr):
    return self.mapTo(pr, SCORE.hasPrivilegesRequired, {
      'HIGH': SCORE.CVSSv3HighPrivilegesRequired,
      'LOW': SCORE.CVSSv3LowPrivilegesRequired,
      'NONE': SCORE.CVSSv3NoPrivilegesRequired
    }, "unknown privilegesRequired")

  def userInteractionV3(self, ia):
    return self.mapTo(ia, SCORE.hasUserInteraction, {
      'REQUIRED': SCORE.CVSSv3RequiredUserInteraction,
      'NONE': SCORE.CVSSv3NoUserInteraction
    }, "unknown userInteraction")

  def scopeV3(self, sc): 
    return self.mapTo(sc, SCORE.hasScope, {
      'CHANGED': SCORE.CVSSv3ChangedScope,
      'UNCHANGED': SCORE.CVSSv3UnchangedScope
    }, "unknown scope")

  def integrityImpactV3(self, ii):
    return self.mapTo(ii, SCORE.hasIntegrityImpact, {
      'NONE': SCORE.CVSSv3NoIntegrityImpact,
      'LOW': SCORE.CVSSv3LowIntegrityImpact,
      'HIGH': SCORE.CVSSv3HighIntegrityImpact
    }, "unknown integrityImpact")

  def integrityImpactV2(self, ii): 
    return self.mapTo(ii, SCORE.hasIntegrityImpact, {
      'PARTIAL': SCORE.CVSSv2PartialIntegrityImpact,
      'COMPLETE': SCORE.CVSSv2CompleteIntegrityImpact,
      'NONE': SCORE.CVSSv2NoIntegrityImpact
    }, "unknown integrityImpact")

  def availabilityImpactV3(self, ai):
    return self.mapTo(ai, SCORE.hasAvailabilityImpact, {
     'NONE': SCORE.CVSSv3NoAvailabilityImpact,
     'LOW': SCORE.CVSSv3LowAvailabilityImpact,
     'HIGH': SCORE.CVSSv3HighAvailabilityImpact
    }, "unknown availabilityImpact")

  def availabilityImpactV2(self, ai): 
    return self.mapTo(ai, SCORE.hasAvailabilityImpact, {
     'PARTIAL': SCORE.CVSSv2PartialAvailabilityImpact,
     'COMPLETE': SCORE.CVSSv2CompleteAvailabilityImpact,
     'NONE': SCORE.CVSSv2NoAvailabilityImpact
    }, "unknown availabilityImpact")

  def accessVectorV2(self, av): 
    return self.mapTo(av, SCORE.hasAccessVector, { 
      'ADJACENT_NETWORK': SCORE.CVSSv2AdjacentAccessVector,
      'LOCAL' :  SCORE.CVSSv2LocalAccessVector,
      'NETWORK': SCORE.CVSSv2NetworkAccessVector
    }, "unknown attackVector")

  def accessComplexityV2(self, ac): 
    return self.mapTo(ac, SCORE.hasAccessComplexity, {
      'LOW': SCORE.CVSSv2LowAccessComplexity,
      'MEDIUM': SCORE.CVSSv2MediumAccessComplexity,
      'HIGH': SCORE.CVSSv2MediumAccessComplexity
    }, "unknown accessComplexity")

  def authenticationV2(self, a): 
    return self.mapTo(a, SCORE.hasAuthentication, {
     'NONE':  SCORE.CVSSv2NoAuthentication,
     'SINGLE': SCORE.CVSSv2SingleAuthentication,
     'MULTIPLE': SCORE.CVSSv2MultipleAuthentications
    }, "unknown authentication")

  def allCWEs(self, p, q, o):
    return [(p, cweURI(s)) for s in all(q, o) if s.startswith('CWE-')]

  def referenceSubject(self, o):
    if len(all("$.url", o)) > 0:
      return self.refURI(all("$.url", o)[0])
    elif len(all("$.name", o)) > 0:
      return self.refURI(all("$.name", o)[0])
    else:
      return self.refURI(o)

  def reference(self, o):
    s = self.referenceSubject(o)
    tags = [ (RDF.type, VULN["".join([t.capitalize() for t in tag.split()])+"Reference"]) for tag in all("$.tags[*]", o) ]
    self.rdfobject(s, VULN.Reference, \
      allString(VULN.referenceSource, '$.refsource', o) + \
      allURL(VULN.referenceURL, "$.url", o) + \
      allString(VULN.referenceTitle, '$.name', o) + \
      tags )
    return s

  def rdfobject(self, s, rdftype, items):
    self.g.add((s, RDF.type, rdftype))
    for (p, o) in items:
      if p and o:
        self.g.add((s, p, o))

  def refURI(self, s):
    hash_object = hashlib.sha1(json.dumps(s, sort_keys=True).encode('utf-8'))
    hex_dig = hash_object.hexdigest()
    return REFS["ref_"+hex_dig]

