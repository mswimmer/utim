from jsonpath_ng import jsonpath, parse
import json
from urllib.parse import urlparse
from rdflib import Graph, Literal, RDF, URIRef, Namespace, BNode
from rdflib.namespace import RDF, RDFS, XSD, DC, DCTERMS, FOAF
import dateutil.parser
import hashlib
from requests.utils import requote_uri


CORE = Namespace("http://ontologies.ti-semantics.com/core#")
CTI = Namespace("http://ontologies.ti-semantics.com/cti#")
PLATFORM = Namespace("http://ontologies.ti-semantics.com/platform#")
SCORE = Namespace("http://ontologies.ti-semantics.com/score#")
VULN = Namespace("http://ontologies.ti-semantics.com/vulnerability#")

nvdfile = "collections/nvdcve-1.1-recent.json"
#nvdfile = "collections/nvdcve-1.1-CVE-2020-10732.json"
#nvdfile = "collections/nvdcve-1.1-CVE-2019-9460.json"
#nvdfile = "collections/nvdcve-1.1-CVE-2020-13150.json"

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
  """ Expects and object like this:
    {
      "lang": "en",
      "value": "In mediaserver, there is a possible out of bounds ..."
    }
  """
  return [ (p, Literal(all("$.value", s)[0], lang=all("$.lang", s)[0])) for s in all(q, o) ]

def allURL(p, q, o):
  return [(p, Literal(u, datatype=XSD.anyURI)) for u in all(q, o)]

def findin(jp, doc, value):
  return value in [m.value for m in parse(jp).find(doc)]

def cveURI(id):
  """
  <xsl:function name="tifn:cveURI">
    <xsl:param name="entryId"/>
    <xsl:value-of select="fn:concat('urn:X-cve:', $entryId)" />
  </xsl:function>
  """
  return URIRef('urn:X-cve:' + id)

def cweURI(id):
  return URIRef('urn:X-cwe:' + id)

def cvssv3IRI(q, o):
  for i in all(q, o):
    return URIRef('urn:'+i)
  return BNode()

def cvssv2IRI(q, o):
  for i in all(q, o):
    return URIRef('urn:CVSS:2.0/'+i)
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
      #print()
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
      #print()
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
    #print("Found children tupels: ", tupels)
    return tupels

  def cpe_match(self, node):
    tupels = list()
    for i in all("$.cpe_match.[*]", node):
      tupels.append((PLATFORM.match, self.config_cpe_match(i)))
    return tupels

  def config_cpe_match(self, cm):
    #sprint("cpe_match: ", cm)
    #print("vulnerable: ", all("$.vulnerable", cm))
    if all("$.vulnerable", cm)[0]:
      v = PLATFORM.VulnerableConfiguration
    else:
      v = PLATFORM.NotVulnerableConfiguration
    subject = BNode()
    self.triples(subject, v, [(PLATFORM.hasPlatform, self.cpeURI(all("$.cpe23Uri", cm)[0]))] + \
      self.versionStartExcluding(cm) + self.versionStartIncluding(cm) + self.versionEndExcluding(cm) + self.versionEndIncluding(cm))
    return subject

  def config_child(self, child):
    #print("Child: ", child)
    if 'OR' in all("$.operator", child):
      #return [(PLATFORM.orChild, self.config_cpe_match(cm)) for cm in all("$.cpe_match.[*]", child)]
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
    #print(items)
    for (p, o) in items:
      if p and o:
        self.g.add((subject, p, o))
    return subject

  def configURI(self, config):
    hash_object = hashlib.sha1(json.dumps(config, sort_keys=True).encode('utf-8'))
    hex_dig = hash_object.hexdigest()
    #print(hex_dig)
    return URIRef(self.baseURI + "platform_configuration_"+hex_dig)

  def cpeURI(self, id):
    #id.replace("\\'", "'")
    return URIRef(requote_uri('urn:X-cpe:' + id.replace("\\'", "'")))

  def versionStartExcluding(self, cm):
    return [(XSD.minExclusive, Literal(i)) for i in all("$.versionStartExcluding", cm)]

  def versionStartIncluding(self, cm):
    return [(XSD.minInclusive, Literal(i)) for i in all("$.versionStartIncluding", cm)]

  def versionEndExcluding(self, cm):
    return [(XSD.maxExclusive, Literal(i)) for i in all("$.versionEndExcluding", cm)]

  def versionEndIncluding(self, cm):
    return [(XSD.maxInclusive, Literal(i)) for i in all("$.versionEndIncluding", cm)]

class NVD2RDF:
  def __init__(self, filename, baseURI):
    with open(nvdfile, 'r') as f:
      self.f = f
      self.collection = json.load(f)
      # Plausibility checking
      if findin('$.CVE_data_type', self.collection, "CVE") and \
        findin('$.CVE_data_format', self.collection, "MITRE") and \
        findin('$.CVE_data_version', self.collection, "4.0"):
          #print("header checks out")
          for match in parse('$.CVE_data_timestamp').find(self.collection):
            self.ts = dateutil.parser.parse(match.value)
          self.g = Graph()
          self.baseURI = URIRef(baseURI)
      else:
          print("unknown data version")
          print([m.value for m in parse('$.CVE_data_type').find(self.collection)], [m.value for m in parse('$.CVE_data_format').find(self.collection)],[m.value for m in parse('$.CVE_data_version').find(self.collection)])
          raise(BaseException("unknown data version"))

  def convert(self):
    self.catalog()
    return self.g
        
  def catalog(self):
    """
    <xsl:template match="/nvdfeed:nvd">
      <rdf:RDF>
        <xsl:apply-templates />
        <rdf:Description rdf:type="{$VULN}NVD20Catalog" rdf:about="{$BASEURI}">
          <xsl:for-each select="//nvdfeed:entry">
            <vuln:vulnerability>
              <rdf:Description rdf:about="{tifn:cveURI(@id)}" rdf:type="{$CORE}Vulnerability" />
            </vuln:vulnerability>
          </xsl:for-each>
        </rdf:Description>
      </rdf:RDF>
    </xsl:template>
    """
    self.rdfobject(self.baseURI, VULN.NVD20Catalog, [ (CORE.vulnerability, self.cve(match.value)) for match in parse('$.CVE_Items[*]').find(self.collection)])
    #self.g.add((self.baseURI, RDF.type, VULN.NVD20Catalog))

  def cve(self, o):
    """
    <xsl:template match="//nvdfeed:entry">
        <rdf:Description rdf:about="{tifn:cveURI(@id)}" rdf:type="{$CORE}Vulnerability" >
          <xsl:apply-templates select="scapvuln:cwe" />
          <xsl:apply-templates select="scapvuln:vulnerable-software-list" />
          <xsl:apply-templates select="scapvuln:references" />
          <xsl:apply-templates select="scapvuln:cvss" />
          <xsl:apply-templates select="scapvuln:vulnerable-configuration" />
        </rdf:Description>
      </xsl:template>
    """
    if findin('$.cve.data_type', o, "CVE") and \
      findin('$.cve.data_format', o, "MITRE") and \
      findin('$.cve.data_version', o, "4.0"):
        id = all('$.cve.CVE_data_meta.ID', o)[0]
        s = cveURI(id)
        self.rdfobject(s, CORE.Vulnerability, \
          [ (VULN.id, Literal(id)) ] + \
          allDateTime(DCTERMS.issued, "$.publishedDate", o)  + \
          allDateTime(DCTERMS.modified, "$.lastModifiedDate", o)  + \
          allLangString(RDFS.comment, "$.cve.description.description_data.[*]", o) + \
          self.allReferences(VULN.reference, "$.cve.references.reference_data[*]", o) + \
          self.allConfigurations( VULN.vulnerableConfiguration, "$.configurations", o) + \
          self.allImpacts(VULN.score, "$.impact", o) + \
          self.allCWEs(VULN.weakness, "$.cve.problemtype.[*].problemtype_data.[*].description.[*].value", o) )
        return s

  def allReferences(self, p, q, o):
    return [ (p, self.reference(r) ) for r in all(q, o) ]

  def allConfigurations(self, p, q, o):
    """
      {
        "CVE_data_version": "4.0",
        "nodes": [
          {
            "operator": "OR",
            "cpe_match": [
              {
                "vulnerable": true,
                "cpe23Uri": "cpe:2.3:o:google:android:10.0:*:*:*:*:*:*:*"
              }
            ]
          }
        ]
      }
    """
    
    platform = CPEConfiguration(self.baseURI, self.g)
    return [(p, c) for c in platform.convert(all(q, o))]
    
  def allImpacts(self, p, q, o):
    """
      {
        "baseMetricV3": {
          "cvssV3": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "attackVector": "LOCAL",
            "attackComplexity": "LOW",
            "privilegesRequired": "LOW",
            "userInteraction": "NONE",
            "scope": "UNCHANGED",
            "confidentialityImpact": "HIGH",
            "integrityImpact": "HIGH",
            "availabilityImpact": "HIGH",
            "baseScore": 7.8,
            "baseSeverity": "HIGH"
          },
          "exploitabilityScore": 1.8,
          "impactScore": 5.9
        },
        "baseMetricV2": {
          "cvssV2": {
            "version": "2.0",
            "vectorString": "AV:L/AC:L/Au:N/C:P/I:P/A:P",
            "accessVector": "LOCAL",
            "accessComplexity": "LOW",
            "authentication": "NONE",
            "confidentialityImpact": "PARTIAL",
            "integrityImpact": "PARTIAL",
            "availabilityImpact": "PARTIAL",
            "baseScore": 4.6
          },
          "severity": "MEDIUM",
          "exploitabilityScore": 3.9,
          "impactScore": 6.4,
          "acInsufInfo": false,
          "obtainAllPrivilege": false,
          "obtainUserPrivilege": false,
          "obtainOtherPrivilege": false,
          "userInteractionRequired": false
        }
      }
    """
    metrics = list()
    for impact in all(q, o):
      if len(impact) == 0:
        print("Empty impact in: ", o)
      else:
        cvssv3MetricGroup = self.mapCVSSv3(all("$.baseMetricV3.cvssV3", impact))
        if not len(cvssv3MetricGroup) == 0:
          metrics.append((CORE.score, self.rdfobject(cvssv3IRI("$.baseMetricV3.cvssV3.vectorString", impact), SCORE.CVSSv3BaseMetricGroup, cvssv3MetricGroup)))
        cvssv2MetricGroup = self.mapCVSSv2(all("$.baseMetricV2.cvssV2", impact))
        if not len(cvssv2MetricGroup) == 0:
          metrics.append((CORE.score, self.rdfobject(cvssv2IRI("$.baseMetricV2.cvssV2.vectorString", impact), SCORE.CVSSv2BaseMetricGroup, cvssv2MetricGroup)))

    return metrics

  def mapCVSSv3(self, impact):
    #print(impact)
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
        tuples += allFloat(SCORE.cvss_v3_baseScore, "$.baseScore", i)
        tuples += allString(SCORE.cvss_v3_severity, "$.baseSeverity", i)
        tuples += allString(SCORE.cvss_v3_vector, "$.vectorString", i)
      else:
        print("Unknown CVSS V3 version: ", all("$.version", i))
    return tuples

  """(hasMetric some CVSSv2AccessComplexity) and 
  (hasMetric some CVSSv2AccessVector) and 
  (hasMetric some CVSSv2Authentication) and 
  (hasMetric some CVSSv2AvailabilityImpact) and 
  (hasMetric some CVSSv2ConfidentialityImpact) and 
  (hasMetric some CVSSv2IntegrityImpact)"""
  def mapCVSSv2(self, impact):
    tuples = list()
    for i in impact:
      if "2.0" in all("$.version", i):
        tuples += self.accessComplexityV2(all("$.accessComplexity", i))
        tuples += self.accessVectorV2(all("$.accessVector", i))
        tuples += self.authenticationV2(all("$.authentication", i))
        tuples += self.availabilityImpactV2(all("$.availabilityImpact", i))
        tuples += self.confidentialityImpactV2(all("$.confidentialityImpact", i))
        tuples += self.integrityImpactV2(all("$.integrityImpact", i))
        tuples += allFloat(SCORE.cvss_v2_baseScore, "$.baseScore", i)
        tuples += allString(SCORE.cvss_v2_vector, "$.vectorString", i)
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
    """
      {
        "problemtype_data": [
          {
            "description": [
              {
                "lang": "en",
                "value": "CWE-787"
              }
            ]
          }
        ]
      }
    """
    #print([(p, cweURI(s)) for s in all(q, o) if s.startswith('CWE-')])
    return [(p, cweURI(s)) for s in all(q, o) if s.startswith('CWE-')]

  def reference(self, o):
    """
    <xsl:template match="scapvuln:references">
      <vuln:reference>
        <xsl:variable name="TYPE">
          <xsl:choose>
            <xsl:when test="starts-with(@reference_type, 'PATCH')">PatchReference</xsl:when>
            <xsl:when test="starts-with(@reference_type, 'VENDOR_ADVISORY')">VendorAdvisoryReference</xsl:when>
            <xsl:otherwise>Reference</xsl:otherwise>
          </xsl:choose>
        </xsl:variable>
        <xsl:variable name="TYPE_URI"><xsl:value-of select="concat($VULN,$TYPE)" /></xsl:variable>
        <rdf:Description rdf:type="{$TYPE_URI}">
          <xsl:if test="@deprecated">
            <vuln:referenceDeprecated rdf:datatype="xsd:boolean">
              <xsl:value-of select="@deprecated" />
            </vuln:referenceDeprecated>
          </xsl:if>
          <xsl:apply-templates select="scapvuln:source" />
          <xsl:apply-templates select="scapvuln:reference" />
        </rdf:Description>
      </vuln:reference>
    </xsl:template>

    <xsl:template match="scapvuln:source">
      <vuln:referenceSource>
        <xsl:value-of select="text()"/>
      </vuln:referenceSource>
    </xsl:template>

    <xsl:template match="scapvuln:reference">
      <vuln:referenceURL rdf:datatype="xsd:anyURI">
        <xsl:value-of select="@href"/>
      </vuln:referenceURL>
    
      <xsl:if test="text()!=@url">
        <vuln:referenceTitle xml:lang="{@xml:lang}">
	        <xsl:value-of select="text()" />
        </vuln:referenceTitle>
      </xsl:if>
    </xsl:template>
    """
    #print(o)
    s = BNode()
    for url in all("$.url", o):
      parsed_url = urlparse(url)
      if parsed_url.scheme:
        s = URIRef(url)
        break
    
    tags = [ (RDF.type, VULN["".join([t.capitalize() for t in tag.split()])+"Reference"]) for tag in all("$.tags[*]", o) ]
    #print(tags)
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

rdfcves = NVD2RDF(nvdfile, "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent/2020-06-19T12:00:08-04:00/")
g = rdfcves.convert()
g.bind('dcterms', DCTERMS)
g.bind('dc', DC)
g.bind('foaf', FOAF)
g.bind('core', CORE)
g.bind('score', SCORE)
g.bind('plat', PLATFORM)
g.bind('vuln', VULN)
g.bind('rdf', RDF)
g.bind('cti', CTI)

g.serialize(destination=nvdfile.replace(".json", ".ttl"), format='turtle', encoding="utf-8")
