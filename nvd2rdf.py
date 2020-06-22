from jsonpath_ng import jsonpath, parse
import json
from rdflib import Graph, Literal, RDF, URIRef, Namespace, BNode
from rdflib.namespace import RDF, RDFS, XSD, DC, DCTERMS, FOAF
import dateutil.parser

CORE = Namespace("http://ontologies.ti-semantics.com/core#")
CTI = Namespace("http://ontologies.ti-semantics.com/cti#")
PLATFORM = Namespace("http://ontologies.ti-semantics.com/platform#")
SCORE = Namespace("http://ontologies.ti-semantics.com/score#")
VULN = Namespace("http://ontologies.ti-semantics.com/vulnerability#")

nvdfile = "collections/nvdcve-1.1-CVE-2019-9460.json"
#nvdfile = "collections/nvdcve-1.1-recent.json"

def all(q, o, fn=None):
  a = [ m.value for m in parse(q).find(o) ]
  if fn:
    for i in a:
      fn(i)
  else:
    return a

def first(q, o, fn=None):
  #TODO could be optimised
  a = all(q,o)
  if len(a) > 0:
    if fn:
      fn(a[0])
    else:
      return a[0]

def allDateTime(p, q, o):
  return [(p, Literal(dt, datatype=XSD.dateTime)) for dt in all(q, o)]

def allString(p, q, o):
  return [(p, Literal(s)) for s in all(q, o)]

def allLangString(p, q, o):
  """ Expects and object like this:
    {
      "lang": "en",
      "value": "In mediaserver, there is a possible out of bounds ..."
    }
  """
  return [ (p, Literal(first("$.value", s), lang=first("$.lang", s))) for s in all(q, o) ]

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

def cvssv2IRI(q, o):
  for i in all(q, o):
    return URIRef('urn:CVSS:2.0'+i)

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
        id = first('$.cve.CVE_data_meta.ID', o)
        s = cveURI(id)
        self.rdfobject(s, CORE.Vulnerability, \
          [ (VULN.id, Literal(id)) ] + \
          allDateTime(DCTERMS.issued, "$.publishedDate", o)  + \
          allDateTime(DCTERMS.modified, "$.lastModifiedDate", o)  + \
          allLangString(RDFS.comment, "$.cve.description.description_data.[*]", o) + \
          self.allReferences(VULN.reference, "$.cve.references.reference_data[*]", o) + \
          self.allConfigurations( VULN.vulnerableConfiguration, "$.cve.configurations", o) + \
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
    return []

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
    #print(o)
    metrics = list()
    for impact in all(q, o):
      #tuples = list()
      #tuples += 
      #tuples += self.mapCVSSv2(all("$.baseMetricV2.cvssV2", impact))
      metrics.append((CORE.score, self.rdfobject(cvssv3IRI("$.baseMetricV3.cvssV3.vectorString", impact), SCORE.CVSSv3BaseMetricGroup, self.mapCVSSv3(all("$.baseMetricV3.cvssV3", impact)))))
      metrics.append((CORE.score, self.rdfobject(cvssv2IRI("$.baseMetricV2.cvssV2.vectorString", impact), SCORE.CVSSv2BaseMetricGroup, self.mapCVSSv2(all("$.baseMetricV2.cvssV2", impact)))))
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
        tuples += self.baseScoreV3(all("$.baseScore", i))
        tuples += self.baseSeverityV3(all("$.baseSeverity", i))
        tuples += self.vectorStringV3(all("$.vectorString", i))
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
        tuples += self.accessComplexityV2(all("$.accessComplexity", id))
        tuples += self.accessVectorV2(all("$.accessVector", i))
        tuples += self.authenticationV2(all("$.authentication", i))
        tuples += self.availabilityImpactV2(all("$.availabilityImpact", i))
        tuples += self.confidentialityImpactV2(all("$.confidentialityImpact", i))
        tuples += self.integrityImpactV2(all("$.integrityImpact", i))
        tuples += self.baseScoreV2(all("$.baseScore", i))
        tuples += self.vectorStringV2(all("$.vectorString", i))
    return tuples

  def mapTo(self, av, p, mapping, error):
    for i in av:
      print(i)
      if i in mapping:
        return [(p, mapping[i])]
      else:
        raise BaseException(error)
    return []

  def vectorStringV2(self, vs):
    return ([(SCORE.cvss_v2_vector, Literal(i)) for i in vs])

  def vectorStringV3(self, vs):
    return ([(SCORE.cvss_v3_vector, Literal(i)) for i in vs])

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

  def baseScoreV3(self, bs): 
    return []

  def baseSeverityV3(self, bs): 
    return []

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

  def baseScoreV2(self, bs): 
    return []

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

print(g.serialize(format='turtle').decode("utf-8"))
