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

#nvdfile = "collections/nvdcve-1.1-CVE-2019-9460.json"
nvdfile = "collections/nvdcve-1.1-recent.json"

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

#def firstDateTime(q, o):
#  return Literal(first(q,o), datatype=XSD.dateTime)

#def firstDateTimeP(p, q, o):
#  return (p, firstDateTime(q, o))

def allDateTime(p, q, o):
  return [(p, Literal(dt, datatype=XSD.dateTime)) for dt in all(q, o)]

#def firstString(q, o):
#  return Literal(first(q, o))

#def firstStringP(p, q, o):
#  return (p, firstString(q, o))

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

#def firstURL(q, o):
#  return Literal(first(q, o), datatype=XSD.anyURI)

#def firstURLP(p, q, o):
#  return (p, firstURL(q, o))

def allURL(p, q, o):
  return [(p, Literal(u, datatype=XSD.anyURI)) for u in all(q, o)]

def findin(jp, doc, value):
  return value in [m.value for m in parse(jp).find(doc)]

#def rdfobject(g, s, rdftype, items):
#  g.add((s, RDF.type, rdftype))
#  for (p, o) in items:
#    if p and o:
#      #print("adding", s, p, o)
#      g.add((s, p, o))
    #else:
    #  print("not adding", s, p, o)

def cveURI(id):
  """
  <xsl:function name="tifn:cveURI">
    <xsl:param name="entryId"/>
    <xsl:value-of select="fn:concat('urn:X-cve:', $entryId)" />
  </xsl:function>
  """
  return URIRef('urn:X-cve:' + id)

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
    print(self.ts)

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
          self.allImpacts(VULN.score, "$.cve.impact", o) + \
          self.allCWEs(VULN.xxx, "$.cve.problemtype", o) )
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
    return []

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
