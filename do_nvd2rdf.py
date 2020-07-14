from nvd2rdf import NVD2RDF
from rdflib import Graph, Literal, RDF, URIRef, Namespace, BNode
from rdflib.namespace import RDF, RDFS, XSD, DC, DCTERMS, FOAF

CORE = Namespace("http://ontologies.ti-semantics.com/core#")
CTI = Namespace("http://ontologies.ti-semantics.com/cti#")
PLATFORM = Namespace("http://ontologies.ti-semantics.com/platform#")
SCORE = Namespace("http://ontologies.ti-semantics.com/score#")
VULN = Namespace("http://ontologies.ti-semantics.com/vulnerability#")
NVD = Namespace("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020/")
REFS = Namespace("https://csrc.nist.gov/publications/references/")
CPEMATCH = Namespace("https://csrc.nist.gov/schema/cpematch/feed/1.0/")

#nvdfile = "collections/nvdcve-1.1-recent.json"
#nvdfile = "collections/nvdcve-1.1-CVE-2020-10732.json"
#nvdfile = "collections/nvdcve-1.1-CVE-2019-9460.json"
#nvdfile = "collections/nvdcve-1.1-CVE-2020-13150.json"
#nvdfile = "collections/CVE-2020-12462.json"
nvdfile = "collections/CVE-2019-0001.json"

rdfcves = NVD2RDF(nvdfile, "2020-06-19T12:00:08-04:00")
g = rdfcves.single()
#g = rdfcves.catalog()

g.bind('dcterms', DCTERMS)
g.bind('dc', DC)
g.bind('foaf', FOAF)
g.bind('core', CORE)
g.bind('score', SCORE)
g.bind('plat', PLATFORM)
g.bind('vuln', VULN)
g.bind('rdf', RDF)
g.bind('cti', CTI)
g.bind('nvd', NVD)
g.bind('refs', REFS)
g.bind('cpematch', CPEMATCH)

g.serialize(destination=nvdfile.replace(".json", ".ttl"), format='turtle', encoding="utf-8")
