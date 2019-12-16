import unittest
import rdflib
from rdflib.plugins.sparql import prepareQuery
from rdflib.namespace import DCTERMS, XSD, DC
from rdflib import Namespace

CTI = Namespace("http://ontologies.ti-semantics.com/cti#")
CORE = Namespace("http://ontologies.ti-semantics.com/core#")

class TestAttackConstruct(unittest.TestCase):
    def setUp(self):
        self.g = rdflib.Graph()
        self.g.parse("tests/pre-attack-attack-pattern--0649fc36-72a0-40a0-a2f9-3fc7e3231ad6.ttl", format="turtle")
        
    def test_ntriples(self):
        self.assertEqual(len(self.g), 21)

    def test_created(self):
        #for r in self.g.query('SELECT * WHERE { ?s terms:created ?t}', initNs = { "terms": DCTERMS, "xsd": XSD }):
        #    print(r)
        self.assertTrue(bool(
            self.g.query(
                'ASK { ?s terms:created "2017-12-14T16:46:06.044000+00:00"^^xsd:dateTime }',
                initNs = { "terms": DCTERMS, "xsd": XSD }
                )
            ))

    def test_modified(self):
        self.assertTrue(bool(
            self.g.query(
                'ASK { ?s terms:modified "2018-10-17T00:14:20.652000+00:00"^^xsd:dateTime }',
                initNs = { "terms": DCTERMS, "xsd": XSD }
                )
            ))

    def test_description(self):
        self.assertTrue(bool(
            self.g.query(
                'ASK { ?s terms:description "Callbacks are malware communications seeking instructions. An adversary will test their malware to ensure the appropriate instructions are conveyed and the callback software can be reached. (Citation: LeeBeaconing)"@en }',
                initNs = { "terms": DCTERMS, "xsd": XSD }
                )
            ))
        
    def test_rightsHolder(self):
        self.assertTrue(bool(
            self.g.query('ASK { ?s terms:rightsHolder :marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168 }')
            ))


    def test_title(self):
        self.assertTrue(bool(
            self.g.query(
                'ASK { ?s terms:title "Test callback functionality"@en }',
                initNs = { "terms": DCTERMS }
                )
            ))

    def test_x_mitre_detectable_by_common_defenses(self):
        self.assertTrue(bool(
            self.g.query(
                'ASK { ?s :x_mitre_detectable_by_common_defenses false }'
                )
            ))

    def test_x_mitre_detectable_by_common_defenses_explanation(self):
        self.assertTrue(bool(
            self.g.query(
                'ASK { ?s :x_mitre_detectable_by_common_defenses_explanation "Adversary controls the test and defender likely has no visibility."@en }'
                )
            ))

    def test_x_mitre_difficulty_for_adversary(self):
        self.assertTrue(bool(
            self.g.query(
                'ASK { ?s :x_mitre_difficulty_for_adversary false }'
                )
            ))
        
    def test_x_mitre_difficulty_for_adversary_explanation(self):
        self.assertTrue(bool(
            self.g.query(
                'ASK { ?s :x_mitre_difficulty_for_adversary_explanation "Adversary controls or acquires all pieces of infrastructure and can test outside of defender\'s visibility."@en }'
                )
            ))

    def test_killchain(self):
        self.assertTrue(bool(
            self.g.query(
                """ASK { ?s cti:killChainPhase  [ a cti:KillChainPhase ;
                              cti:killChainName "mitre-pre-attack" ;
                              cti:phaseName "test-capabilities"^^xsd:token
                            ] }"""
                            ,
                initNs = { "cti": CTI, "xsd": XSD }
                )
            ))

    def test_reference_1(self):
        self.assertTrue(bool(
            self.g.query("""ASK { 
                ?s core:reference [ 
                    a core:Reference ;
                    core:referenceSource "LeeBeaconing" ;
                    terms:description "Tony Lee. (2012, December 11). Testing Your Defenses - Beaconing. Retrieved March 9, 2017." ;
                  ]
                }""",
                initNs = { "terms": DCTERMS, "cti": CTI, "core": CORE }
                )))
       
    def test_reference_2(self):
        self.assertTrue(bool(
            self.g.query("""ASK { 
                ?s core:reference [ 
                    a core:Reference ;
                    core:referenceSource "mitre-pre-attack" ;
                    core:referenceURL <https://attack.mitre.org/techniques/T1356> ;
                    terms:id "T1356"^^xsd:token ;
                  ]
                }""",
                initNs = { "terms": DCTERMS, "cti": CTI, "core": CORE, "xsd": XSD }
                )))


        #    def test_split(self):
#        s = 'hello world'
#        self.assertEqual(s.split(), ['hello', 'world'])
#        # check that s.split fails when the separator is not a string
#        with self.assertRaises(TypeError):
#            s.split(2)

if __name__ == '__main__':
    unittest.main()

    
#print("ObjectProperties")
#qObjectProperties = prepareQuery(
#    'SELECT DISTINCT ?c WHERE { ?c a <http://www.w3.org/2002/07/owl#ObjectProperty> .}',
#    initNs = { "owl": OWL })
#validObjectProperties = [ row[0] for row in onto.query(qObjectProperties) if isinstance(row[0], rdflib.term.URIRef) ]
#for c in validObjectProperties:
#    print(c)

#print("DataProperties")
#qDataProperties = prepareQuery(
#    'SELECT DISTINCT ?c WHERE { ?c a <http://www.w3.org/2002/07/owl#DataProperty> .}',
#    initNs = { "owl": OWL })
#validDataProperties = [ row[0] for row in onto.query(qDataProperties) if isinstance(row[0], rdflib.term.URIRef) ]
#for c in validDataProperties:
#    print(c)

#sys.exit()    
#basedir="collections"

