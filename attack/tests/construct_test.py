import unittest
import rdflib
from rdflib.plugins.sparql import prepareQuery
from rdflib.namespace import DCTERMS, XSD, RDFS, RDF
from rdflib import Namespace
from rdflib.term import Literal

CTI = Namespace("http://ontologies.ti-semantics.com/cti#")
CORE = Namespace("http://ontologies.ti-semantics.com/core#")
BASE = Namespace("https://attack.mitre.org/pre-attack#")
TRUE = Literal('true', datatype=XSD.boolean)
FALSE = Literal('false', datatype=XSD.boolean)

class TestAttackConstruct_attack_pattern__0649fc36_72a0_40a0_a2f9_3fc7e3231ad6(unittest.TestCase):
    def setUp(self):
        self.g = rdflib.Graph()
        self.g.parse("tests/pre-attack-attack-pattern--0649fc36-72a0-40a0-a2f9-3fc7e3231ad6.ttl", format="turtle")
        self.s = rdflib.term.URIRef('https://attack.mitre.org/pre-attack#attack-pattern--0649fc36-72a0-40a0-a2f9-3fc7e3231ad6')
        
    def test_ntriples(self):
        self.assertEqual(len(self.g), 21)

    def test_class(self):
        self.assertTrue(self.g[self.s : RDF.type : CTI.AttackPattern])

    def test_created(self):
        r = list(self.g[ self.s : DCTERMS.created ])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0], Literal("2017-12-14T16:46:06.044000+00:00", datatype=XSD.dateTime) )

    def test_modified(self):
        r = list(self.g[ self.s : DCTERMS.modified ])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0], Literal("2018-10-17T00:14:20.652000+00:00", datatype=XSD.dateTime) )

    def test_description(self):
        r = list(self.g[ self.s : DCTERMS.description])
        self.assertEqual(len(r), 1)
        self.assertEquals(r[0], Literal("Callbacks are malware communications seeking instructions. An adversary will test their malware to ensure the appropriate instructions are conveyed and the callback software can be reached. (Citation: LeeBeaconing)", lang="en"))
        
    def test_rightsHolder(self):
        r = list(self.g[ self.s : DCTERMS.rightsHolder])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0], BASE['marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168'])

    def test_title(self):
        r = list(self.g[ self.s : DCTERMS.title])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0], Literal("Test callback functionality", lang="en"))

    def test_x_mitre_detectable_by_common_defenses(self):
        self.assertTrue(
            self.g[ self.s : BASE.x_mitre_detectable_by_common_defenses : FALSE ])

    def test_x_mitre_detectable_by_common_defenses_explanation(self):
        r = list(self.g[ self.s : BASE.x_mitre_detectable_by_common_defenses_explanation])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0], Literal("Adversary controls the test and defender likely has no visibility.", lang="en") )
        
    def test_x_mitre_difficulty_for_adversary(self):
        self.assertTrue(
            self.g[ self.s : BASE.x_mitre_difficulty_for_adversary : FALSE ])
        
    def test_x_mitre_difficulty_for_adversary_explanation(self):
        r = list(self.g[ self.s : BASE.x_mitre_difficulty_for_adversary_explanation])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0], Literal("Adversary controls or acquires all pieces of infrastructure and can test outside of defender\'s visibility.", lang="en") )

        self.assertTrue(bool(
            self.g.query(
                'ASK { ?s :x_mitre_difficulty_for_adversary_explanation "Adversary controls or acquires all pieces of infrastructure and can test outside of defender\'s visibility."@en }'
                )
            ))

    def test_x_mitre_old_attack_id(self):
        r = list(self.g[ self.s : BASE.x_mitre_old_attack_id])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0], Literal('PRE-T1133'))


    def test_killchain(self):
        self.assertTrue(bool(
            self.g.query(
                """ASK { ?s cti:killChainPhase  [ a cti:KillChainPhase ;
                              cti:killChainName "mitre-pre-attack" ;
                              cti:phaseName "test-capabilities"^^xsd:token
                            ] }"""
                            ,
                initNs = { "cti": CTI, "xsd": XSD, "rdf": RDF }
                )
            ))

    def test_reference_1(self):
        self.assertTrue(bool(
            self.g.query("""ASK { 
                ?s core:reference [ 
                    a core:Reference ;
                    core:referenceSource "LeeBeaconing"^^xsd:token ;
                    terms:description "Tony Lee. (2012, December 11). Testing Your Defenses - Beaconing. Retrieved March 9, 2017." ;
                  ]
                }""",
                initNs = { "terms": DCTERMS, "cti": CTI, "core": CORE, "xsd": XSD }
                )))
       
    def test_reference_2(self):
        self.assertTrue(bool(
            self.g.query("""ASK { 
                ?s core:reference [ 
                    a core:Reference ;
                    core:referenceSource "mitre-pre-attack"^^xsd:token ;
                    core:referenceURL <https://attack.mitre.org/techniques/T1356> ;
                    terms:id "T1356"^^xsd:token ;
                  ]
                }""",
                initNs = { "terms": DCTERMS, "cti": CTI, "core": CORE, "xsd": XSD }
                )))


class TestAttackConstruct_attack_pattern__773950e1_090c_488b_a480_9ff236312e31(unittest.TestCase):
    def setUp(self):
        self.g = rdflib.Graph()
        self.g.parse("tests/pre-attack-attack-pattern--773950e1-090c-488b-a480-9ff236312e31.ttl", format="turtle")
        self.s = rdflib.term.URIRef('https://attack.mitre.org/pre-attack#attack-pattern--773950e1-090c-488b-a480-9ff236312e31')
        
    def test_ntriples(self):
        self.assertEqual(len(self.g), 21)

    def test_class(self):
        self.assertTrue(self.g[self.s : RDF.type : CTI.AttackPattern])
        
    def test_created(self):
        r = list(self.g[ self.s : DCTERMS.created ])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0], Literal("2017-12-14T16:46:06.044000+00:00", datatype=XSD.dateTime) )

    def test_modified(self):
        r = list(self.g[ self.s : DCTERMS.modified ])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0], Literal("2018-10-17T00:14:20.652000+00:00", datatype=XSD.dateTime) )

    def test_description(self):
        r = list(self.g[ self.s : DCTERMS.description])
        self.assertEqual(len(r), 1)
        self.assertEquals(r[0], Literal("An adversary will assess collected information such as software/hardware versions, vulnerabilities, patch level, etc.  They will analyze technical scanning results to identify weaknesses in the confirmation or architecture. (Citation: SurveyDetectionStrategies) (Citation: CyberReconPaper) (Citation: RSA-APTRecon) (Citation: FireEyeAPT28)", lang="en"))
        
    def test_rightsHolder(self):
        r = list(self.g[ self.s : DCTERMS.rightsHolder])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0], BASE['marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168'])

    def test_title(self):
        r = list(self.g[ self.s : DCTERMS.title])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0], Literal("Analyze data collected", lang="en"))

    def test_x_mitre_detectable_by_common_defenses(self):
        self.assertTrue(
            self.g[ self.s : BASE.x_mitre_detectable_by_common_defenses : FALSE ])
        
    def test_x_mitre_detectable_by_common_defenses_explanation(self):
        r = list(self.g[ self.s : BASE.x_mitre_detectable_by_common_defenses_explanation])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0], Literal("This can be done offline after the data has been collected.", lang="en") )

    def test_x_mitre_difficulty_for_adversary(self):
        self.assertTrue(
            self.g[ self.s : BASE.x_mitre_difficulty_for_adversary : FALSE ])
        
    def test_x_mitre_difficulty_for_adversary_explanation(self):
        r = list(self.g[ self.s : BASE.x_mitre_difficulty_for_adversary_explanation])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0], Literal("Many of the common tools highlight these weaknesses automatically.  Adversary can \"dry run\" against the target using known exploits or burner devices to determine key identifiers of software, hardware, and services.", lang="en") )

    def test_x_mitre_old_attack_id(self):
        r = list(self.g[ self.s : BASE.x_mitre_old_attack_id])
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0], Literal('PRE-T1064'))

    def test_killchain(self):
        self.assertTrue(bool(
            self.g.query(
                """ASK { ?s cti:killChainPhase  [ a cti:KillChainPhase ;
                              cti:killChainName "mitre-pre-attack" ;
                              cti:phaseName "technical-weakness-identification"^^xsd:token
                            ] }"""
                            ,
                initNs = { "cti": CTI, "xsd": XSD, "rdf": RDF }
                )
            ))

    def test_reference_1(self):
        self.assertTrue(bool(
            self.g.query("""ASK { 
                ?s core:reference [ 
                    a core:Reference ;
                    core:referenceSource "CyberReconPaper"^^xsd:token ;
                    terms:description "H. P. Sanghvi and M. S. Dahiya. (2013, February). Cyber Reconnaissance: An Alarm before Cyber Attack. Retrieved March 5, 2017." ;
                  ]
                }""",
                initNs = { "terms": DCTERMS, "cti": CTI, "core": CORE, "xsd": XSD }
                )))
       
    def test_reference_2(self):
        self.assertTrue(bool(
            self.g.query("""ASK { 
                ?s core:reference [ 
                    a core:Reference ;
                    core:referenceSource "RSA-APTRecon"^^xsd:token ;
                    terms:description "Rotem Kerner. (2015, October). RECONNAISSANCE: A Walkthrough of the “APT” Intelligence Gathering Process. Retrieved March 1, 2017." ;
                  ]
                }""",
                initNs = { "terms": DCTERMS, "cti": CTI, "core": CORE, "xsd": XSD }
                )))
       
    def test_reference_3(self):
        self.assertTrue(bool(
            self.g.query("""ASK { 
                ?s core:reference [ 
                    a core:Reference ;
                    core:referenceSource "FireEyeAPT28"^^xsd:token ;
                    terms:description "FireEye, Inc. (2014). APT 28: A Window into Russia’s Cyber Espionage Operations?. Retrieved March 1, 2017." ;
                  ]
                }""",
                initNs = { "terms": DCTERMS, "cti": CTI, "core": CORE, "xsd": XSD }
                )))
       
    def test_reference_4(self):
        self.assertTrue(bool(
            self.g.query("""ASK { 
                ?s core:reference [ 
                    a core:Reference ;
                    core:referenceSource "SurveyDetectionStrategies"^^xsd:token ;
                    terms:description "Jamal Raiyn. (2014). A survey of Cyber Attack Detection Strategies. Retrieved March 5, 2017." ;
                  ]
                }""",
                initNs = { "terms": DCTERMS, "cti": CTI, "core": CORE, "xsd": XSD }
                )))

    def test_reference_5(self):
        self.assertTrue(bool(
            self.g.query("""ASK { 
                ?s core:reference [ 
                    a core:Reference ;
                    core:referenceSource "mitre-pre-attack"^^xsd:token ;
                    core:referenceURL <https://attack.mitre.org/techniques/T1287> ;
                    terms:id "T1287"^^xsd:token ;
                  ]
                }""",
                initNs = { "terms": DCTERMS, "cti": CTI, "core": CORE, "xsd": XSD }
                )))


if __name__ == '__main__':
    unittest.main()
