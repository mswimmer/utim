BASE <https://nvd.nist.gov/feeds/json/cve/1.1>
PREFIX : <#>
PREFIX core: <http://ontologies.ti-semantics.com/core#>
PREFIX vuln: <http://ontologies.ti-semantics.com/vulnerability#>
PREFIX score: <http://ontologies.ti-semantics.com/score#>
PREFIX terms: <http://purl.org/dc/terms/>

CONSTRUCT {
  ?cveURL a core:Vulnerability ;
  # The description of this vulnerability in text form. We use DC terms for this.
  terms:description ?description ;
  terms:title ?cveID ;
  terms:creator ?author ;
  # Make a reference to the CWE entity that this vulnerability is related to.
  vuln:cwe ?cwe ;
  # Create a reference object
  vuln:reference [
		   a vuln:Reference ;
		   terms:title ?name ;
		   terms:subject ?tag ;
		   core:referenceURL ?refURL ;
		   core:referenceSource ?refSource
		 ] ;
  # CVSS v2
  # bool:
  score:cvss_v2_insufficientInformation ?acInsufInfoV2 ;
  score:cvss_v2_obtainAllPrivilege ?obtainAllPrivilegeV2 ;
  score:cvss_v2_obtainOtherPrivilege ?obtainOtherPrivilegeV2 ;
  score:cvss_v2_obtainUserPrivilege ?obtainUserPrivilegeV2 ;
  score:cvss_v2_userInteractionRequired ?userInteractionRequiredV2 ; 
  # numeric score
  score:cvss_v2_exploitabilityScore ?exploitabilityScoreV2 ;
  score:cvss_v2_impactSubscore ?impactScoreV2 ;
  # enum
  score:cvss_v2_severity ?severityV2 ;
  # complext string
  score:cvss_v2_vector ?vectorStringV2 ;
  # should be entities
  score:hasAvailabilityImpact ?availabilityImpactV2 ;
  score:hasAuthentication ?authenticationV2 ;
  #:version ?versionV2 ;
  score:hasConfidentialityImpact ?confidentialityImpactV2 ;
  score:cvss_v2_baseScore ?baseScoreV2 ;
  score:hasAccessVector ?accessVectorV2 ;
  score:hasAccessComplexity ?accessComplexityV2 ;
  score:hasIntegrityImpact ?integrityImpactV2 ;
  # CVSS V3
  score:cvss_v3_exploitabilityScore ?exploitabilityScoreV3 ;
  score:cvss_v3_impactSubscore ?impactScoreV3 ;
  score:cvss_v3_vector ?vectorStringV3 ;
  score:hasAvailabilityImpact ?availabilityImpactV3 ;
  score:hasConfidentialityImpact ?confidentialityImpactV3 ;
  score:cvss_v3_baseScore ?baseScoreV3 ;
  score:hasAttackVector ?attacksVectorV3 ;
  score:hasttackComplexity ?attackComplexityV3 ;
  score:hasIntegrityImpact ?integrityImpactV3 ;
  score:hasBaseSeverity ?baseSeverityV3 ;
  score:hasUserInteraction ?userInteractionV3 ;
  score:hasPrivilegesRequired ?privilegesRequiredV3 ;

	
.
} WHERE {
  ?collection :CVE_Items
  [
    :cve [
	   # Restrict this selection to Mitre CVE format 4.0
	   :data_type "CVE" ;
	   :data_version  "4.0" ;
	   :data_format "MITRE" ;
	   # The description of the vulnerability is comprised of the value and the language code, which is usually 'en'
	   :description [
			  :description_data [
					      :value ?descStr ;
					      :lang ?descLangCode
					    ]
			] ;
	   :CVE_data_meta [
			    :ASSIGNER ?author_str ;
			    :ID ?cveID
			  ] ;
	   # The problem type is actually the CWE(s) associated with this vulnerability
	   :problemtype [
			  :problemtype_data [
					      :description [
							     :value ?cweStr
							     # There is a language tag, but we can ignore that
							   ]
					    ]
			] ;
	   :references [
			 :reference_data [
					   :tags ?tag ;
					   :name ?name ; 
					   :url ?urlStr ;
					   :refsource ?refSource
					 ]
		       ]
	 ] ;
    :impact [
	      :baseMetricV2 [
			      :exploitabilityScore ?exploitabilityScoreV2 ;
			      :acInsufInfo ?acInsufInfoV2 ;
			      :obtainAllPrivilege ?obtainAllPrivilegeV2 ;
			      :obtainOtherPrivilege ?obtainOtherPrivilegeV2 ;
			      :impactScore ?impactScoreV2 ;
			      :userInteractionRequired ?userInteractionRequiredV2 ; 
			      :severity ?severityV2 ;
			      :obtainUserPrivilege ?obtainUserPrivilegeV2 ;
			      :cvssV2 [
					:version "2.0" ;
					:vectorString ?vectorStringV2 ;
					:availabilityImpact ?availabilityImpactV2Str ;
					:authentication ?authenticationV2Str ;
					:version ?versionV2 ;
					:confidentialityImpact ?confidentialityImpactV2Str ;
					:baseScore ?baseScoreV2 ;
					:accessVector ?accessVectorV2Str ;
					:accessComplexity ?accessComplexityV2Str ;
					:integrityImpact ?integrityImpactV2Str 
				      ] 
			    ] ;
	      :baseMetricV3 [
			      :exploitabilityScore ?exploitabilityScoreV3 ;
			      :impactScore ?impactScoreV3 ;
			      :cvssV3 [
					:version "3.1" ;
					:vectorString ?vectorStringV3 ;
					:availabilityImpact ?availabilityImpactV3Str ;
					:confidentialityImpact ?confidentialityImpactV3Str ;
					:baseScore ?baseScoreV3 ;
					:attackVector ?attacksVectorV3Str ;
					:attackComplexity ?attackComplexityV3Str ;
					:integrityImpact ?integrityImpactV3Str ;
					:baseSeverity ?baseSeverityV3 ;
					:userInteraction ?userInteractionV3Str ;
					:privilegesRequired ?privilegesRequiredV3Str ;
					:scope ?scopeV3Str ;
				      ] 
			    ]
	    ]
    #TODO:
    #    <https://nvd.nist.gov/feeds/json/cve/1.1#configurations> [
    #            <https://nvd.nist.gov/feeds/json/cve/1.1#CVE_data_version> "4.0" ;
    #            <https://nvd.nist.gov/feeds/json/cve/1.1#nodes> [
    #                <https://nvd.nist.gov/feeds/json/cve/1.1#cpe_match> [
    #                    <https://nvd.nist.gov/feeds/json/cve/1.1#cpe23Uri> "cpe:2.3:o:google:android:10.0:*:*:*:*:*:*:*" ;
    #                    <https://nvd.nist.gov/feeds/json/cve/1.1#vulnerable> true
    #                ] ;
    #                <https://nvd.nist.gov/feeds/json/cve/1.1#operator> "OR"
    #            ]
    #        ] ;
    #
    # check CVE_data_version for known value
    # extract the cpe23Uri and see if it can be coerced into a value URI
  ].
  
  BIND ("http://ontologies.ti-semantics.com/score#" AS ?score_ns)
  BIND ("https://nvd.nist.gov/vuln/detail/" AS ?cve_ns)
  BIND ("https://cwe.mitre.org/data/definitions/" AS ?cwe_ns)
  
  BIND( STRLANG(?descStr, ?descLangCode) AS ?description ) .
  # We create a URL out of the CWE string by prefixing it with the Mitre CWE URL and stripping out the 'CWE-' portion so that the URL actual resolves
  BIND( URI(?cwe_ns+STRAFTER(?cweStr, '-')) AS ?cwe ) .
  BIND( URI(?urlStr) AS ?refURL ) .
  BIND( URI(?cve_ns+?cveID) AS ?cveURL ) .
  # Convert CVSS v2 strings to entities
  # confidentialityImpact
  BIND( URI( ?score_ns +
	    IF(UCASE(?confidentialityImpactV2Str)="NONE", "CVSSv2NoneConfidentialityImpact",
	       IF(UCASE(?confidentialityImpactV2Str)="PARTIAL", "CVSSv2PartialConfidentialityImpact",
		  IF(UCASE(?confidentialityImpactV2Str)="COMPLETE", "CVSSv2CompleteConfidentialityImpact",
		     "ERROR")))) as ?confidentialityImpactV2 ) .
  # availabilityImpact
  BIND( URI(?score_ns+
	    IF(UCASE(?availabilityImpactV2Str)="NONE", "CVSSv2NoneAvailabilityImpact",
	       IF(UCASE(?availabilityImpactV2Str)="PARTIAL", "CVSSv2PartialAvailabilityImpact",
		  IF(UCASE(?availabilityImpactV2Str)="COMPLETE", "CVSSv2CompleteAvailabilityImpact",
		     "ERROR")))) as ?availabilityImpactV2 ) .
  # integrityImpact
  BIND( URI(?score_ns+
	    IF(UCASE(?integrityImpactV2Str)="NONE", "CVSSv2NoneIntegrityImpact",
	       IF(UCASE(?integrityImpactV2Str)="PARTIAL", "CVSSv2PartialIntegrityImpact",
		  IF(UCASE(?integrityImpactV2Str)="COMPLETE", "CVSSv2CompleteIntegrityImpact",
		     "ERROR")))) as ?integrityImpactV2 ) .
  # accessComplexity
  BIND( URI(?score_ns+
	    IF(UCASE(?accessComplexityV2Str)="LOW", "CVSSv2LowAccessComplixity",
	       IF(UCASE(?accessComplexityV2Str)="MEDIUM", "CVSSv2MediumAccessComplixity",
		  IF(UCASE(?accessComplexityV2Str)="HIGH", "CVSSv2HighAccessComplixity",
		     "ERROR")))) as ?accessComplexityV2 ) .
  # authentication
  BIND( URI(?score_ns+
	    IF(UCASE(?authenticationV2Str)="NONE", "CVSSv2NoAuthentication",
	       IF(UCASE(?authenticationV2Str)="SINGLE", "CVSSv2SingleAuthentication",
		  IF(UCASE(?authenticationV2Str)="MULTIPLE", "CVSSv2MultipleAuthentication",
		     "ERROR")))) as ?authenticationV2 ) .
  #accessVector
  BIND( URI(?score_ns+
	    IF(UCASE(?accessVectorV2Str)="LOCAL", "CVSSv2LocalAccessVector",
	       IF(UCASE(?accessVectorV2Str)="ADJACENT", "CVSSv2AdjacentAccessVector",
		  IF(UCASE(?accessVectorV2Str)="NETORK", "CVSSv2NetworkAccessVector",
		     "ERROR")))) as ?accessVectorV2 ) .

  # Convert CVSS v3 strings to entities
  # confidentialityImpact
  BIND( URI(?score_ns+
	    IF(UCASE(?confidentialityImpactV3Str)="NO", "CVSSv3NoConfidentialityImpact",
	       IF(UCASE(?confidentialityImpactV3Str)="LOW", "CVSSv3LowConfidentialityImpact",
		  IF(UCASE(?confidentialityImpactV3Str)="HIGH", "CVSSv3HighConfidentialityImpact",
		     "ERROR")))) as ?confidentialityImpactV3 ) .
  # availabilityImpact
  BIND( URI(?score_ns+
	    IF(UCASE(?availabilityImpactV3Str)="NONE", "CVSSv3NoAvailabilityImpact",
	       IF(UCASE(?availabilityImpactV3Str)="LOW", "CVSSv3LowAvailabilityImpact",
		  IF(UCASE(?availabilityImpactV3Str)="HIGH", "CVSSv3HighAvailabilityImpact",
		     "ERROR")))) as ?availabilityImpactV3 ) .
  # integrityImpact
  BIND( URI(?score_ns+
	    IF(UCASE(?integrityImpactV3Str)="NONE", "CVSSv3NoIntegrityImpact",
	       IF(UCASE(?integrityImpactV3Str)="LOW", "CVSSv3LowIntegrityImpact",
		  IF(UCASE(?integrityImpactV3Str)="HIGH", "CVSSv3HighIntegrityImpact",
		     "ERROR")))) as ?integrityImpactV3 ) .
  # attackComplexity
  BIND( URI(?score_ns+
	    IF(UCASE(?attackComplexityV3Str)="LOW", "CVSSv3LowAttackComplixity",
	       IF(UCASE(?attackComplexityV3Str)="HIGH", "CVSSv3HighAttackComplixity",
		  "ERROR"))) as ?attackComplexityV3 ) .
  # attackVector
  BIND( URI(?score_ns+
	    IF(UCASE(?attacksVectorV3Str)="PHYSICAL", "CVSSv3PhysicalAttacksVector",
	       IF(UCASE(?attacksVectorV3Str)="LOCAL", "CVSSv3LocalAttacksVector",
		  IF(UCASE(?attacksVectorV3Str)="ADJACENT", "CVSSv3AdjacentAttacksVector",
		     IF(UCASE(?attacksVectorV3Str)="NETWORK", "CVSSv3NetworkAttacksVector",
		     "ERROR"))))) as ?attacksVectorV3 ) .
  # userInteraction
  BIND( URI(?score_ns+
	    IF(UCASE(?userInteractionV3Str)="REQUIRED", "CVSSv3RequiredUserInteraction",
	       IF(UCASE(?userInteractionV3Str)="NONE", "CVSSv3NoUserInteraction",
		  "ERROR"))) as ?userInteractionV3 ) .

  # scope
  BIND( URI(?score_ns+
	    IF(UCASE(?scopeV3Str)="UNCHANGED", "CVSSv3UnchangedScope",
	       IF(UCASE(?scopeV3Str)="CHANGED", "CVSSv3ChangedScope",
		  "ERROR"))) as ?scopeV3 ) .
  # privilegesRequired
  BIND( URI(?score_ns+
	    IF(UCASE(?privilegesRequiredV3Str)="NONE", "CVSSv3NoPrivilegesRequired",
	       IF(UCASE(?privilegesRequiredV3Str)="LOW", "CVSSv3LowPrivilegesRequired",
		  IF(UCASE(?privilegesRequiredV3Str)="HIGH", "CVSSv3HighPrivilegesRequired",
		     "ERROR")))) as ?privilegesRequiredV3 ) .
  BIND( URI("mailto:"+?author_str) as ?author)
  
}
