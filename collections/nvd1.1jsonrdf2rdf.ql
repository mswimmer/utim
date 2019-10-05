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
			    :ASSIGNER ?author ;
			    :ID ?cveID
			  ] ;
	   # The problem type is actually the CWE(s) associated with this vulnerability
	   :problemtype [
			  :problemtype_data [
					      :description [
							     :value ?cweStr
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
					:authentication ?authenticationV2 ;
					:version ?versionV2 ;
					:confidentialityImpact ?confidentialityImpactV2Str ;
					:baseScore ?baseScoreV2 ;
					:accessVector ?accessVectorV2 ;
					:accessComplexity ?accessComplexityV2 ;
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
					:attackVector ?attacksVectorV3 ;
					:attackComplexity ?attackComplexityV3 ;
					:integrityImpact ?integrityImpactV3Str ;
					:baseSeverity ?baseSeverityV3 ;
					:userInteraction ?userInteractionV3 ;
					:privilegesRequired ?privilegesRequiredV3 ;
				      ] 
			    ]
	    ]
  ].
  
  BIND( STRLANG(?descStr, ?descLangCode) AS ?description )
  # We create a URL out of the CWE string by prefixing it with the Mitre CWE URL and stripping out the 'CWE-' portion so that the URL actual resolves
  BIND( URI("https://cwe.mitre.org/data/definitions/"+STRAFTER(?cweStr, '-')) AS ?cwe )
  BIND( URI(?urlStr) AS ?refURL )
  BIND( URI("https://nvd.nist.gov/vuln/detail/"+?cveID) AS ?cveURL )
  BIND( URI("http://ontologies.ti-semantics.com/score#"+
	    IF(?confidentialityImpactV2Str="NONE", "CVSSv2NoneConfidentialityImpact",
	       IF(?confidentialityImpactV2Str="PARTIAL", "CVSSv2PartialConfidentialityImpact",
		  IF(?confidentialityImpactV2Str="COMPLETE", "CVSSv2CompleteConfidentialityImpact",
		     "ERROR")))) as ?confidentialityImpactV2 ) .
  BIND( URI("http://ontologies.ti-semantics.com/score#"+
	    IF(?confidentialityImpactV3Str="NO", "CVSSv3NoConfidentialityImpact",
	       IF(?confidentialityImpactV3Str="LOW", "CVSSv3LowConfidentialityImpact",
		  IF(?confidentialityImpactV3Str="HIGH", "CVSSv3HighConfidentialityImpact",
		     "ERROR")))) as ?confidentialityImpactV3 ) .
  BIND( URI("http://ontologies.ti-semantics.com/score#"+
	    IF(?availabilityImpactV2Str="NONE", "CVSSv2NoneAvailabilityImpact",
	       IF(?availabilityImpactV2Str="PARTIAL", "CVSSv2PartialAvailabilityImpact",
		  IF(?availabilityImpactV2Str="COMPLETE", "CVSSv2CompleteAvailabilityImpact",
		     "ERROR")))) as ?availabilityImpactV2 ) .
  BIND( URI("http://ontologies.ti-semantics.com/score#"+
	    IF(?availabilityImpactV3Str="NONE", "CVSSv3NoAvailabilityImpact",
	       IF(?availabilityImpactV3Str="LOW", "CVSSv3LowAvailabilityImpact",
		  IF(?availabilityImpactV3Str="HIGH", "CVSSv3HighAvailabilityImpact",
		     "ERROR")))) as ?availabilityImpactV3 ) .
  BIND( URI("http://ontologies.ti-semantics.com/score#"+
	    IF(?integrityImpactV2Str="NONE", "CVSSv2NoneIntegrityImpact",
	       IF(?integrityImpactV2Str="PARTIAL", "CVSSv2PartialIntegrityImpact",
		  IF(?integrityImpactV2Str="COMPLETE", "CVSSv2CompleteIntegrityImpact",
		     "ERROR")))) as ?integrityImpactV2 ) .
  BIND( URI("http://ontologies.ti-semantics.com/score#"+
	    IF(?integrityImpactV3Str="NONE", "CVSSv3NoIntegrityImpact",
	       IF(?integrityImpactV3Str="LOW", "CVSSv3LowIntegrityImpact",
		  IF(?integrityImpactV3Str="HIGH", "CVSSv3HighIntegrityImpact",
		     "ERROR")))) as ?integrityImpactV3 ) .

}
