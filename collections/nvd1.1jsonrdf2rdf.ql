BASE <https://nvd.nist.gov/feeds/json/cve/1.1>
PREFIX : <#>
PREFIX core: <http://ontologies.ti-semantics.com/core>
PREFIX vuln: <http://ontologies.ti-semantics.com/vulnerability#>
PREFIX score: <http://ontologies.ti-semantics.com/score>
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
  score:hasBaseScore ?baseScoreV2 ;
  score:hasAccessVector ?accessVectorV2 ;
  score:hasAccessComplexity ?accessComplexityV2 ;
  score:hasIntegrityImpact ?integrityImpactV2 
	
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
					:vectorString ?vectorStringV2 ;
					:availabilityImpact ?availabilityImpactV2 ;
					:authentication ?authenticationV2 ;
					:version ?versionV2 ;
					:confidentialityImpact ?confidentialityImpactV2 ;
					:baseScore ?baseScoreV2 ;
					:accessVector ?accessVectorV2 ;
					:accessComplexity ?accessComplexityV2 ;
					:integrityImpact ?integrityImpactV2 
				      ] 
			    ]
	    ]
  ].
  
  BIND( STRLANG(?descStr, ?descLangCode) AS ?description )
  # We create a URL out of the CWE string by prefixing it with the Mitre CWE URL and stripping out the 'CWE-' portion so that the URL actual resolves
  BIND( URI("https://cwe.mitre.org/data/definitions/"+STRAFTER(?cweStr, '-')) AS ?cwe )
  BIND( URI(?urlStr) AS ?refURL )
  BIND( URI("https://nvd.nist.gov/vuln/detail/"+?cveID) AS ?cveURL )

}
