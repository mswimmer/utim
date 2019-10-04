BASE <https://nvd.nist.gov/feeds/json/cve/1.1>
PREFIX : <#>
PREFIX core: <http://ontologies.ti-semantics.com/core>
PREFIX vuln: <http://ontologies.ti-semantics.com/vulnerability#>
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
		     core:referenceURL ?refURL 
		   ].
} WHERE {
  ?collection :cve [
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
		   ] .
  
  BIND( STRLANG(?descStr, ?descLangCode) AS ?description )
  # We create a URL out of the CWE string by prefixing it with the Mitre CWE URL and stripping out the 'CWE-' portion so that the URL actual resolves
  BIND( URI("https://cwe.mitre.org/data/definitions/"+STRAFTER(?cweStr, '-')) AS ?cwe )
  BIND( URI(?urlStr) AS ?refURL )
  BIND( URI("https://nvd.nist.gov/vuln/detail/"+?cveID) AS ?cveURL )

}
