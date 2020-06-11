#BASE <https://attack.mitre.org/pre-attack>
#BASE <https://attack.mitre.org/enterprise-attack>
PREFIX : <#>
PREFIX core: <http://ontologies.ti-semantics.com/core#>
PREFIX vuln: <http://ontologies.ti-semantics.com/vulnerability#>
PREFIX terms: <http://purl.org/dc/terms/>

CONSTRUCT {
  
  ?id_url a ?type ;
  
  # The description of this vulnerability in text form. We use DC terms for this.
  terms:description ?description_str ;
  
  terms:title ?name_str ;

  terms:created ?created_str;
	    
  terms:modified ?modified_str;
  
  terms:creator ?created_by ;
  
  # Create a reference object
#  vuln:reference [
#		   a vuln:Reference ;
#		   terms:id ?external_references_external_id_str ;
#		   terms:description ?external_references_description_str ;
#		   core:referenceURL ?external_references_url ;
#		   core:referenceSource ?external_references_source_name_str
#		 ] ;
	
.
} WHERE {
  
  [] :objects [
   		:created ?created_str;
	    
		:modified ?modified_str;
     
		:created_by_ref ?created_by_ref;
	
		:description ?description_str;

		:id ?id_str;

		:name ?name_str;

		:object_marking_refs ?object_marking_refs_str;

		:type ?type_str;

		:x_mitre_detectable_by_common_defenses ?x_mitre_detectable_by_common_defenses_str;

		:x_mitre_detectable_by_common_defenses_explanation ?x_mitre_detectable_by_common_defenses_explanation_str;

		:x_mitre_difficulty_for_adversary ?x_mitre_difficulty_for_adversary_str;

		:x_mitre_difficulty_for_adversary_explanation ?x_mitre_difficulty_for_adversary_explanation_str;

		:x_mitre_old_attack_id ?x_mitre_old_attack_id_str;
      
#		:external_references [	   
#				       :source_name ?external_references_source_name_str ;
				       
#				       :description ?external_references_description_str 
#				     ] ;
	      ] .
  
#  OPTIONAL { [] :external_id ?external_references_external_id_str }
#  OPTIONAL {
#    [] :url ?external_references_url_str .
#    BIND( URI(REPLACE(?external_references_url_str, " ", "")) AS ?external_references_url ) .
#  }
#  OPTIONAL {
#    [] :kill_chain_phases [
#				    
#			    :kill_chain_name ?kill_chain_phases_kill_chain_name_str ;
#			    
#			    :phase_name ?kill_chain_phases_phase_name_str
#			    
#			  ]
#  }
  
  
  #BIND( URI("https://attack.mitre.org/pre-attack#" + ?id_str) AS ?id_url ) .
  BIND( URI(":" + ?id_str) AS ?id_url ) .
  
  #BIND( URI("https://attack.mitre.org/pre-attack#"+?type_str) as ?type) .
  BIND( URI(":" + ?type_str) as ?type) .
  
  #BIND( URI("https://attack.mitre.org/pre-attack#"+?created_by_ref) as ?created_by)
  BIND( URI(":" + ?created_by_ref) as ?created_by)
  
}
