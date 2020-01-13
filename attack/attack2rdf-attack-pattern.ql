BASE <https://attack.mitre.org/pre-attack#>
PREFIX : <#>
PREFIX core: <http://ontologies.ti-semantics.com/core#>
PREFIX vuln: <http://ontologies.ti-semantics.com/vulnerability#>
PREFIX cti: <http://ontologies.ti-semantics.com/cti#>
PREFIX xsd:  <http://www.w3.org/2001/XMLSchema#>
PREFIX terms: <http://purl.org/dc/terms/>

CONSTRUCT {
  ?id_url a cti:AttackPattern;
	  terms:description ?description;
          terms:title ?name;
          terms:created ?created;
          terms:modified ?modified;
          terms:creator ?created_by;
          terms:rightsHolder ?object_marking_refs;
          :x_mitre_difficulty_for_adversary ?x_mitre_difficulty_for_adversary;
          :x_mitre_difficulty_for_adversary_explanation ?x_mitre_difficulty_for_adversary_explanation;
          :x_mitre_detectable_by_common_defenses ?x_mitre_detectable_by_common_defenses;
          :x_mitre_detectable_by_common_defenses_explanation ?x_mitre_detectable_by_common_defenses_explanation ;
          :x_mitre_old_attack_id ?x_mitre_old_attack_id_str .
  # create a kill chain phase object
  ?id_url cti:killChainPhase [
			       a cti:KillChainPhase ;
			       cti:phaseName ?kill_chain_phases_phase_name ;
			       cti:killChainName ?kill_chain_phases_kill_chain_name_str
			     ] .
  # Create a reference object
  ?id_url core:reference [
			   a core:Reference ;
			   terms:id ?external_references_external_id ;
			   terms:description ?external_references_description_str ;
			   core:referenceURL ?external_references_url ;
			   core:referenceSource ?external_references_source_name
  			 ] .
  
} WHERE {
  ?objs :objects ?ap .
  ?ap :type "attack-pattern"; # only match attack-pattern objects
      :x_mitre_version "1.0"; # make sure this is the format that we expect
      :created ?created_str;
      :modified ?modified_str;
      :created_by_ref ?created_by_ref;
      :description ?description_str;
      :id ?id_str;
      :name ?name_str;
      :object_marking_refs ?object_marking_refs_str;
      :x_mitre_detectable_by_common_defenses ?x_mitre_detectable_by_common_defenses_str;
      :x_mitre_detectable_by_common_defenses_explanation ?x_mitre_detectable_by_common_defenses_explanation_str;
      :x_mitre_difficulty_for_adversary ?x_mitre_difficulty_for_adversary_str;
      :x_mitre_difficulty_for_adversary_explanation ?x_mitre_difficulty_for_adversary_explanation_str;
      :x_mitre_old_attack_id ?x_mitre_old_attack_id_str .
  
  OPTIONAL {
    {
      ?ap :external_references [
				 :external_id ?external_references_external_id_str ;
				 :source_name ?external_references_source_name_str ;
				 :url ?external_references_url_str 				       
			       ] .
      BIND( URI(REPLACE(?external_references_url_str, " ", "")) AS ?external_references_url ) .
      BIND( STRDT(?external_references_external_id_str, xsd:token) AS ?external_references_external_id ) .
    } UNION {
      ?ap :external_references [
				 :description ?external_references_description_str ;
				 :source_name ?external_references_source_name_str ;
			       ] .
    }
    BIND( STRDT(?external_references_source_name_str, xsd:token) AS  ?external_references_source_name ) .
  }

  OPTIONAL {
    ?ap :kill_chain_phases ?kc .
    ?kc :kill_chain_name ?kill_chain_phases_kill_chain_name_str;
	:phase_name ?kill_chain_phases_phase_name_str .
    BIND( STRDT(?kill_chain_phases_phase_name_str, xsd:token) AS ?kill_chain_phases_phase_name) .
  }
  
  BIND( URI("https://attack.mitre.org/pre-attack#" + ?id_str) AS ?id_url ) .
  BIND( URI("https://attack.mitre.org/pre-attack#" + ?created_by_ref) as ?created_by) .
  BIND( STRDT(?created_str, xsd:dateTime) as ?created) .
  BIND( STRDT(?modified_str, xsd:dateTime) as ?modified) .
  BIND( STRLANG(?description_str, "en") as ?description) .
  BIND( STRLANG(?name_str, "en") as ?name) .
  BIND( URI("https://attack.mitre.org/pre-attack#" + ?object_marking_refs_str) as ?object_marking_refs) .
  BIND( STRDT(IF(?x_mitre_detectable_by_common_defenses_str="yes", "true", "false"), xsd:boolean) as ?x_mitre_detectable_by_common_defenses) .
  BIND( STRDT(IF(?x_mitre_difficulty_for_adversary_str="yes", "true", "false"), xsd:boolean) as ?x_mitre_difficulty_for_adversary) .
  BIND( STRLANG(?x_mitre_detectable_by_common_defenses_explanation_str, "en") as ?x_mitre_detectable_by_common_defenses_explanation ) .
  BIND( STRLANG(?x_mitre_difficulty_for_adversary_explanation_str, "en") as ?x_mitre_difficulty_for_adversary_explanation ) .
}
