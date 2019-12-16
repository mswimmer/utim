
git submodule update --remote cti

#function processSTIX {
#    python attack2rdf.py --namespace="http://ti-semantics.com/attack#" --type $2 cti/$1/$1.json $1.ttl
#}

#processSTIX enterprise-attack enterprise
#processSTIX mobile-attack mobile
#processSTIX pre-attack pre

BASEURL="https://attack.mitre.org"
BASEDIR="./cti"

#BASENAME="nvdcve-1.1-recent"
#NVDFILE="${BASENAME}.json.gz"
#RAWRDFNVD="${BASENAME}.raw.ttl"
#RDFNVD="${BASENAME}.ttl"

function processATTACK {
    cat $1 | java -jar ~/bin/json2rdf-1.0.1-jar-with-dependencies.jar $3 | riot --formatted=TURTLE > $2.raw.ttl
    #cat $1 | java -jar ~/bin/json2rdf-1.0.1-jar-with-dependencies.jar $3 > tmp.ttl
    echo "$2.raw.ttl created"

    arq --query attack2rdf.ql --data=$2.raw.ttl > $2.ttl
    rapper -i turtle -o rdfxml $2.ttl > $2.rdf
    echo "$2 produced"

}

#processATTACK ${BASEDIR}/enterprise-attack/enterprise-attack.json enterprise-attack ${BASEURL}/enterprise-attack
processATTACK ${BASEDIR}/pre-attack/pre-attack.json pre-attack ${BASEURL}/pre-attack
#processATTACK ${BASEDIR}/mobile-attack/mobile-attack.json mobile-attack ${BASEURL}/mobile-attack

python3 test.py
