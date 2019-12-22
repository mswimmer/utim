
BASEURL="https://attack.mitre.org"
BASEDIR="./tests"

function processATTACK {
    cat $1.json | java -jar ~/bin/json2rdf-1.0.1-jar-with-dependencies.jar $2 | riot --formatted=TURTLE > $1.raw.ttl

    echo "$1.raw.ttl created"

    arq --query attack2rdf-attack-pattern.ql --data=$1.raw.ttl > $1.ttl
    rapper -i turtle -o rdfxml $1.ttl > $1.rdf
    echo "$1.rdf produced"

}

processATTACK ${BASEDIR}/pre-attack-attack-pattern--0649fc36-72a0-40a0-a2f9-3fc7e3231ad6\
	      ${BASEURL}/pre-attack
processATTACK ${BASEDIR}/pre-attack-attack-pattern--773950e1-090c-488b-a480-9ff236312e31 \
	      ${BASEURL}/pre-attack

python3 ${BASEDIR}/construct_test.py
