
git submodule update --remote cti

function processSTIX {
    python attack2rdf.py --namespace="http://ti-semantics.com/attack#" --type $2 cti/$1/$1.json $1.ttl
}

processSTIX enterprise-attack enterprise
processSTIX mobile-attack mobile
processSTIX pre-attack pre

