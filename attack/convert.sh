
git submodule update --remote cti

function processSTIX {
    python attack2rdf.py --namespace="http://ti-semantics.com/$1#" cti/$1/$1.json $1.ttl
}

processSTIX enterprise-attack
processSTIX mobile-attack
processSTIX pre-attack

