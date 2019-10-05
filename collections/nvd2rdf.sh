BASEURL="https://nvd.nist.gov/feeds/json/cve/1.1"
BASENAME="nvdcve-1.1-recent"
NVDFILE="${BASENAME}.json.gz"
RAWRDFNVD="${BASENAME}.raw.ttl"
RDFNVD="${BASENAME}.ttl"

wget -N "${BASEURL}/${NVDFILE}"

gzcat ${NVDFILE} | java -jar ~/bin/json2rdf-1.0.1-jar-with-dependencies.jar ${BASEURL} | riot --formatted=TURTLE > ${RAWRDFNVD}


arq --query nvd1.1jsonrdf2rdf.ql --data=${RAWRDFNVD} > ${RDFNVD}




