BASEURL="https://nvd.nist.gov/feeds/json/cve/1.1"
BASENAME="nvdcve-1.1-recent"
NVDFILE="${BASENAME}.json.gz"
RAWRDFNVD="${BASENAME}.raw.ttl"

wget -N "${BASEURL}/${NVDFILE}"

gzcat ${NVDFILE} | java -jar ~/bin/json2rdf-1.0.1-jar-with-dependencies.jar ${BASEURL} | riot --formatted=TURTLE > ${RAWRDFNVD}




