#!/bin/bash

BUCKET=ontologies.ti-semantics.com
AWSARGS="--profile personal.iam"
WORKDIR=collections
XSLTDIR=xslt
CVEFILELIST=cve_file_list.html

function processCVE {
    baseurl=$1
    basename=$2

    #cd ${WORKDIR}/
    #wget -N ${baseurl}${basename}.xml.gz
    #cd ..
    wget -N -P ${WORKDIR}/ ${baseurl}${basename}.xml.gz
    if [ ${WORKDIR}/${basename}.xml.gz -nt ${WORKDIR}/${basename}.xml ]; then
	echo "[	gunzip -c ${WORKDIR}/${basename}.xml.gz > ${WORKDIR}/${basename}.xml ]"
	gunzip -c ${WORKDIR}/${basename}.xml.gz > ${WORKDIR}/${basename}.xml
	# Convert XML to RDF
	if [ ${WORKDIR}/${basename}.xml -nt  ${WORKDIR}/${basename}.rdf ] ; then
	    echo "[ saxon -s:${WORKDIR}/${basename}.xml -xsl:${XSLTDIR}/cve2rdf.xsl -o: ${WORKDIR}/${basename}.rdf BASEURI= ${baseurl}${basename}.xml ]"
	    saxon -s:${WORKDIR}/${basename}.xml -xsl:${XSLTDIR}/cve2rdf.xsl -o:${WORKDIR}/${basename}.rdf BASEURI=${baseurl}${basename}.xml
	    rapper -i rdfxml -o turtle ${WORKDIR}/${basename}.rdf > ${WORKDIR}/${basename}.ttl
	    gzip -k -f ${WORKDIR}/${basename}.rdf
	    gzip -k -f ${WORKDIR}/${basename}.ttl
	    aws $AWSARGS s3 cp ${WORKDIR}/${basename}.rdf.gz s3://${BUCKET}/${basename}.rdf.gz --content-type="application/gzip"
	    echo "uploaded to s3://${BUCKET}/${basename}.rdf.gz"
	    aws $AWSARGS s3 cp ${WORKDIR}/${basename}.ttl.gz s3://${BUCKET}/${basename}.ttl.gz --content-type="application/gzip"
	    echo "uploaded to s3://${BUCKET}/${basename}.ttl.gz"
	else
	    echo "${WORKDIR}/${basename}.rdf doesn't need updating"
	fi
    else
	echo "${basename}.xml was already decompressed"
    fi
    
    echo "<a href=\"http://${BUCKET}/${basename}.rdf.gz\" alt=\"${basename}\">${basename}.rdf.gz</a>" >> ${CVEFILELIST}
    echo "<a href=\"http://${BUCKET}/${basename}.ttl.gz\" alt=\"${basename}\">${basename}.ttl.gz</a>" >> ${CVEFILELIST}
    
}

#function processCVE {
#    baseurl=$1
#    basename=$2
#    
#    curl -s ${baseurl}${basename}.xml.gz | gunzip >${WORKDIR}/tmp.xml
#    
#    saxon -s:${WORKDIR}/tmp.xml -xsl:${XSLTDIR}/cve2rdf.xsl -o:${WORKDIR}/${basename}.rdf BASEURI=${baseurl}${basename}.xml
#
#    rapper -i rdfxml -o turtle ${WORKDIR}/${basename}.rdf > ${WORKDIR}/${basename}.ttl
#    gzip ${WORKDIR}/${basename}.rdf
#    gzip ${WORKDIR}/${basename}.ttl
#    rm ${WORKDIR}/tmp.xml
#    aws $AWSARGS s3 cp ${WORKDIR}/${basename}.rdf.gz s3://${BUCKET}/${basename}.rdf.gz --content-type="application/gzip"
#    aws $AWSARGS s3 cp ${WORKDIR}/${basename}.ttl.gz s3://${BUCKET}/${basename}.ttl.gz --content-type="application/gzip"
#    rm ${WORKDIR}/${basename}.rdf.gz ${WORKDIR}/${basename}.ttl.gz
#    echo "http://${BUCKET}/${basename}.rdf.gz"
#    echo "http://${BUCKET}/${basename}.ttl.gz"
#}

rm ${CVEFILELIST}
touch ${CVEFILELIST}

processCVE https://nvd.nist.gov/feeds/xml/cve/2.0/ nvdcve-2.0-2002
processCVE https://nvd.nist.gov/feeds/xml/cve/2.0/ nvdcve-2.0-2003
processCVE https://nvd.nist.gov/feeds/xml/cve/2.0/ nvdcve-2.0-2004
processCVE https://nvd.nist.gov/feeds/xml/cve/2.0/ nvdcve-2.0-2005
processCVE https://nvd.nist.gov/feeds/xml/cve/2.0/ nvdcve-2.0-2006
processCVE https://nvd.nist.gov/feeds/xml/cve/2.0/ nvdcve-2.0-2007
processCVE https://nvd.nist.gov/feeds/xml/cve/2.0/ nvdcve-2.0-2008
processCVE https://nvd.nist.gov/feeds/xml/cve/2.0/ nvdcve-2.0-2009
processCVE https://nvd.nist.gov/feeds/xml/cve/2.0/ nvdcve-2.0-2010
processCVE https://nvd.nist.gov/feeds/xml/cve/2.0/ nvdcve-2.0-2011
processCVE https://nvd.nist.gov/feeds/xml/cve/2.0/ nvdcve-2.0-2012
processCVE https://nvd.nist.gov/feeds/xml/cve/2.0/ nvdcve-2.0-2013
processCVE https://nvd.nist.gov/feeds/xml/cve/2.0/ nvdcve-2.0-2014
processCVE https://nvd.nist.gov/feeds/xml/cve/2.0/ nvdcve-2.0-2015
processCVE https://nvd.nist.gov/feeds/xml/cve/2.0/ nvdcve-2.0-2016
processCVE https://nvd.nist.gov/feeds/xml/cve/2.0/ nvdcve-2.0-2017
processCVE https://nvd.nist.gov/feeds/xml/cve/2.0/ nvdcve-2.0-2018
processCVE https://nvd.nist.gov/feeds/xml/cve/2.0/ nvdcve-2.0-2019
processCVE http://cve.mitre.org/data/downloads/ allitems
