#!/bin/bash

BUCKET=ontologies.ti-semantics.com
AWSARGS="--profile personal.iam"
WORKDIR=collections
XSLTDIR=xslt
CVEFILELIST=cve_file_list.html

function processCVE {
    baseurl=$1
    basename=$2

    echo "[ saxon -s:${WORKDIR}/${basename}.xml -xsl:${XSLTDIR}/cve2rdf.xsl -o: ${WORKDIR}/${basename}.rdf BASEURI= ${baseurl}${basename}.xml ]"
    saxon -s:${WORKDIR}/${basename}.xml -xsl:${XSLTDIR}/cve2rdf.xsl -o:${WORKDIR}/${basename}.rdf BASEURI=${baseurl}${basename}.xml
    rapper -i rdfxml -o turtle ${WORKDIR}/${basename}.rdf > ${WORKDIR}/${basename}.ttl    
}

rm ${CVEFILELIST}
touch ${CVEFILELIST}
echo "<ul>" >> ${CVEFILELIST}

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
echo "</ul>" >> ${CVEFILELIST}

echo "Publishing data"

python publish.py
