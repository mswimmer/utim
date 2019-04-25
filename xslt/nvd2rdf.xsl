<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE xsl:stylesheet [
  <!ENTITY rdf 'http://www.w3.org/1999/02/22-rdf-syntax-ns#'>
  <!ENTITY rdfs 'http://www.w3.org/2000/01/rdf-schema#'>
]>
<xsl:stylesheet version="2.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
    xmlns:rdfs="http://www.w3.org/2000/01/rdf-schema#"
    xmlns:dc="http://purl.org/dc/terms/"
    xmlns:fn="http://ontologies.ti-semantics.com/fn"

    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 

    xmlns:cpe-lang="http://cpe.mitre.org/language/2.0" 
    xmlns:scapvuln="http://scap.nist.gov/schema/vulnerability/0.4" 
    xmlns:scapcvss="http://scap.nist.gov/schema/cvss-v2/0.2"
    
    xmlns:cvefeed="http://cve.mitre.org/cve/downloads/1.0"
    xmlns:nvdfeed="http://scap.nist.gov/schema/feed/vulnerability/2.0"
    xmlns:nvd1feed="http://nvd.nist.gov/feeds/cve/1.2"
    
    xmlns:vuln="http://ontologies.ti-semantics.com/vulnerability#"
    xmlns:core="http://ontologies.ti-semantics.com/core#"
    >
  
  <xsl:include href="cvss2rdf.xsl"/>
  <xsl:include href="cpe-lang2rdf.xsl"/>
  
  <!--xsl:variable name="URI">http://nvd.nist.gov/nvd-feed</xsl:variable-->
  <xsl:param name="BASEURI"/>
  <xsl:variable name="VULN">http://ontologies.ti-semantics.com/vulnerability#</xsl:variable>

  <xsl:function name="fn:datetype">
    <xsl:param name="datestr"/>
    <xsl:value-of select="if(string(normalize-space($datestr)) castable as xsd:dateTime) then 'xsd:dateTime' else if(string(normalize-space($datestr)) castable as xsd:date) then 'xsd:date' else 'rdfs:Literal'" />
  </xsl:function>

  <xsl:function name="fn:cveURI">
    <xsl:param name="entryId"/>
    <xsl:value-of select="$BASEURI" />#<xsl:value-of select="$entryId"/>
  </xsl:function>

  <xsl:function name="fn:nvd12URI">
    <xsl:param name="entryId"/>
    <xsl:value-of select="$BASEURI" />#<xsl:value-of select="$entryId"/>
  </xsl:function>
  
  <xsl:function name="fn:nvd20URI">
    <xsl:param name="entryId"/>
    <xsl:value-of select="$BASEURI" />#<xsl:value-of select="$entryId"/>
  </xsl:function>
  
  <xsl:output method="xml" encoding="UTF-8"/>
  <xsl:strip-space elements="*" />
  <xsl:output indent="yes" />

  <!-- NVD 1 root -->
  <xsl:template match="/nvd1feed:nvd">
    <rdf:RDF>
      <xsl:apply-templates />

      <rdf:Description rdf:type="{$VULN}NVD12Catalog">
	<xsl:for-each select="//nvd1feed:entry">
	  <vuln:vulnerability>
	    <rdf:Description rdf:about="{fn:nvd12URI(@name)}"
		rdf:type="{$VULN}NVD12Vulnerability" />
	  </vuln:vulnerability>
	</xsl:for-each>
      </rdf:Description>

    </rdf:RDF>
  </xsl:template>

  <!-- NVD 2 root -->
  <xsl:template match="/nvdfeed:nvd">
    <rdf:RDF>
      <xsl:apply-templates />
      
      <rdf:Description rdf:type="{$VULN}NVD20Catalog">
	<xsl:for-each select="//nvdfeed:entry">
	  <vuln:vulnerability>
	    <rdf:Description rdf:about="{fn:nvd20URI(@id)}"
		rdf:type="{$VULN}NVD20Vulnerability" />
	  </vuln:vulnerability>
	</xsl:for-each>
      </rdf:Description>
    </rdf:RDF>
  </xsl:template>

  <!-- CVE root -->
  <xsl:template match="/cvefeed:cve">
    <rdf:RDF>
      <xsl:apply-templates />

      <rdf:Description rdf:type="{$VULN}NVD12Catalog">
	<xsl:for-each select="//cvefeed:item">
	  <vuln:vulnerability>
	    <rdf:Description rdf:about="{fn:cveURI(@name)}"
		rdf:type="{$VULN}CVEVulnerability" />
	  </vuln:vulnerability>
	</xsl:for-each>
      </rdf:Description>

    </rdf:RDF>
  </xsl:template>
  
  <xsl:template match="*">
    <xsl:message terminate="no">
      WARNING: Unmatched element: <xsl:value-of select="name()"/>
    </xsl:message>
    <xsl:apply-templates/>
  </xsl:template>

  <!-- NVD 2.0 entry -->
  <xsl:template match="//nvdfeed:entry">
    <rdf:Description rdf:about="{fn:nvd20URI(@id)}" rdf:type="{$VULN}NVD20Vulnerability" >

      <vuln:id>
        <xsl:value-of select="@id"/>
      </vuln:id>
      
      <rdfs:comment>
        <xsl:value-of select="scapvuln:summary"/>
      </rdfs:comment>

      <xsl:apply-templates select="scapvuln:cwe" />
      
      <vuln:published rdf:datatype="{fn:datetype(scapvuln:published-datetime)}">
        <xsl:value-of select="scapvuln:published-datetime"/>
      </vuln:published>
      
      <vuln:modified rdf:datatype="{fn:datetype(scapvuln:last-modified-datetime)}">
        <xsl:value-of select="scapvuln:last-modified-datetime"/>
      </vuln:modified>

      <xsl:apply-templates select="scapvuln:vulnerable-software-list" />
      <xsl:apply-templates select="scapvuln:references" />
      <xsl:apply-templates select="scapvuln:cvss" />
      <xsl:apply-templates select="scapvuln:vulnerable-configuration" />

      <!-- TODO: not tested -->
      <xsl:apply-templates select="scapvuln:assessment_check" />
      <xsl:apply-templates select="scapvuln:scanner" />
      
    </rdf:Description>
  </xsl:template>
  
  <xsl:template match="scapvuln:cwe">
    <vuln:weakness>
      <xsl:variable name="CWE">http://cve.mitre.org/data/<xsl:value-of select="@id" /></xsl:variable>
      <rdf:Description rdf:about="{$CWE}" rdf:type="core:Weakness" />
    </vuln:weakness>
  </xsl:template>
  
   <!-- NVD 1.2 entry -->
  <xsl:template match="//nvd1feed:entry">
    <xsl:variable name="TYPE">
      <xsl:choose>
        <xsl:when test="@type='CAN'"><xsl:value-of select="$VULN" />CandidateVulnerability</xsl:when>
        <xsl:when test="@type='CVE'"><xsl:value-of select="$VULN" />NVD12Vulnerability</xsl:when>
	<xsl:otherwise><xsl:value-of select="$VULN" />Vulnerability</xsl:otherwise>
      </xsl:choose>
    </xsl:variable>
    
    <rdf:Description  rdf:about="{fn:nvd12URI(@name)}" rdf:type="{$TYPE}">

      <vuln:id>
        <xsl:value-of select="@name"/>
      </vuln:id>

      <rdfs:comment>
        <xsl:value-of select="nvd1feed:desc/nvd1feed:descript"/>
      </rdfs:comment>

      <vuln:published rdf:datatype="{fn:datetype(@published)}">
        <xsl:value-of select="@published"/>
      </vuln:published>
      
      <vuln:modified rdf:datatype="{fn:datetype(@modified)}">
        <xsl:value-of select="@modified"/>
      </vuln:modified>

      <xsl:apply-templates select="nvd1feed:refs" />
      <!-- we will skip votes and comments because these were
	   eventually phased out -->
    </rdf:Description>
  </xsl:template>
 
  <!-- CVE Item (entry) -->
  <xsl:template match="//cvefeed:item">
    <rdf:Description  rdf:about="{fn:cveURI(@name)}">
      <rdf:type>
	<xsl:choose>
          <xsl:when test="@type='CAN'">
            <rdf:Description rdf:about="{$VULN}CandidateEntry" />
          </xsl:when>
          <xsl:when test="@type='CVE'">
            <rdf:Description rdf:about="{$VULN}CVEEntry" />
          </xsl:when>
	</xsl:choose>
      </rdf:type>

      <vuln:id>
        <xsl:value-of select="@name"/>
      </vuln:id>

      <rdfs:comment>
        <xsl:value-of select="cvefeed:desc"/>
      </rdfs:comment>

      <xsl:apply-templates select="cvefeed:refs" />
      <!-- we will skip votes and comments because these were
	   eventually phased out -->
    </rdf:Description>
  </xsl:template>
  
  <xsl:template match="scapvuln:vulnerable-software-list">
      <xsl:apply-templates select="scapvuln:product" />
  </xsl:template>
  
  <xsl:template match="scapvuln:product">
    <vuln:vulnerableProduct>
     <rdf:Description rdf:about="urn:X-{text()}" rdf:type="{$CORE}Platform" />
    </vuln:vulnerableProduct>
  </xsl:template>
  
  <xsl:template match="scapvuln:vulnerable-configuration">
    <vuln:vulnerableConfiguration>
      <xsl:apply-templates select="cpe-lang:logical-test" />
    </vuln:vulnerableConfiguration>
  </xsl:template>
  
  <!-- TODO: utilize the xml:lang attribute to set the language -->
  <xsl:template match="scapvuln:references">
    <vuln:reference>
      <xsl:variable name="TYPE">
        <xsl:choose>
          <xsl:when test="starts-with(@reference_type, 'PATCH')">PatchReference</xsl:when>
          <xsl:when test="starts-with(@reference_type, 'VENDOR_ADVISORY')">VendorAdvisoryReference</xsl:when>
          <xsl:otherwise>Reference</xsl:otherwise>
        </xsl:choose>
      </xsl:variable>
      <xsl:variable name="TYPE_URI"><xsl:value-of select="concat($VULN,$TYPE)" /></xsl:variable>
      <rdf:Description rdf:type="{$TYPE_URI}">
        <xsl:if test="@deprecated">
          <vuln:referenceDeprecated rdf:datatype="xsd:boolean">
            <xsl:value-of select="@deprecated" />
          </vuln:referenceDeprecated>
        </xsl:if>
        <xsl:apply-templates select="scapvuln:source" />
        <xsl:apply-templates select="scapvuln:reference" />
      </rdf:Description>
    </vuln:reference>
  </xsl:template>
  
  <xsl:template match="nvd1feed:refs">
    <xsl:apply-templates select="nvd1feed:ref" />
  </xsl:template>
    
  <xsl:template match="nvd1feed:ref">
    <vuln:reference>
      <rdf:Description>
        <rdf:type>
          <rdf:Description rdf:about="{$VULN}Reference" />
        </rdf:type>
	
        <vuln:referenceSource>
	  <xsl:value-of select="@source"/>
	</vuln:referenceSource>
	
        <xsl:apply-templates select="scapvuln:reference" />
	<xsl:if test="@url">
	  <vuln:referenceURL rdf:datatype="xsd:anyURI">
	    <xsl:value-of select="@url" />
	  </vuln:referenceURL>
	</xsl:if>
	<vuln:referenceTitle xml:lang="en">
	  <xsl:value-of select="text()" />
	</vuln:referenceTitle>
	
      </rdf:Description>
    </vuln:reference>
  </xsl:template>

  <xsl:template match="cvefeed:refs">
    <xsl:apply-templates select="cvefeed:ref" />
  </xsl:template>
    
  <xsl:template match="cvefeed:ref">
    <vuln:reference>
      <rdf:Description>
        <rdf:type>
          <rdf:Description rdf:about="{$VULN}Reference" />
        </rdf:type>
	
        <vuln:referenceSource>
	  <xsl:value-of select="@source"/>
	</vuln:referenceSource>
	
        <xsl:apply-templates select="scapvuln:reference" />
	<xsl:if test="@url">
	  <vuln:referenceURL rdf:datatype="xsd:anyURI">
	    <xsl:value-of select="@url" />
	  </vuln:referenceURL>
	</xsl:if>

	<vuln:referenceTitle xml:lang="en">
	  <xsl:value-of select="text()" />
	</vuln:referenceTitle>
	
      </rdf:Description>
    </vuln:reference>
  </xsl:template>
  
  <xsl:template match="scapvuln:reference">
    <vuln:referenceURL rdf:datatype="xsd:anyURI">
      <xsl:value-of select="@href"/>
    </vuln:referenceURL>
    <vuln:referenceTitle xml:lang="{@xml:lang}">
      <xsl:value-of select="text()"/>
    </vuln:referenceTitle>
  </xsl:template>

  <xsl:template match="scapvuln:source">
    <vuln:referenceSource>
      <xsl:value-of select="text()"/>
    </vuln:referenceSource>
  </xsl:template>

  <xsl:template match="scapvuln:cvss">
    <vuln:score>
      <xsl:apply-templates select="scapcvss:base_metrics" />
    </vuln:score>
  </xsl:template>
  
  <!-- vuln:assessment_check -->
  <xsl:template match="scapvuln:assessment_check">
    <vuln:assessmentCheck>
      <rdf:Description>
        <vuln:assessmentCheckName>
          <xsl:value-of select="@name"/>
        </vuln:assessmentCheckName>
        <vuln:assessmentCheckURL>
          <xsl:value-of select="@href"/>
        </vuln:assessmentCheckURL>
      </rdf:Description>
    </vuln:assessmentCheck>
  </xsl:template>

  <!-- vuln:scanner -->
  <xsl:template match="scapvuln:scanner">
    <vuln:scanner>
      <rdf:Description>
        <xsl:apply-templates select="scapvuln:definition" />
      </rdf:Description>
    </vuln:scanner>
  </xsl:template>
  
  <!-- vuln:definition -->
  <xsl:template match="scapvuln:definition">
    <rdf:Description>
      <vuln:definitionName>
        <xsl:value-of select="@name"/>
      </vuln:definitionName>
      <vuln:definitionURL>
        <xsl:value-of select="@href"/>
      </vuln:definitionURL>
      <vuln:definitionSystem>
        <xsl:value-of select="@system"/>
      </vuln:definitionSystem>
    </rdf:Description>
  </xsl:template>

</xsl:stylesheet>
