<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xsl:stylesheet [
<!ENTITY rdf 'http://www.w3.org/1999/02/22-rdf-syntax-ns#'>
<!ENTITY rdfs 'http://www.w3.org/2000/01/rdf-schema#'>
]>
<xsl:stylesheet
    version="2.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:xs="http://www.w3.org/2001/XMLSchema"
    xmlns:cpe-dict="http://cpe.mitre.org/dictionary/2.0"
    xmlns:cpe-23="http://scap.nist.gov/schema/cpe-extension/2.3"
    xmlns:vuln="http://scap.nist.gov/schema/vulnerability/0.4"
    xmlns:platform="http://ontologies.ti-semantics.com/platform#"
    xmlns:core="http://ontologies.ti-semantics.com/core#"
    xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
    xmlns:rdfs="http://www.w3.org/2000/01/rdf-schema#"
    >
  
  <xsl:variable
      name="PLATFORM">http://ontologies.ti-semantics.com/platform#</xsl:variable>
  <xsl:variable
      name="CORE">http://ontologies.ti-semantics.com/core#</xsl:variable>
  
  <xsl:output method="xml" />
  <xsl:strip-space elements="*" />
  <xsl:output indent="yes" />

  <xsl:template match="cpe-dict:cpe-list">
    <rdf:RDF>
      <xsl:apply-templates />
    </rdf:RDF>
  </xsl:template>

  <xsl:template match="cpe-dict:generator">
    <rdf:Description
	rdf:type="{$PLATFORM}PlatformCatalog">
      <rdfs:label><xsl:value-of select="cpe-dict:product_name" /></rdfs:label>
      <platform:generationDate
	  rdf:datatype="xsd:dateTime"><xsl:value-of select="cpe-dict:timestamp"
	  /></platform:generationDate>
      <platform:generatorName><xsl:value-of select="cpe-dict:product_name"
      /></platform:generatorName>
      <platform:generatorVersion><xsl:value-of select="cpe-dict:product_version"
      /></platform:generatorVersion>
      <platform:generatorSchemaVersion><xsl:value-of select="cpe-dict:schema_version"
      /></platform:generatorSchemaVersion>      
      <xsl:for-each select="//cpe-dict:cpe-item">
	<platform:platform>
	  <rdf:Description
	      rdf:about="urn:X-{@name}" 
	      rdf:type="{$CORE}Platform" />
	</platform:platform>
      </xsl:for-each>
    </rdf:Description>
  </xsl:template>
  
  <xsl:template match="cpe-dict:cpe-item">
    <rdf:Description
	rdf:about="urn:X-{@name}" 
	rdf:type="{$CORE}Platform">
      <platform:cpe22uri>
	<xsl:value-of select="@name" />
      </platform:cpe22uri>
      <core:deprecated  rdf:datatype="xsd:boolean">
	<xsl:value-of select="if (@deprecated = 'true') then 'true' else 'false'" />
      </core:deprecated>
      <xsl:if test="@deprecation_date">
	<core:deprecationDate  rdf:datatype="xsd:dateTime">
	  <xsl:value-of select="@deprecated" />
	</core:deprecationDate>	
      </xsl:if>
      <xsl:apply-templates select="cpe-dict:title" />
      <xsl:apply-templates select="cpe-dict:references" />
      <xsl:apply-templates select="cpe-23:cpe23-item" />
    </rdf:Description>
  </xsl:template>

  <xsl:template match="cpe-dict:title">
    <rdfs:label xml:lang="{@xml:lang}">
      <xsl:value-of select="text()" />
    </rdfs:label>
  </xsl:template>

  <xsl:template match="cpe-dict:references">
      <xsl:apply-templates select="cpe-dict:reference" />
  </xsl:template>

  <xsl:template match="cpe-dict:reference">
    <platform:reference>
      <rdf:Description
	  rdf:type="{$PLATFORM}Reference">
	<platform:referenceURL rdf:datatype="xsd:anyURI">
	  <xsl:value-of select="@href" />
	</platform:referenceURL>
	<rdfs:label>
	  <xsl:value-of select="text()" />
	</rdfs:label>
      </rdf:Description>
    </platform:reference>
  </xsl:template>

    <xsl:template match="cpe-23:cpe23-item">
      <platform:cpe23uri>
	<xsl:value-of select="@name" />
      </platform:cpe23uri>
       <xsl:apply-templates select="cpe-23:deprecation" />
    </xsl:template>

    <xsl:template match="cpe-23:deprecation">
      <!--xsl:variable
	  name="DATE"><xsl:value-of select="@date" /></xsl:variable-->
      <xsl:apply-templates select="cpe-23:deprecated-by">
	<xsl:with-param name="DATE" select="@date" />
      </xsl:apply-templates>
    </xsl:template>
    
    <xsl:template match="cpe-23:deprecated-by">
      <xsl:param name="DATE" />
      <xsl:variable
	  name="NAME"><xsl:value-of select="@name" /></xsl:variable>

      <xsl:variable name="TYPE">
	<xsl:choose>
	  <xsl:when test="@type='NAME_CORRECTION'">NameCorrection</xsl:when>
	  <xsl:otherwise>Deprecation</xsl:otherwise>
	</xsl:choose>
      </xsl:variable>
      
      <platform:deprecation>
	<rdf:Description
	    rdf:type="{$PLATFORM}{$TYPE}">
	  <platform:cpe23uri><xsl:value-of select="$NAME" /></platform:cpe23uri>
	  <platform:deprecationDate
	      rdf:datatype="xsd:dateTime"><xsl:value-of select="$DATE"
	      />
	  </platform:deprecationDate>
	</rdf:Description>
      </platform:deprecation>
      
    </xsl:template>
</xsl:stylesheet>
