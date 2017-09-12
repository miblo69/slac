<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="/">
<xsl:value-of select="report/title"/>
Input Files: <xsl:value-of select="report/inputfiles"/>
Log Start: <xsl:value-of select="report/logdatestart"/>
Log Stop:  <xsl:value-of select="report/logdateend"/>
nr of analyzed rows: <xsl:value-of select="report/rowsanalysed"/>
nr of unique IP-addresses: <xsl:value-of select="report/nripaddr"/>
Performance: <xsl:value-of select="report/perf"/>
Rows identified as: <xsl:value-of select="report/nripaddr"/>


</xsl:template>

</xsl:stylesheet>
