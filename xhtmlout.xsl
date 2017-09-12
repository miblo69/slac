<html
        xsl:version="1.0"
        xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
        xmlns="http://www.w3.org/TR/xhtml1/strict">


<h1><xsl:value-of select="report/reporttitle"/></h1>
<xsl:for-each select="html/report/inputfiles">
<br/>Input Files:<xsl:value-of select="file"/>
</xsl:for-each>
<br/>Output Files:<xsl:value-of select="html/report/outputfile"/>
<br/>Exec Start:<xsl:value-of select="html/report/execstart"/>
<br/>Exec Stop: <xsl:value-of select="html/report/execstop"/> 
<br/>Rows analyzed: <xsl:value-of select="html/report/rowsanalysed"/>
<br/>Nr IP-addresses: <xsl:value-of select="html/report/nripaddr"/>
<br/>Performance: <xsl:value-of select="html/report/perf"/>
<br/>Name Resoultion Off: <xsl:value-of select="html/report/nameresoff"/>
<br/>
<br/>Rep:
<br/><h2><xsl:value-of select="html/report/logformats/title"/></h2>
<xsl:for-each select="html/report/logformats/rec">
<br/><xsl:value-of select="format"/>:<xsl:value-of select="nrfound"/> 
</xsl:for-each>
<br/> 

<br/><h2><xsl:value-of select="html/report/hitsperhour/title"/></h2>
<table border="1">
<tr><th>Hour</th>
<th>Hits</th>
</tr>
<xsl:for-each select="html/report/hitsperhour/rec">
<tr>
<td><xsl:value-of select="hour"/></td>
<td><xsl:value-of select="hits"/></td>
</tr>
</xsl:for-each>
</table>

<br/><h2><xsl:value-of select="html/report/dangerousfiles/title"/></h2>      
<xsl:for-each select="html/report/dangerousfiles/rec">
<br/><xsl:value-of select="count"/>:<xsl:value-of select="srcip"/>:<xsl:value-of select="url"/>
                                    
</xsl:for-each>


<br/><h2><xsl:value-of select="html/report/unauthorized/title"/></h2>
<table border="1">
<xsl:for-each select="html/report/unauthorized/rec">
<tr>
<td><xsl:value-of select="count"/></td>
<td><xsl:value-of select="status"/></td>
<td><xsl:value-of select="srcip"/></td>
<td><xsl:value-of select="user"/></td>
<td><xsl:value-of select="url"/></td>
</tr>
</xsl:for-each>
</table>
<br/>


<br/><h2><xsl:value-of select="html/report/logged_in_users/title"/></h2>
<table border="1">
<xsl:for-each select="html/report/logged_in_users/rec">
<tr>
<td><xsl:value-of select="count"/></td>
<td><xsl:value-of select="user"/></td>
</tr>
</xsl:for-each>
</table>

<br/>


<br/><h2><xsl:value-of select="html/report/logged_in_users_per_ip/title"/></h2>
<table border="1">
<tr><th>Count</th>        
<th>User</th>
<th>Src IP</th>
<th>FQDN</th></tr> 
<xsl:for-each select="html/report/logged_in_users_per_ip/rec">
<tr>
<td><xsl:value-of select="count"/></td>
<td><xsl:value-of select="user"/></td>
<td><xsl:value-of select="srcip"/></td>
<td><xsl:value-of select="fqdn"/></td>
</tr>
</xsl:for-each>
</table>
<br/>


<h2><xsl:value-of select="html/report/statuscodes/title"/></h2>
<table border="1">
<tr><th>Count</th>
<th>Status</th>
<th>Status Desc</th></tr>
<xsl:for-each select="html/report/statuscodes/rec">
<tr>
<td align="right"><xsl:value-of select="count"/></td>
<td><xsl:value-of select="status"/></td>
<td><xsl:value-of select="statusname"/></td>
</tr>
</xsl:for-each>
</table>
<br/>

<h2><xsl:value-of select="html/report/httpmethods/title"/></h2>
<table border="1">
<tr>
<th>Count</th>
<th>Method</th>
</tr>
<xsl:for-each select="html/report/httpmethods/rec">
<tr>
<td align="right"><xsl:value-of select="count"/></td>
<td><xsl:value-of select="method"/></td>
</tr>
</xsl:for-each>
</table>
<br/>


<h2><xsl:value-of select="html/report/httpversions/title"/></h2>            
<table border="1">
<tr>
<th>Count</th>
<th>Version</th>
</tr>
<xsl:for-each select="html/report/httpversions/rec">
<tr>
<td align="right"><xsl:value-of select="count"/></td>
<td><xsl:value-of select="version"/></td>
</tr>
</xsl:for-each>
</table>
<br/>


<h2><xsl:value-of select="html/report/illegalhttp/title"/></h2>       
<table border="1">
<tr>
<th>Count</th>
<th>HTTP String</th>
<th>Src IP</th>
<th>FQDN</th>
</tr>
<xsl:for-each select="html/report/illegalhttp/rec">
<tr>
<td align="right"><xsl:value-of select="count"/></td>
<td><xsl:value-of select="httpstr"/></td>
<td><xsl:value-of select="srcip"/></td>
<td><xsl:value-of select="fqdn"/></td>
</tr>
</xsl:for-each>
</table>
<br/>


<h2><xsl:value-of select="html/report/tophitters/title"/></h2>               
<table border="1">
<tr>
<th>Rank</th>
<th>Count</th>
<th>Src IP</th>
<th>FQDN</th>
</tr>
<xsl:for-each select="html/report/tophitters/rec">
<tr>
<td align="right"><xsl:value-of select="rank"/></td>
<td align="right"><xsl:value-of select="count"/></td>
<td align="left"><xsl:value-of select="srcip"/></td>
<td><xsl:value-of select="fqdn"/></td>
</tr>
</xsl:for-each>
</table>
<br/>

<h2><xsl:value-of select="html/report/errors4xx/title"/></h2>
<table border="1">
<tr>
<th>Count</th>
<th>HTTP Status</th>
<th>URL</th>
</tr>
<xsl:for-each select="html/report/errors4xx/rec">
<tr>
<td align="right"><xsl:value-of select="count"/></td>
<td align="left"><xsl:value-of select="httpstatus"/></td>
<td><xsl:value-of select="url"/></td>
</tr>
</xsl:for-each>
</table>
<br/>


<h2><xsl:value-of select="html/report/top4xxerrorsperip/title"/></h2>
<table border="1">
<tr>
<th>Rank</th>
<th>Count</th>
<th>Src IP</th>
<th>FQDN</th>
</tr>
<xsl:for-each select="html/report/top4xxerrorsperip/rec">
<tr>
<td align="right"><xsl:value-of select="rank"/></td>
<td align="right"><xsl:value-of select="count"/></td>
<td align="left"><xsl:value-of select="srcip"/></td>
<td align="left"><xsl:value-of select="fqdn"/></td>
</tr>
</xsl:for-each>
</table>
<br/>


<h2><xsl:value-of select="html/report/top4xxerrorsperipurl/title"/></h2>
<table border="1">
<tr>
<th>Rank</th>
<th>Count</th>
<th>Src IP</th>
<th>URL</th>
</tr>
<xsl:for-each select="html/report/top4xxerrorsperipurl/rec">
<tr>
<td align="right"><xsl:value-of select="rank"/></td>
<td align="right"><xsl:value-of select="count"/></td>
<td align="left"><xsl:value-of select="srcip"/></td>
<td align="left"><xsl:value-of select="url"/></td>
</tr>
</xsl:for-each>
</table>
<br/>


<h2><xsl:value-of select="html/report/top_5xx_errors_per_ip/title"/></h2>
<table border="1">
<tr>
<th>Count</th>
<th>Status</th>
<th>Src IP</th>
<th>FQDN</th>
</tr>
<xsl:for-each select="html/report/top_5xx_errors_per_ip/rec">
<tr>
<td align="right"><xsl:value-of select="count"/></td>
<td align="right"><xsl:value-of select="status"/></td>
<td align="left"><xsl:value-of select="srcip"/></td>
<td align="left"><xsl:value-of select="fqdn"/></td>
</tr>
</xsl:for-each>
</table>
<br/>

<h2><xsl:value-of select="html/report/top_5xx_errors_per_url/title"/></h2>
<table border="1">
<tr>
<th>Count</th>
<th>Status</th>
<th>URL</th>
</tr>
<xsl:for-each select="html/report/top_5xx_errors_per_url/rec">
<tr>
<td align="right"><xsl:value-of select="count"/></td>
<td align="right"><xsl:value-of select="status"/></td>
<td align="left"><xsl:value-of select="url"/></td>
</tr>
</xsl:for-each>
</table>
<br/>

<h2><xsl:value-of select="html/report/top_5xx_errors_per_ip_url/title"/></h2>  
<table border="1">
<tr>
<th>Count</th>
<th>Status</th>
<th>Src IP</th>
<th>URL</th>
</tr>
<xsl:for-each select="html/report/top_5xx_errors_per_ip_url/rec">
<tr>
<td align="right"><xsl:value-of select="count"/></td>
<td align="right"><xsl:value-of select="status"/></td>
<td align="right"><xsl:value-of select="srcip"/></td>
<td align="left"><xsl:value-of select="url"/></td>
</tr>
</xsl:for-each>
</table>
<br/>


<h2><xsl:value-of select="html/report/topreferers/title"/></h2>
<table border="1">
<tr>
<th width="10%">Count</th>
<th width="40%">Ref URL</th>
<th width="50%">Ref URI</th>
</tr>
<xsl:for-each select="html/report/topreferers/rec">
<tr>
<td align="right" valign="top"><xsl:value-of select="count"/></td>
<td align="left" valign="top"><xsl:value-of select="refurl"/></td>
<td align="left" valign="top"><xsl:value-of select="refuri"/></td>
</tr>
</xsl:for-each>
</table>
<br/>




</html>