<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:value-of select="html/report/title"/>


Input Files:<xsl:value-of select="html/report/inputfiles">
Output Files:<xsl:value-of select="html/report/outputfiles">
Exec Start:<xsl:value-of select="html/report/execstart">
Exec Stop: <xsl:value-of select="html/report/execstop"> 
Rows analyzed: <xsl:value-of select="html/report/rowsanalyzed">
Nr IP-addresses: <xsl:value-of select="html/report/nripaddr">
Performance: <xsl:value-of select="html/report/perf">
Name Resoultion Off: <xsl:value-of select="html/report/nroff">


<br/>Rep:
<br/><h2><xsl:value-of select="report/logformats/title"/></h2>
<xsl:for-each select="report/logformats/rec">
<br/><xsl:value-of select="format"/>:<xsl:value-of select="nrfound"/> 
</xsl:for-each>
<br/> 

<br/><h2><xsl:value-of select="report/hitsperhour/title"/></h2>
<table border="1">
<tr><th>Hour</th>
<th>Hits</th>
</tr>
<xsl:for-each select="report/hitsperhour/rec">
<tr>
<td><xsl:value-of select="hour"/></td>
<td><xsl:value-of select="hits"/></td>
</tr>
</xsl:for-each>
</table>
<br/><h2><xsl:value-of select="report/dangerousfiles/title"/></h2>      
<xsl:for-each select="report/dangerousfiles/rec">
<br/><xsl:value-of select="count"/>:<xsl:value-of select="srcip"/>:<xsl:value-of select="url"/>
                                    
</xsl:for-each>


<br/><h2><xsl:value-of select="report/unauthorized/title"/></h2>
<table border="1">
<xsl:for-each select="report/unauthorized/rec">
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


<br/><h2><xsl:value-of select="report/logged_in_users/title"/></h2>              
<table border="1">
<xsl:for-each select="report/logged_in_users/rec">
<tr>
<td><xsl:value-of select="count"/></td>
<td><xsl:value-of select="user"/></td>
</tr>
</xsl:for-each>
</table>
<br/>


<br/><h2><xsl:value-of select="report/logged_in_users_per_ip/title"/></h2>
<table border="1">
<tr><th>Count</th>        
<th>User</th>
<th>Src IP</th>
<th>FQDN</th></tr> 
<xsl:for-each select="report/logged_in_users_per_ip/rec">
<tr>
<td><xsl:value-of select="count"/></td>
<td><xsl:value-of select="user"/></td>
<td><xsl:value-of select="srcip"/></td>
<td><xsl:value-of select="fqdn"/></td>
</tr>
</xsl:for-each>
</table>
<br/>


<h2><xsl:value-of select="report/statuscodes/title"/></h2>
<table border="1">
<tr><th>Count</th>
<th>Status</th>
<th>Status Desc</th></tr>
<xsl:for-each select="report/statuscodes/rec">
<tr>
<td align="right"><xsl:value-of select="count"/></td>
<td><xsl:value-of select="status"/></td>
<td><xsl:value-of select="statusname"/></td>
</tr>
</xsl:for-each>
</table>
<br/>

<h2><xsl:value-of select="report/httpmethods/title"/></h2>
<table border="1">
<tr>
<th>Count</th>
<th>Method</th>
</tr>
<xsl:for-each select="report/httpmethods/rec">
<tr>
<td align="right"><xsl:value-of select="count"/></td>
<td><xsl:value-of select="method"/></td>
</tr>
</xsl:for-each>
</table>
<br/>


<h2><xsl:value-of select="report/httpversions/title"/></h2>            
<table border="1">
<tr>
<th>Count</th>
<th>Version</th>
</tr>
<xsl:for-each select="report/httpversions/rec">
<tr>
<td align="right"><xsl:value-of select="count"/></td>
<td><xsl:value-of select="version"/></td>
</tr>
</xsl:for-each>
</table>
<br/>


<h2><xsl:value-of select="report/illegalhttp/title"/></h2>       
<table border="1">
<tr>
<th>Count</th>
<th>HTTP String</th>
<th>Src IP</th>
<th>FQDN</th>
</tr>
<xsl:for-each select="report/illegalhttp/rec">
<tr>
<td align="right"><xsl:value-of select="count"/></td>
<td><xsl:value-of select="httpstr"/></td>
<td><xsl:value-of select="srcip"/></td>
<td><xsl:value-of select="fqdn"/></td>
</tr>
</xsl:for-each>
</table>
<br/>


<h2><xsl:value-of select="report/tophitters/title"/></h2>               
<table border="1">
<tr>
<th>Rank</th>
<th>Count</th>
<th>Src IP</th>
<th>FQDN</th>
</tr>
<xsl:for-each select="report/tophitters/rec">
<tr>
<td align="right"><xsl:value-of select="rank"/></td>
<td align="right"><xsl:value-of select="count"/></td>
<td align="left"><xsl:value-of select="srcip"/></td>
<td><xsl:value-of select="fqdn"/></td>
</tr>
</xsl:for-each>
</table>
<br/>

<h2><xsl:value-of select="report/errors4xx/title"/></h2>
<table border="1">
<tr>
<th>Count</th>
<th>HTTP Status</th>
<th>URL</th>
</tr>
<xsl:for-each select="report/errors4xx/rec">
<tr>
<td align="right"><xsl:value-of select="count"/></td>
<td align="left"><xsl:value-of select="httpstatus"/></td>
<td><xsl:value-of select="url"/></td>
</tr>
</xsl:for-each>
</table>
<br/>


<h2><xsl:value-of select="report/top4xxerrorsperip/title"/></h2>
<table border="1">
<tr>
<th>Rank</th>
<th>Count</th>
<th>Src IP</th>
<th>FQDN</th>
</tr>
<xsl:for-each select="report/top4xxerrorsperip/rec">
<tr>
<td align="right"><xsl:value-of select="rank"/></td>
<td align="right"><xsl:value-of select="count"/></td>
<td align="left"><xsl:value-of select="srcip"/></td>
<td align="left"><xsl:value-of select="fqdn"/></td>
</tr>
</xsl:for-each>
</table>
<br/>


<h2><xsl:value-of select="report/top4xxerrorsperipurl/title"/></h2>
<table border="1">
<tr>
<th>Rank</th>
<th>Count</th>
<th>Src IP</th>
<th>URL</th>
</tr>
<xsl:for-each select="report/top4xxerrorsperipurl/rec">
<tr>
<td align="right"><xsl:value-of select="rank"/></td>
<td align="right"><xsl:value-of select="count"/></td>
<td align="left"><xsl:value-of select="srcip"/></td>
<td align="left"><xsl:value-of select="url"/></td>
</tr>
</xsl:for-each>
</table>
<br/>


<h2><xsl:value-of select="report/top_5xx_errors_per_ip/title"/></h2>
<table border="1">
<tr>
<th>Count</th>
<th>Status</th>
<th>Src IP</th>
<th>FQDN</th>
</tr>
<xsl:for-each select="report/top_5xx_errors_per_ip/rec">
<tr>
<td align="right"><xsl:value-of select="count"/></td>
<td align="right"><xsl:value-of select="status"/></td>
<td align="left"><xsl:value-of select="srcip"/></td>
<td align="left"><xsl:value-of select="fqdn"/></td>
</tr>
</xsl:for-each>
</table>
<br/>

<h2><xsl:value-of select="report/top_5xx_errors_per_url/title"/></h2>
<table border="1">
<tr>
<th>Count</th>
<th>Status</th>
<th>URL</th>
</tr>
<xsl:for-each select="report/top_5xx_errors_per_url/rec">
<tr>
<td align="right"><xsl:value-of select="count"/></td>
<td align="right"><xsl:value-of select="status"/></td>
<td align="left"><xsl:value-of select="url"/></td>
</tr>
</xsl:for-each>
</table>
<br/>

<h2><xsl:value-of select="report/top_5xx_errors_per_ip_url/title"/></h2>  
<table border="1">
<tr>
<th>Count</th>
<th>Status</th>
<th>Src IP</th>
<th>URL</th>
</tr>
<xsl:for-each select="report/top_5xx_errors_per_ip_url/rec">
<tr>
<td align="right"><xsl:value-of select="count"/></td>
<td align="right"><xsl:value-of select="status"/></td>
<td align="right"><xsl:value-of select="srcip"/></td>
<td align="left"><xsl:value-of select="url"/></td>
</tr>
</xsl:for-each>
</table>
<br/>


<h2><xsl:value-of select="report/topreferers/title"/></h2>
<table border="1">
<tr>
<th width="10%">Count</th>
<th width="40%">Ref URL</th>
<th width="50%">Ref URI</th>
</tr>
<xsl:for-each select="report/topreferers/rec">
<tr>
<td align="right" valign="top"><xsl:value-of select="count"/></td>
<td align="left" valign="top"><xsl:value-of select="refurl"/></td>
<td align="left" valign="top"><xsl:value-of select="refuri"/></td>
</tr>
</xsl:for-each>
</table>
<br/>

