<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns="http://www.w3.org/1999/xhtml">
 	<xsl:output method="html" indent="yes"
		doctype-system="xhtml1-transitional.dtd"
		doctype-public="-//W3C//DTD XHTML 1.0 Transitional//EN"/>
	<xsl:template match="/">   <!-- Applica questo template al nodo radice indicato dal carattere / -->
	<html xmlns="http://www.w3.org/1999/xhtml">
		<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
		<link type="text/css" rel="stylesheet" href="../style.css" />
		</head>
		<body>
			<table class="t1">
				<tr>
					<td class="type">Id:</td> <td class="type">L4 protocol:</td> <td class="type">IP:</td> <td class="type">Port:</td> <td class="type">Bytes:</td> <td class="type">Packets:</td> <td class="type">First packet timestamp:</td> <td class="type">Last packet timestamp:</td> <td></td>
				</tr>
				<tr style="height : 5px;"></tr>
				<xsl:for-each select="//f">
					<xsl:sort data-type="number" select="i" order="descending" />
							<tr>
								<td rowspan="2"><xsl:value-of select="i" /></td> <td rowspan="2"><xsl:value-of select="t" /></td> <td><xsl:value-of select="si" /></td> <td><xsl:value-of select="sp" /></td> <td><xsl:value-of select="sb" /></td> <td><xsl:value-of select="sdp" /></td> <td><xsl:value-of select="sf" /></td> <td><xsl:value-of select="sl" /></td> <td class="type">src-&gt;dst</td>
							</tr>
							<tr>
								<td><xsl:value-of select="di" /></td> <td><xsl:value-of select="dp" /></td> <td><xsl:value-of select="db" /></td> <td><xsl:value-of select="dsp" /></td> <td><xsl:value-of select="df" /></td> <td><xsl:value-of select="dl" /></td> <td class="type">dst-&gt;src</td>
							</tr>	
							<tr style="height : 7px;"></tr>			
				</xsl:for-each>
			</table>
		</body>
	</html>
	</xsl:template>
</xsl:stylesheet>
