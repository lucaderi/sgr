<!doctype html>
<html>
	<meta charset="UTF-8">
	<head>
		<title>:: Progetto Gestione di Rete ::</title>
		<link type="text/css" rel="stylesheet" media="all" href="styles/styles.css" />
		<script src="js/jquery-1.4.1.min.js" type="text/javascript"></script>
		<script src="js/lavalamp.js" type="text/javascript"></script>
   </head>
<body>
        
<h2>
         <?php
						$pcarico= shell_exec("less /var/www/pids/carico.pid");
						$pnprobe= shell_exec("less /var/www/pids/nprobe.pid");
						$psonda= shell_exec("less /var/www/pids/sonda.pid");
						$pgrafica= shell_exec("less /var/www/pids/grafica.pid");
						//print_r($processo);
						
						//Processo Grafico carico CPU
						$ps1 =shell_exec("ps -eo pid,comm  | grep $pcarico");
						if (empty($ps1)) $tag1="<font color=\"red\">Non Attivo</font>";
						else $tag1="<font color=\"green\">Attivo</font>";
						//Processo nprobe attivo
						$ps2 =shell_exec("ps -eo pid,comm  | grep $pnprobe");
						if (empty($ps2)) $tag2="red";
						else $tag2="green";
						//Processo Sonda java
						$ps3 =shell_exec("ps -eo pid,comm  | grep $psonda");
						if (empty($ps3)) $tag3="red";
						else $tag3="green";
						//Processo Grafico carico CPU
						$ps4 =shell_exec("ps -eo pid,comm  | grep $pgrafica");
						if (empty($ps4)) $tag4="red";
						else $tag4="green";
						?>
			<header>
				Monitoraggio con Mikrotik
				<h2></h2>
			</header> 
			<nav id="menu"> 
				<div class="lavalamp cyan">
					<ul>
						<li class="active"><a href="index.html">Home</a></li>
						<li><a href="progetto.html">Progetto</a></li>
						<li><a href="monitoraggio.php">Monitoraggio</a></li>
						<li><a href="porte.html">Porte</a></li>
						<li><a href="documentazione.html">Documentazione</a></li>
					</ul>
					<div class="floatr">
					</div>
				</div> 
			</nav>
	 </h2>
		<section class="contenitore">
			<br>
        
         <table width="360" height="268" align="center">
         	
         	<tr >
         	  <td><div align="center">Carico CPU:</div></td>
       	  </tr>
         	<tr >
            	<td height="227"><p align="center"><img src="graph/loadav.png" alt="Carico CPU" align="middle"></p>
           	    <p align="center">Stato Processo Carico CPU:</p>
           	    <p align="center"><?php echo $tag1 ?></p></td>
           </tr>
          </table>
         <table width="100%" border="0" cellspacing="1" cellpadding="1">
	    <tr>
			    <td colspan="100%"><div align="center">Stato processi applicazione: </div></td>
		      </tr>
			  <tr>
			    <td>
                <td width="33%" bgcolor="<?php echo $tag2 ?>"
			      <div align="center">
			      <font color="#DDDDDD">Stato Processo nProbe</font>
	            </div></td>
                
			    <td>
                <td width="33%" bgcolor="<?php echo $tag3 ?>"
                <div align="center">
                <font color="#DDDDDD">Stato Processo Parser</font></div></td>
                
			    <td>
                <td width="33%" bgcolor="<?php echo $tag4 ?>"
		        <div align="center">
                  <div align="center"><font color="#DDDDDD">Stato Processo disegno Grafici</font></div>
                </div></td>
		      </tr>
			  <tr>
			    <td colspan="100%"><div align="center"><br>

			   			     Legenda: <font color="#006600">Attivo</font> | <font color="#FF0000">Non Attivo</font>
			    </div></td>
		      </tr>
		  </table>
			<p><br>
		  </p>
        </section>
		<h2>
			<footer id="footercont">
				<div id="footer"> 
					<div class="lavalamp cyan" align="center">
						<ul >
							<li class="foot">
								<a href="index.html"> Progetto di rete 2011</a>
							</li>
						</ul>
					</div>
				</div>
		  </footer>
</h2>
	</body>
</html>
