<!DOCTYPE html>

<html>

<head>
	<title>Temperature</title>

	<link type="image/png" sizes="96x96" rel="icon" href="http://raspberrypi-simone.ddns.net/favicon.png">
	
	<meta charset="utf-8">
    <meta name="author" content="Simone Passera">
    
	<style>
		body {
			font-family: sans-serif;
			font-size: 2em;
			text-align: center;
			background: #1e272e;
			color: #ecf0f1;
		}
	</style>
</head>

<body>
	<h1>Temperature</h1>
	<h2>Current : <span style="color: #55e6c1"><?php echo shell_exec("/home/pi/temp/shtemp"); ?></span>°C</h2>
		
	<img src="graphs/temp_graph_1h.png" alt="Temperature_graph_1h" width="994" height="338">
	<img src="graphs/temp_graph_7d.png" alt="Temperature_graph_7d" width="994" height="338">
	
</body>

</html>
