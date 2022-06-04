<!DOCTYPE html>

<html>

<head>
	<title>Temperature</title>
	
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
	<h2>Current : <span style="color: #55e6c1"><?php echo shell_exec("/home/pi/temp/shtemp"); ?></span> °C</h2>
		
	<img src="temp_graph.png" alt="Temperature_graph" width="994" height="338">
</body>

</html>
