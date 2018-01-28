<?php
/*Set default timezone*/
date_default_timezone_set('UTC');

/*Random function for create host ip v4*/
function hrand() {
	return rand(0,255).".".rand(0,255).".".rand(0,255).".".rand(0,255);
}

/*Get date values from datepickers*/
$date1 = $_POST['date1'];
$date2 = $_POST['date2'];


try {
	/*Try to open the db*/
	$file_db = new PDO('sqlite:db/cronDB.sqlite');

	/*Set errormode to exceptions*/
	$file_db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	/*Create cron table, if not exists*/
	$file_db->exec("CREATE TABLE IF NOT EXISTS cronTable (Id INTEGER PRIMARY KEY, Record TEXT)");

	/*Populating Cron DB*/
	$date1_a = explode("-", $date1);
	$date2_a = explode("-", $date2);
	$timedate1 = mktime($date1_a[0],$date1_a[1],0,$date1_a[2],$date1_a[3],$date1_a[4]);
	$timedate2 = mktime($date2_a[0],$date2_a[1],0,$date2_a[2],$date2_a[3],$date2_a[4]);

	if($timedate2 <= $timedate1) {
		session_destroy();
		die('<div class="alert alert-error">
				<button type="button" class="close" data-dismiss="alert">&times;</button>
				<h4>Error!</h4>Right side of time interval must be GREATER than left side!!
			</div>');
	}

	/*Create pseudo-random record to put into .csv file*/
	for($i = $timedate1; $i < $timedate2; $i++) {
		
		$rec_tmp = hrand().":".rand(0,1000000).",".hrand().":".rand(0,1000000).",".hrand().":".rand(0,1000000);
		
		$file_db->exec("INSERT INTO cronTable (Id, Record) VALUES ('$i', '$rec_tmp')");
	}

	/*If population gone right return success message*/
	echo '<div class="alert alert-success">
			<button type="button" class="close" data-dismiss="alert">&times;</button>
			<h4>Success!</h4>The Database is fully Populated now!!
		</div>';

	/*Close the db*/
	$file_db = null;
}
catch(PDOException $e) {
	/*Print PDOException message*/
	echo '<div class="alert alert-error">
				<button type="button" class="close" data-dismiss="alert">&times;</button>
				<h4>Error!</h4>Something is going wrong! :( Server Message:';
				print $e->getMessage();
			echo '</div>';
}
?>