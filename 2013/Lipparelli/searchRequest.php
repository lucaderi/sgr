<?php
/*Set default timezone*/
date_default_timezone_set('UTC');

$tmp_dir = "tmp/";
$req = $_POST['url'];
$file_db = null;
$file_to_chk = null;

try {
	/*Try to open the db*/
	$file_db = new PDO('sqlite:db/cronDB.sqlite', null, null);

	/*Set errormode to exceptions*/
	$file_db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

	/*Query Cron DB*/
	$date1_a = explode("-", $req);
	/*yyyy-mm-dd-hh-mm to mktime format hour,minute,second,month,day,year,is_dst(optional)*/
	$timedate1 = mktime($date1_a[3],$date1_a[4],0,$date1_a[1],$date1_a[2],$date1_a[0]);
	$file_to_chk = "$tmp_dir"."$req".".csv";
	
	/*If file exist then take it from tmp dir and don't do query to db else do query and create/add .csv file*/
	if(file_exists("$file_to_chk") == false) {
		if (($open_file = fopen("$file_to_chk", "w+")) == false){
			$file_db = null;
			die('<div class="alert alert-error span6 offest3">
						<button type="button" class="close" data-dismiss="alert">&times;</button>
						<h4>Error!</h4>Technical Problem, sorry try later... :(
				</div>');
		}
		
		fwrite($open_file,"State,Traffic Top Host 1,Traffic Top Host 2,Traffic Top Host 3\n");
		for($i = $timedate1; $i <= $timedate1 + 59; $i++) {
			/*prepare statement and execute it*/
			$result = $file_db->query("SELECT * FROM cronTable WHERE Id = '$i'");
			$cnt_res = 0;
			
			foreach ($result as $row) {
				$cnt_res = 1;
				$row_rec = $row['Record'];
				$num_padded = sprintf("%02s", $i - $timedate1);
				fwrite($open_file, $num_padded.",".$row_rec."\n");
			}
			
			if ($cnt_res == 0) {
				fclose($open_file);
				unlink($file_to_chk);
				$file_db = null;
				die('<div class="alert alert-error span6 offset3">
						<button type="button" class="close" data-dismiss="alert">&times;</button>
						<h4>Error!</h4>There is no values in the Database corresponding to your research! :(
					</div>');
			}
		}
		fclose($open_file);
	}
	/*Close the db*/
	$file_db = null;
	
	/*TO-DO prepare and return D3 stacked bar chart graph or compact layout on request, into client div*/
	echo '<div class="span8 offset2" id="barChart">
			<style>
				.axis path,
				.axis line {
					fill: none;
					stroke: #000;
					shape-rendering: crispEdges;
				}

				.bar {
					fill: steelblue;
				}

				.x.axis path {
					display: none;
				}
			</style>

			<script type="text/javascript" src="js/d3.v3.js"></script>
			<script type="text/javascript" src="js/jquery-1.10.1.js"></script>
			<script>
				function numberWithCommas(x) {
					return x.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
				}

				var margin = {top: 20, right: 20, bottom: 30, left: 40},
					width = 1200 - margin.left - margin.right,
					height = 700 - margin.top - margin.bottom;

				var x = d3.scale.ordinal()
					.rangeRoundBands([0, width], .1);

				var y = d3.scale.linear()
					.rangeRound([height, 0]);

				var color = d3.scale.ordinal()
					.range(["#98abc5", "#8a89a6", "#7b6888"]);

				var xAxis = d3.svg.axis()
					.scale(x)
					.orient("bottom");

				var yAxis = d3.svg.axis()
					.scale(y)
					.orient("left")
					.tickFormat(d3.format(".2s"));

				var svg = d3.select("#barChart").append("svg")
					.attr("width", width + margin.left + margin.right)
					.attr("height", height + margin.top + margin.bottom)
				.append("g")
					.attr("transform", "translate(" + margin.left + "," + margin.top + ")");

				d3.csv("'.$file_to_chk.'", function(error, data) {
					color.domain(d3.keys(data[0]).filter(function(key) { return key !== "State"; }));

					data.forEach(function(d) {
						var y0 = 0;
						d.ages = color.domain().map(function(name) {var host = d[name].split(":"); return {name: name, host: host[0], state: d.State, traffic: numberWithCommas(host[1]), y0: y0, y1: y0 += +host[1]}; });
						d.total = d.ages[d.ages.length - 1].y1;
					});

					x.domain(data.map(function(d) { return d.State; }));
					y.domain([0, d3.max(data, function(d) { return d.total; })]);

					svg.append("g")
						.attr("class", "x axis")
						.attr("transform", "translate(0," + height + ")")
						.call(xAxis);

					svg.append("g")
						.attr("class", "y axis")
						.call(yAxis)
					.append("text")
						.attr("transform", "rotate(-90)")
						.attr("y", 6)
						.attr("dy", ".71em")
						.style("text-anchor", "end")
						.text("Traffic");

					var state = svg.selectAll(".state")
						.data(data)
						.enter().append("g")
						.attr("class", "g")
						.attr("transform", function(d) { return "translate(" + x(d.State) + ",0)"; });

					state.selectAll("rect")
						.data(function(d) { return d.ages; })
					.enter().append("rect")
						.attr("width", x.rangeBand())
						.attr("y", function(d) { return y(d.y1); })
						.attr("height", function(d) { return y(d.y0) - y(d.y1); })
						.style("fill", function(d) { return color(d.name); })
						.on("click", function(d) {  $("#infoTable").append("<tr><td>"+d.state+"</td><td>"+d.host+"</td><td>"+d.name+"</td><td>"+d.traffic+"</td></tr>");})
						.on("mouseover",function() {d3.select(this).style("fill","black");} )
						.on("mouseout", function(d) {d3.select(this).style("fill", function(d){return color(d.name);});});

					/*For remove legend comment these three blocks of code*/
					var legend = svg.selectAll(".legend")
						.data(color.domain().slice().reverse())
					.enter().append("g")
						.attr("class", "legend")
						.attr("transform", function(d, i) { return "translate(0," + i * 20 + ")"; });

					legend.append("rect")
						.attr("x", width - 18)
						.attr("width", 18)
						.attr("height", 18)
						.style("fill", color);

					legend.append("text")
						.attr("x", width - 24)
						.attr("y", 9)
						.attr("dy", ".35em")
						.style("text-anchor", "end")
						.text(function(d) { return d; })
					});
			</script>
		</div>';
}
catch(PDOException $e) {
	/*Print PDOException message*/
	$file_db = null;
	unlink($file_to_chk);
	echo '<div class="alert alert-error span6 offset3">
				<button type="button" class="close" data-dismiss="alert">&times;</button>
				<h4>Error!</h4>Something is going wrong! :( Server Message:';
				print $e->getMessage();
				echo '</div>';

}
?>