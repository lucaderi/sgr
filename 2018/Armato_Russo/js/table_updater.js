function update_social_table(ip) {
	$.ajax({
		type : 'GET',
		url: "/lua/social_stats",
		data: "host="+ip+"",
		success: function(content){
			var metrics=JSON.parse(content)
        	var col = [];
        	for (var i = 0; i < metrics.length; i++) {
            	for (var key in metrics[i]) {
                	if (col.indexOf(key) === -1) {
                    		col.push(key);
                	}
            	}
        	}
        	var table = document.createElement("table");
        	var tr = table.insertRow(-1);

        	for (var i = 0; i < col.length; i++) {
        		var th = document.createElement("th");
        		th.innerHTML = col[i];
        		tr.appendChild(th);
       	 	}

        	for (var i = 0; i < metrics.length; i++) {
        		tr = table.insertRow(-1);
            		for (var j = 0; j < col.length; j++) {
                		var tabCell = tr.insertCell(-1);
                		tabCell.innerHTML = metrics[i][col[j ] ]  
            		}	
        	}
        	var divContainer = document.getElementById("stats_table");
        	divContainer.innerHTML = "";
        	divContainer.appendChild(table);

  		}
	})
}
