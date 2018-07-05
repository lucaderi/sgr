
// Controlla se ci sono informazioni riguardanti i flussi social
// ed in caso positivo abilita il tab social in host_details?host=[host_ip]
function show_social_tab(ip){
	$.ajax({
		type : 'GET',
		url: "/lua/social_stats",
		data: "host="+ip,
		success: function(content){
			var metrics=JSON.parse(content)
			if(metrics != ""){
				var social_tab = document.getElementById('social_tab');
    			social_tab.style.display = "inline";
			}
  		}
	})
}
