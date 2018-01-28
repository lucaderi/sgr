var t = 5 //refresh in seconds

function list(arr){
	var str = "<ul>";
	for(var i=0; i<arr.length; i++){
		str += "<li>"+arr[i]+"</li>"
	}
	return str += "</ul>";
}

$(document).ready(window.setInterval("go()", t*1000));

function go() 
{
    //var $body = $("body");
    var $agg = $("#aggiornare");
    $agg.empty();
    $agg.append($("<ul id=\"list\"></ul>"));

$.get('http://127.0.0.1:8080/json', function(data) 
    {
    	var obj = jQuery.parseJSON(data);
	  	for(var i=0; i<obj.vhost.length; i++)
        {
	  		var $tmp = $("<li class=\"vhost\">"+
	  			"<h2>"+obj["vhost"][i].name+"</h2>"+
	  			"<p><em>IP:</em> "+obj["vhost"][i].ip+"</p>"+
                //http://www.coffer.com/mac_find/?string=00%3A23%3A32%3Ada%3Afa%3A98
                "<p><em>MAC:</em><a href=\"http://www.coffer.com/mac_find/\">"+obj["vhost"][i].mac+"</a></p>"+
	  			"<p><em>User Agent:</em> "+obj["vhost"][i].useragent+"</p>"+
	  			"<p><em>Inactive:</em> "+(obj["vhost"][i].inactive==true)+"</p>"+
	  			"<p><em>Seen Alive:</em> "+$.format.date(obj["vhost"][i].lastseenalive, "dd/MM/yyyy hh:mm.ss")+"</p>"+
	  			"<p><em>Web Sites:</em> "+list(obj["vhost"][i].websites)+"</p>"+
                "<p><em>App. Protocol:</em> "+list(obj["vhost"][i].application)+"</p>"+
                "<p><em>Transp. Protocol:</em> "+list(obj["vhost"][i].transport)+"</p>"+
	  		"</li>");
	  		if(obj["vhost"][i].inactive==true)
	  			$tmp.addClass("inactive");
	  		//$("#list").append($tmp);
            //$agg.replaceWith($("<ul id=\"list\"></ul>"));
	  	}
	});

    }
$.format.date("Wed Jan 13 10:43:41 CET 2010", "dd~MM~yyyy")
