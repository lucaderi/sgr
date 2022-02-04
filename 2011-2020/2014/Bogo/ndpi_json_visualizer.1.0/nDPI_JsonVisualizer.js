/*
 * nDPI.JsonVisualizer.js
 *
 * Carica un file .json contenente le statistiche raccolte con ndpiReader
 * e le visualizza graficamente.
 *
 */

function load_JSON() {
    
    /* Loading JSON */       
    d3.json("test.json", function (data) {
                    
        /* DATA */
        
        /* FIRST JSON OBJECT: traffic statistics */
        
        var traffic_statistics = data["traffic.statistics"];
        
        /* Packets Type Row Chart Data */
        var pkts_type = [
            { Name: "0.TCP", value: traffic_statistics["tcp.pkts"] },
            { Name: "1.UDP", value: traffic_statistics["udp.pkts"] },
            { Name: "2.VLAN", value: traffic_statistics["vlan.pkts"] },
            { Name: "3.MPLS", value: traffic_statistics["mpls.pkts"] },
            { Name: "4.PPPoE", value: traffic_statistics["pppoe.pkts"] }
        ];
        
        /* Packets Length Row Chart Data */
        var pkts_len = [
            { Name: "0.< 64", value: traffic_statistics["pkt.len_min64"] },
            { Name: "1.64-128", value: traffic_statistics["pkt.len_64_128"] },
            { Name: "2.128-256", value: traffic_statistics["pkt.len_128_256"] },
            { Name: "3.256-1024", value: traffic_statistics["pkt.len_256_1024"] },
            { Name: "4.1024-1500", value: traffic_statistics["pkt.len_1024_1500"] },
            { Name: "5.> 1500", value: traffic_statistics["pkt.len_grt1500"] }
        ];
        
        var total_pkts = traffic_statistics["total.packets"];
        var ip_pkts = traffic_statistics["ip.packets"];
        var other_pkts = total_pkts - ip_pkts;
        
        /* IP/Other Packets Pie Chart Data */
        var ip_other_pkts = [
            { Name: "Not IP", value: other_pkts },
            { Name: "IP", value: ip_pkts }
        ];
        
        var eth_bytes = traffic_statistics["ethernet.bytes"];
        var ip_bytes = traffic_statistics["ip.bytes"];
        var other_bytes = eth_bytes - ip_bytes;        
        
        /* IP/Other Bytes Pie Chart Data */
        var ip_other_bytes = [
            { Name: "IP", value: ip_bytes},
            { Name: "Not IP", value: other_bytes}
        ];        
        
        /* MAX/AVG Packet Size Row Chart Data */
        var max_avg_pkts_size = [
            { Name: "0.MAX", value: traffic_statistics["max.pkt.size"] },
            { Name: "1.Average", value: traffic_statistics["avg.pkt.size"] }
        ];
        
        /* Unique/Guessed Flows Row Chart Data */
        var unique_guess_flows = [
            { Name: "0.Detected", value: traffic_statistics["unique.flows"] },
            { Name: "1.Guessed", value: traffic_statistics["guessed.flow.protos"] }
        ]
        
        /* Other Traffic Statistics Datatable Data */       
        var tot_size_ethbytes = [
            { Name: "Total Packets", value: total_pkts },
            { Name: "Ethernet Bytes", value: eth_bytes},
            { Name: "Discarded Bytes", value: traffic_statistics["discarded.bytes"] },
            { Name: "Fragmented Packets", value: traffic_statistics["fragmented.pkts"] }
        ];
        
        /* ------------------------------------------------------------------------------- */
        
        /* SECOND JSON OBJECT: detected protocols */
        
        var detected_protos = data["detected.protos"];
        
        /* ------------------------------------------------------------------------------- */
        
        /* THIRD JSON OBJECT: known flows */      
        
        var known_flows = data["known.flows"];

        /* ------------------------------------------------------------------------------- */
        
        /*
         * dc.js Chart Objects
         */

        /* Traffic Statistics */
        
        /* Packets Types Row Chart Object */
        var packet_types_rowChart = dc.rowChart("#dc-packets-types-chart");
        
        /* Packets Length Row Chart Object */
        var packets_len_rowChart = dc.rowChart("#dc-packets-len-chart");
        
        /* IP/Other Packets Pie Chart Object */
        var total_ip_pkts_pieChart = dc.pieChart("#dc-ip-packets-chart");
        
        /* IP/Other Bytes Pie Chart Object */
        var ip_other_bytes_pieChart = dc.pieChart("#dc-ip-bytes-chart");
        
        /* MAX/AVG Packet Size Row Chart Object */
        var max_avg_pkts_size_rowChart = dc.rowChart("#dc-max-avg-packets-chart");
        
        /* Unique/Guessed Flows Row Chart Object */
        var unique_guess_flows_rowChart = dc.rowChart("#dc-unique-guessed-flows-chart");
        
        /* Other Traffic Statistics, DataTable Chart Object */
        var tot_size_ethbytes_dataTableChart = dc.dataTable("#dc-datatable-1");
        
        /* Detected Protocols Bubble Chart Object */
        var detected_protocols_bubbleChart = dc.bubbleChart("#dc-detected-protos-chart");
        
        /* Detected Protocols Datatable Chart Object */
        var detected_protocols_datatableChart = dc.dataTable("#dc-datatable-2");
        
        /* Known Flows Datatable Chart Object */
        var known_flows_datatableChart = dc.dataTable("#dc-datatable-3");
        
        /*
         * Crossfilter
         */
        var ndx_pkts_types = crossfilter(pkts_type);
        var ndx_pkts_length = crossfilter(pkts_len);
        var ndx_total_ip_pkts = crossfilter(ip_other_pkts);
        var ndx_ip_other_bytes = crossfilter(ip_other_bytes);
        var ndx_max_avg_pkts_size = crossfilter(max_avg_pkts_size);
        var ndx_unique_guessed_flows = crossfilter(unique_guess_flows);
        var ndx_tot_size_ethbytes = crossfilter(tot_size_ethbytes);
        var ndx_detected_protocols = crossfilter(detected_protos);
        var ndx_known_flows = crossfilter(known_flows);

        /*
         * Dimensions
         */
        
        /* Packets Types */
        var dim_pkts_types = ndx_pkts_types.dimension(function (d) { return d.Name; });
        
        /* Packets Lenght */
        var dim_pkts_len = ndx_pkts_length.dimension(function(d) { return d.Name; });
        
        /* IP/Other Packets */
        var dim_total_ip_pkts = ndx_total_ip_pkts.dimension(function(d) { return d.Name; });
        
        /* IP/Other Bytes */
        var dim_ip_other_bytes = ndx_ip_other_bytes.dimension(function(d) { return d.Name; });
        
        /* MAX/AVG Packet Size */
        var dim_max_avg_pkts_size = ndx_max_avg_pkts_size.dimension(function(d) { return d.Name; });
        
        /* Unique/Guessed Flows */
        var dim_unique_guessed_flows = ndx_unique_guessed_flows.dimension(function(d) { return d.Name; });
        
        /* Other Traffic Statistics */
        var dim_tot_size_ethbytes = ndx_tot_size_ethbytes.dimension(function(d) { return d.Name; });
        
        /* Detected Protocols */
        var dim_detected_protocols = ndx_detected_protocols.dimension(function(d) { return d.name; });
        var dim_detected_protocols_xDim = ndx_detected_protocols.dimension(function(d) { return d.bytes; });
        
        /* Known Flows */
        var dim_known_flows = ndx_known_flows.dimension(function(d) { return d["detected.protocol.name"]; });
        
        /*
         * Groups
         */
                
        /* Packets Types Group */        
        var group_pkts_types = dim_pkts_types.group().reduceSum(function(d) { return d.value; });
        
        /* Packets Length Group */
        var group_pkts_length = dim_pkts_len.group().reduceSum(function(d) { return d.value; });
        
        /* IP/Other Packets Group */
        var group_total_ip_pkts = dim_total_ip_pkts.group().reduceSum(function(d) { return d.value; });
        
        /* IP/Other Bytes Group */
        var group_ip_other_bytes = dim_ip_other_bytes.group().reduceSum(function(d) { return d.value; });
        
        /* MAX/AVG Packet Size Group */
        var group_max_avg_pkts_size = dim_max_avg_pkts_size.group().reduceSum(function(d) { return d.value; });
        
        /* Unique/Guessed Flows Group */
        var group_unique_guessed_flows = dim_unique_guessed_flows.group().reduceSum(function(d) { return d.value; });
        
        /* Other Traffic Statistics Group */
        var group_tot_size_ethbytes = dim_tot_size_ethbytes.group().reduceSum(function(d) { return d.value; });
        
        /* Detected Protocols */
        var group_detected_protocols = dim_detected_protocols.group().reduce(
            function(p, v) {
                ++p.count;
                p.name = v.name;
                p.packets = v.packets;
                p.bytes = v.bytes;
                p.flows = v.flows;
                
                return p;
            
            },
            function(p, v) {
                --p.count;
                p.name = "";
                p.packets = 0;
                p.bytes = 0;
                p.flows = 0;
                
                return p;
            },
            function() {
                return { count: 0, name: "", packets: 0, bytes: 0, flows: 0 };
            });
        
        /* bubbleChart */
        var min = dim_detected_protocols.bottom(1)[0].name;
        var max = dim_detected_protocols.top(1)[0].name;
        
        var x_max_range = d3.max(group_detected_protocols.all(), function(d) { return d.value.packets + d.value.flows; });
        var y_max_range = d3.max(group_detected_protocols.all(), function(d) { return d.value.bytes + d.value.flows; });
        
        /* Simmetric BubbleChart Axis Dimensions */
        var xRangePercent = x_max_range + ((x_max_range * 25)/100);
        var yRangePercent = y_max_range + ((y_max_range * 25)/100);
        
        
        var xRange = [-d3.max(group_detected_protocols.all(), function(d) { return d.value.packets + d.value.flows; }),
                      xRangePercent
                      ];
        var yRange = [-d3.max(group_detected_protocols.all(), function(d) { return d.value.bytes + d.value.flows; }),
                      yRangePercent
                      ];
        
        /* Visualizations */
        
        /* Packets Types Chart Configuration */
        packet_types_rowChart
            .width(600)
            .height(300)
            .dimension(dim_pkts_types)
            .group(group_pkts_types)
            .colors(d3.scale.category10())
            .label(function (d){
                return d.key.split(".")[1];
            })
            .title(function(d){ return d.value; })
            .elasticX(true)
            .xAxis().ticks(6);
            
        
        /* Packets Length Chart Configuration */
        packets_len_rowChart
            .width(600)
            .height(300)
            .dimension(dim_pkts_len)
            .group(group_pkts_length)
            .colors(d3.scale.category10())
            .label(function (d){
                return d.key.split(".")[1];
            })
            .title(function(d){ return d.value; })
            .elasticX(true)
            .xAxis().ticks(6);
            
        /* IP/Other Packets Chart Configuration */
        total_ip_pkts_pieChart
            .width(300)
            .height(250)
            .radius(100)
            .innerRadius(30)
            .dimension(dim_total_ip_pkts)
            .group(group_total_ip_pkts)
            .label(function(d) {
                return d.data.key + ' ' + Math.round((d.endAngle - d.startAngle) / Math.PI * 50) + '%';
            })
            .title(function(d){ return d.value; });
            
        /* IP/Other Bytes Chart Configuration */
        ip_other_bytes_pieChart
            .width(300)
            .height(250)
            .radius(100)
            .innerRadius(30)
            .dimension(dim_ip_other_bytes)
            .group(group_ip_other_bytes)
            .label(function(d) {
                return d.data.key + ' ' + Math.round((d.endAngle - d.startAngle) / Math.PI * 50) + '%';
            })
            .title(function(d){ return d.value; });
            
        /* MAX/AVG Packet Size Chart Configuration */
        max_avg_pkts_size_rowChart
            .width(600)
            .height(100)
            .dimension(dim_max_avg_pkts_size)
            .group(group_max_avg_pkts_size)
            .colors(d3.scale.category10())
            .label(function (d){
                return d.key.split(".")[1];
            })
            .title(function(d){ return d.value; })
            .elasticX(true)
            .xAxis().ticks(6);
            
        /* Unique/Guessed Flows Chart Configuration */
        unique_guess_flows_rowChart
            .width(600)
            .height(100)
            .dimension(dim_unique_guessed_flows)
            .group(group_unique_guessed_flows)
            .colors(d3.scale.category10())
            .label(function (d){
                return d.key.split(".")[1];
            })
            .title(function(d){ return d.value; })
            .elasticX(true)
            .xAxis().ticks(6);
            
        /* Other Traffic Statistics Chart Configuration */
        tot_size_ethbytes_dataTableChart
            .width(400)
            .height(200)
            .dimension(dim_tot_size_ethbytes)
            .group(function(d) { return "Traffic Informations" })
            .size(4)   //numero record della tabella
            .columns([
                function(d) { return d.Name; },
                function(d) { return d.value; }
            ]);
            
        /* Detected Protocols Chart Configuration */
        detected_protocols_bubbleChart
            .dimension(dim_detected_protocols)
            .group(group_detected_protocols)
            .x(d3.scale.linear().domain(xRange))
            .y(d3.scale.linear().domain(yRange))
            .width(1000)
            .height(500)
            .margins({top: 0, right: 0, bottom: 50, left: 100}) 
            .yAxisPadding(50)
            .xAxisPadding(50)
            .xAxisLabel('Packets')
            .yAxisLabel('Bytes')
            .label(function (p) {
                return p.value.name;
            })
            .renderLabel(true)
            .title(function (p) {
                
                return [
                    "Packets: " + p.value.packets,
                    "Bytes: " + p.value.bytes,
                    "Flows: " + p.value.flows,        
                ]
                .join("\n");
            })
            .renderTitle(true)
            //.renderHorizontalGridLines(true)
            //.renderVerticalGridLines(true)
            .maxBubbleRelativeSize(0.1)
            .keyAccessor(function (p) {
                
                return p.value.packets;
            })
            .valueAccessor(function (p) {
                
                return p.value.bytes;
            })
            .radiusValueAccessor(function (p) {
                
                return p.value.flows;
            });
        
            
        /* Detected Protocols Datatable Chart Configuration */
        detected_protocols_datatableChart
            .width(400)
            .dimension(dim_detected_protocols)
            .group(function(d) { return "Detected Protocols Statistics"; })
            .columns([
                function(d) { return d["name"]; },
                function(d) { return d["breed"]; },
                function(d) { return d["packets"]; },
                function(d) { return d["bytes"]; },
                function(d) { return d["flows"]; }
            ])
            .sortBy(function (d) {
                return d.flows;
            })
            .order(d3.ascending)
            .renderlet(function (table) {
                table.selectAll(".dc-table-group").classed("info", true);
            });
            
        /* Known Flows Datatable Chart Configuration */
        known_flows_datatableChart
            .width(400)
            .dimension(dim_known_flows)
            .group(function(d) { return "Known Flows"; })
            .columns([
                function(d) { return d["protocol"]; },
                function(d) { return d["host_a.name"]; },
                function(d) { return d["host_a.port"]; },
                function(d) { return d["host_b.name"]; },
                function(d) { return d["host_n.port"]; },
                function(d) { return d["detected.protocol"]; },
                function(d) { return d["detected.protocol.name"]; },
                function(d) { return d["packets"]; },
                function(d) { return d["bytes"]; }
            ])
            .sortBy(function (d) {
                return d["detected.protocol.name"];
            })
            .order(d3.ascending)
            .renderlet(function (table) {
                table.selectAll(".dc-table-group").classed("info", true);
            });
        
        /* Rendering Charts */
        dc.renderAll();
        
        /* Load Charts Titles */        
        document.getElementById("charts-titles-packets-type").innerHTML = "Protocol Distribution";
        document.getElementById("charts-titles-packets-length").innerHTML = "Packet Length";
        document.getElementById("charts-titles-ip-packets").innerHTML = "IP Packets";
        document.getElementById("charts-titles-ip-bytes").innerHTML = "IP Bytes";
        document.getElementById("charts-titles-packet-size").innerHTML = "Packet Size";
        document.getElementById("charts-titles-flows").innerHTML = "Flow Protocol Detection";
        document.getElementById("charts-titles-detected-protocols").innerHTML = "Detected Protocols";
        
        /* Load Datatable Titles */
        document.getElementById("datatable-1-data").innerHTML = "Data"
        document.getElementById("datatable-1-value").innerHTML = "Value";
        
        document.getElementById("datatable-2-protocol").innerHTML = "Protocol";
        document.getElementById("datatable-2-breed").innerHTML = "Breed";
        document.getElementById("datatable-2-packets").innerHTML = "Packets";
        document.getElementById("datatable-2-bytes").innerHTML = "Bytes";
        document.getElementById("datatable-2-flows").innerHTML = "Flows";
        
        if (known_flows != "") {
        
            document.getElementById("datatable-3-protocol").innerHTML = "Protocol";
            document.getElementById("datatable-3-host-a-name").innerHTML = "Host A";
            document.getElementById("datatable-3-host-a-port").innerHTML = "Port A";
            document.getElementById("datatable-3-host-b-name").innerHTML = "Host B";
            document.getElementById("datatable-3-host-b-port").innerHTML = "Port B";
            document.getElementById("datatable-3-detected-protocol").innerHTML = "Detected Protocol Number";
            document.getElementById("datatable-3-detected-protocol-name").innerHTML = "Detected Protocol Name";
            document.getElementById("datatable-3-packets").innerHTML = "Packets";
            document.getElementById("datatable-3-bytes").innerHTML = "Bytes";
            
        }
    });
}