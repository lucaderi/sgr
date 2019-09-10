var ctx = document.getElementById('myChart');

//generates an array of ip addresses (without duplicates) to be used as axes labels
var axLabelsDupe = jsonData.dataset.map(a => a.rx_addr).concat(jsonData.dataset.map(a => a.tx_addr));
var axLabelUnique = [...new Set(axLabelsDupe)].sort();

var opt = {
    title: {
        display: true,
        text: "Sniffer report of " + jsonInfo.count + " packets from: " + jsonInfo.device,
        position: 'top'
    },
    legend: {
        position: 'right'
    },
    tooltips: {
        callbacks: {
            title: function (item, data) {
                return "from " + data.datasets[item[0].datasetIndex].data[item[0].index].x + " to " + data.datasets[item[0].datasetIndex].data[item[0].index].y
            },
            label: function (item, data) {
                var bytes = data.datasets[item.datasetIndex].data[item.index].payload;
                if (bytes < 1024) return bytes + " bytes, " + data.datasets[item.datasetIndex].data[item.index].pktcount + " packets";
                return Math.round(bytes / 1024) + " KiB, " + data.datasets[item.datasetIndex].data[item.index].pktcount + " packets"
            }
        }
    },
    scales: {
        xAxes: [{
            type: 'category',
            labels: axLabelUnique,
            offset: true,
            scaleLabel: {
                display: true,
                labelString: 'hosts (tx)'
            }
        }],
        yAxes: [{
            type: 'category',
            labels: axLabelUnique,
            offset: true,
            scaleLabel: {
                display: true,
                labelString: 'hosts (rx)'
            }
        }]
    }
};

var udpDataset = [];
var tcpDataset = [];
var icmpDataset = [];
var maxPayload = 0;
var radScalingFactor = 10000;
jsonData.dataset.forEach(getMaxPayload);
jsonData.dataset.forEach(parse);

function getMaxPayload(item) {
    if (item.udp_bytes > maxPayload)
        maxPayload = item.udp_bytes;
    if (item.tcp_bytes > maxPayload)
        maxPayload = item.tcp_bytes;
    if (item.icmp_bytes > maxPayload)
        maxPayload = item.icmp_bytes;
}

function parse(item) {
    var newBubble = {x: item.tx_addr, y: item.rx_addr, r: 0, pktcount: item.pktcount, payload: 0};

    if (item.udp_bytes > 0) {
        newBubble.r = Math.sqrt(item.udp_bytes / maxPayload * radScalingFactor);
        newBubble.payload = item.udp_bytes;
        udpDataset.push(newBubble);
    }
    if (item.tcp_bytes > 0) {
        newBubble.r = Math.sqrt(item.tcp_bytes / maxPayload * radScalingFactor);
        newBubble.payload = item.tcp_bytes;
        tcpDataset.push(newBubble);
    }
    if (item.icmp_bytes > 0) {
        newBubble.r = Math.sqrt(item.icmp_bytes / maxPayload * radScalingFactor);
        newBubble.payload = item.icmp_bytes;
        icmpDataset.push(newBubble);
    }
}

var cData = {
    datasets: [{
        label: 'udp',
        data: udpDataset,
        backgroundColor: "rgba(28,90,168,0.5)"
    },
        {
            label: 'tcp',
            data: tcpDataset,
            backgroundColor: "rgba(143,34,23,0.5)",
        },
        {
            label: 'icmp',
            data: icmpDataset,
            backgroundColor: "rgba(127,63,191,0.5)",
        }]
};

var myChart = new Chart(ctx, {
    type: 'bubble',
    data: cData,
    options: opt
});