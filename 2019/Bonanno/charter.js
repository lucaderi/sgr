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

jsonData.dataset.forEach(parse);

function parse(item) {
    if (item.udp_bytes > 0) {
        udpDataset.push({
            x: item.tx_addr,
            y: item.rx_addr,
            r: Math.cbrt(item.udp_bytes),
            payload: item.udp_bytes,
            pktcount: item.pktcount
        });
    }
    if (item.tcp_bytes > 0) {
        tcpDataset.push({
            x: item.tx_addr,
            y: item.rx_addr,
            r: Math.cbrt(item.tcp_bytes),
            payload: item.tcp_bytes,
            pktcount: item.pktcount
        });
    }
    if (item.icmp_bytes > 0) {
        icmpDataset.push({
            x: item.tx_addr,
            y: item.rx_addr,
            r: Math.cbrt(item.icmp_bytes),
            payload: item.icmp_bytes,
            pktcount: item.pktcount
        })
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