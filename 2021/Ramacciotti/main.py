import time, json, math, requests, threading, http.server
import plotly.graph_objects as go
from easysnmp import Session, exceptions

global divhtml
global sysInfo
global chatID
global telegramURL


class Server(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(bytes(divhtml, 'utf8'))


# Compute double exponential smoothing algorithm
def double_exponential_smoothing(values, alpha, beta, rho):
    # Compute predictions
    prediction = [values[0]]
    for n in range(1, len(values) + 2):
        if n == 1:
            level, trend = values[0], values[1] - values[0]
        if n >= len(values):
            value = prediction[-1]
        else:
            value = values[n]
        last_level, level = level, alpha * value + (1 - alpha) * (level + trend)
        trend = beta * (level - last_level) + (1 - beta)*trend
        prediction.append(level + trend)
    # Find standard deviation and calculate confidence bounds
    sumError = 0
    for index in range(len(values)):
        sumError += (values[index] - prediction[index])**2
    deviation = math.sqrt(sumError / (len(values) + 1))
    confidence = deviation * rho
    return (prediction[-3] - confidence, prediction[-3] + confidence)


# Call double exponential smoothing and check for the bounds
def analyzePrediction(values, alpha, beta, rho, string):
    (lowBound, upBound) = double_exponential_smoothing(values, alpha, beta, rho)
    if values[-1] > upBound:
        sendMessage(f'Anomaly detected on {sysInfo} - {string}: up to {values[-1]} bytes (instead of a maximum of {upBound})')
    if values[-1] < lowBound:
        sendMessage(f'Anomaly detected on {sysInfo} - {string}: down to {values[-1]} bytes (instead of a minimum of {lowBound})')


# Send message with Telegram API
def sendMessage(message):
    send = {'chat_id': chatID, 'text': message}
    requests.post(telegramURL, send).json()


# Sum all values in a list of integers
def sumValues(list):
    sum = 0
    for val in list:
        sum += int(val.value)
    return sum


# Detect a fault if value is greater than min
def checkFault(value, min, max, string, unit):
    if value > min:
        if value > max:
            sendMessage(f'ERROR on {sysInfo} - {string}: {value}{unit}')
        else:
            sendMessage(f'Warning on {sysInfo} - {string}: {value}{unit}')    


# Main function used to monitor the computer specified
def snmp():
    try:

        # Setup SNMP
        host = 'localhost'
        ver = 1
        comm = 'public'
        snmpSession = Session(hostname=host, version=ver, community=comm)
        
        # Get location and name of the monitored computer
        info = snmpSession.get(['sysName.0', 'sysLocation.0'])
        global sysInfo
        sysInfo = info[0].value + ' (' + info[1].value + ')'
        print(f'Monitoring {sysInfo}')

        # Setup Telegram bot
        with open('credentials.json') as json_file:
            telegram = json.load(json_file)
            global chatID, telegramURL
            telegramURL = f'https://api.telegram.org/bot{telegram["bot"]}/sendMessage'
            chatID = telegram['chat']

        # Initialize data structures and variables
        x_time = []
        y_cpu = []
        y_cputemp = []
        inOctList = []
        outOctList = []
        uptimeOld = 0
        inOctOld = 0
        outOctOld = 0

        firstIter = True

        while True:

            # Get data
            query = ['sysUpTimeInstance', 'ifInOctets.2', 'ifOutOctets.2', 'hrSystem.0']
            values = snmpSession.get(query)
            uptimeNew = int(values[0].value)
            inOctNew = int(values[1].value)
            outOctNew = int(values[2].value)
            cputemp = int(values[3].value)
            cores = snmpSession.walk("hrProcessorLoad")
            cpuavg = sumValues(cores) / len(cores)
            inOctDiff = inOctNew - inOctOld
            outOctDiff = outOctNew - outOctOld

            # If the computer has been restarted, skip the iteration (octets would give a negative difference)
            if uptimeNew < uptimeOld:
                print(f'Computer {sysInfo} has been restarted')
                sendMessage(f'Computer {sysInfo} has been restarted')
                uptimeOld = uptimeNew
                inOctOld = inOctNew
                outOctOld = outOctNew
                time.sleep(300)
                continue
            
            # Avoid appending huge values for octets on the first iteration, append only the difference between measurements
            if not firstIter:
                inOctList.append(inOctDiff)
                outOctList.append(outOctDiff)
            else:
                firstIter = False

            print(f'Stats: uptime {uptimeNew}, in {inOctDiff}, out {outOctDiff}, cpu {cpuavg}, cputemp {cputemp}')

            # Create the graph and update server html
            x_time.append(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            y_cpu.append(cpuavg)
            y_cputemp.append(cputemp)            
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=x_time, y=y_cpu, name="CPU usage"))
            fig.add_trace(go.Scatter(x=x_time, y=y_cputemp, name="CPU temperature"))
            fig.update_layout(title='CPU usage over time', yaxis_range=[0, 100], xaxis_title='Time', yaxis_title='Percentage/Degrees Celsius', legend_title='Legend', showlegend=True)
            global divhtml
            divhtml = fig.to_html()

            # Analyze CPU data
            checkFault(cpuavg, 80, 90, 'CPU Load', '%')
            checkFault(cputemp, 75, 95, 'CPU Temperature', ' °C')

            # Compare smoothing prediction with real value collected
            alpha = 0.5
            beta = 0.5
            rho = 3
            if len(inOctList) > 1 and len(outOctList) > 1:
                analyzePrediction(inOctList, alpha, beta, rho, 'InOct')
                analyzePrediction(outOctList, alpha, beta, rho, 'OutOct')

            # Update old variables
            uptimeOld = uptimeNew
            inOctOld = inOctNew
            outOctOld = outOctNew

            time.sleep(300)

    except exceptions.EasySNMPError as error:
        print(error)


if __name__ == "__main__":
    try:
        webServer = http.server.HTTPServer(('localhost', 7777), Server)
        threading.Thread(target=webServer.serve_forever, daemon=True).start()
        snmp()
    except KeyboardInterrupt:
        webServer.server_close()
        print('\nService stopped')
