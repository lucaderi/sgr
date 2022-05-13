import "contrib/sranka/telegram"

option task = {name: "cpuAlerts", every: 60s}
option t = {timeRangeStart: -1h, timeRangeStop: now(), windowPeriod: 10000ms}

bucketName = "Insert bucket name here"
tokenTel = "Insert telegram bot token"
channelTel = "Insert telegram channel"

//The whole point of this block is to yield something otherwise Flux complains
ignoreMe =
    from(bucket: bucketName)
        |> range(start: t.timeRangeStart, stop: t.timeRangeStop)
        |> yield()

lastUsage =
    from(bucket: bucketName)
        |> range(start: t.timeRangeStart, stop: t.timeRangeStop)
        |> filter(fn: (r) => r["_measurement"] == "cpuMonitor")
        |> filter(fn: (r) => r["_field"] == "CPU Percent Usage")
        |> last()

higherBand =
    from(bucket: bucketName)
        |> range(start: t.timeRangeStart, stop: t.timeRangeStop)
        |> filter(fn: (r) => r["_measurement"] == "cpuMonitor")
        |> filter(fn: (r) => r["_field"] == "Higher Bound")
        |> last()

lowerBand =
    from(bucket: bucketName)
        |> range(start: t.timeRangeStart, stop: t.timeRangeStop)
        |> filter(fn: (r) => r["_measurement"] == "cpuMonitor")
        |> filter(fn: (r) => r["_field"] == "Lower Bound")
        |> last()

higherBandExtract =
    higherBand
        |> findRecord(fn: (key) => true, idx: 0)

lowerBandExtract =
    lowerBand
        |> findRecord(fn: (key) => true, idx: 0)

cpuAlert =
    lastUsage
        |> map(
            fn: (r) =>
                ({r with level:
                        if r._value > 90 then
                            "critical"
                        else if r._value > higherBandExtract._value or r._value < lowerBandExtract._value then
                            "warning"
                        else
                            "normal",
                }),
        )

ExtractAlert =
    cpuAlert
        |> findRecord(fn: (key) => true, idx: 0)

if ExtractAlert.level == "critical" then
    telegram.message(
        url: "https://api.telegram.org/bot",
        token: tokenTel,
        channel: channelTel,
        text: "Host CPU usage higher than 90%",
    )
else
    0

if ExtractAlert.level == "warning" then
    telegram.message(
        url: "https://api.telegram.org/bot",
        token: tokenTel,
        channel: channelTel,
        text: "Host CPU usage sudden change",
    )
else
    0