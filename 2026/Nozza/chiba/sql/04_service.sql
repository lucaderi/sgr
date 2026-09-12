CREATE TABLE IF NOT EXISTS chiba.service_agg
(
    TIME_BUCKET DateTime,

    UNIQUE_SRCADDR AggregateFunction(uniq, IPv6),

    EXACT_START AggregateFunction(min, UInt32),
    EXACT_END AggregateFunction(max, UInt32),

    TOTAL_DPKTS AggregateFunction(sum, UInt64),
    TOTAL_DOCTETS AggregateFunction(sum, UInt64),
    
    DSTPORT UInt16,
    PROT UInt8
) ENGINE = AggregatingMergeTree()
ORDER BY (TIME_BUCKET, DSTPORT, PROT);

CREATE MATERIALIZED VIEW IF NOT EXISTS chiba.service_mv
TO chiba.service_agg
AS 
SELECT 
    toStartOfMinute(toDateTime(START_TIME)) AS TIME_BUCKET,
    uniqState(SRCADDR) AS UNIQUE_SRCADDR,
    minState(START_TIME) AS EXACT_START,
    maxState(END_TIME) AS EXACT_END,
    sumState(toUInt64(DPKTS)) AS TOTAL_DPKTS,
    sumState(toUInt64(DOCTETS)) AS TOTAL_DOCTETS,
    DSTPORT,
    PROT
FROM chiba.ingest_flows
GROUP BY TIME_BUCKET, DSTPORT, PROT;