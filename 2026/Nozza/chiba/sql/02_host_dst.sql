CREATE TABLE IF NOT EXISTS chiba.host_dst_agg
(
    TIME_BUCKET DateTime,
    DSTADDR IPv6,
    
    -- Distribution indicator
    UNIQUE_SRCADDR AggregateFunction(uniq, IPv6),
    
    -- Time bounds
    EXACT_START AggregateFunction(min, UInt32),
    EXACT_END AggregateFunction(max, UInt32),
    
    -- Volumetric indicators
    TOTAL_DPKTS AggregateFunction(sum, UInt64),
    TOTAL_DOCTETS AggregateFunction(sum, UInt64)
) ENGINE = AggregatingMergeTree() 
ORDER BY (TIME_BUCKET, DSTADDR);

CREATE MATERIALIZED VIEW IF NOT EXISTS chiba.host_dst_mv
TO chiba.host_dst_agg
AS 
SELECT 
    toStartOfMinute(toDateTime(START_TIME)) AS TIME_BUCKET,
    DSTADDR,
    uniqState(SRCADDR) AS UNIQUE_SRCADDR,
    minState(START_TIME) AS EXACT_START,
    maxState(END_TIME) AS EXACT_END,
    sumState(toUInt64(DPKTS)) AS TOTAL_DPKTS,
    sumState(toUInt64(DOCTETS)) AS TOTAL_DOCTETS
FROM chiba.ingest_flows
GROUP BY TIME_BUCKET, DSTADDR;