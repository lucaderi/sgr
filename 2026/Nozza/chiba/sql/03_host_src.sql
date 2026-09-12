CREATE TABLE IF NOT EXISTS chiba.host_src_agg
(
    TIME_BUCKET DateTime,
    SRCADDR IPv6,
    
    UNIQUE_DSTADDR AggregateFunction(uniq, IPv6),
    
    EXACT_START AggregateFunction(min, UInt32),
    EXACT_END AggregateFunction(max, UInt32),

    TOTAL_DPKTS AggregateFunction(sum, UInt64),
    TOTAL_DOCTETS AggregateFunction(sum, UInt64),
    
    UNIQUE_DSTPORT AggregateFunction(uniqExact, UInt16),

    PROT UInt8
) ENGINE = AggregatingMergeTree()
ORDER BY (TIME_BUCKET, SRCADDR, PROT);

CREATE MATERIALIZED VIEW IF NOT EXISTS chiba.host_src_mv
TO chiba.host_src_agg
AS
SELECT 
    toStartOfMinute(toDateTime(START_TIME)) AS TIME_BUCKET,
    SRCADDR,
    uniqState(DSTADDR) AS UNIQUE_DSTADDR,
    minState(START_TIME) AS EXACT_START,
    maxState(END_TIME) AS EXACT_END,
    sumState(toUInt64(DPKTS)) AS TOTAL_DPKTS,
    sumState(toUInt64(DOCTETS)) AS TOTAL_DOCTETS,
    uniqExactState(DSTPORT) AS UNIQUE_DSTPORT,
    PROT
FROM chiba.ingest_flows     
GROUP BY TIME_BUCKET, SRCADDR, PROT;
 
