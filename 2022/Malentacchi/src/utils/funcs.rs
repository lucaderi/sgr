
use std::{fs::File, io::{Write, Stdout}, collections::HashMap, time::Instant};
use crossterm::{terminal::{Clear, ClearType}, ExecutableCommand, cursor::MoveTo};
use serde_derive::Deserialize;
use reqwest::blocking::Client;

use influxdb::Client as InfluxClient;
use influxdb::InfluxDbWriteable;
use chrono::{DateTime, Utc};


#[derive(Deserialize)]
#[derive(Debug)]
pub struct Config {
    pub contacts: Contacts,
    pub timings: Timings,
    pub thresholds: Thresholds,
    pub database: Database,
}

impl Config {
    pub fn new(webhook: String, webhook_pause:u64,interval:u64,used_mem:u8,load_1m: u32, influxdb_url: String, influxdb_name: String, grafana_url: String) -> Config {
        Config { 
            contacts: Contacts { webhook }, 
            timings: Timings { webhook_pause, interval },
            thresholds: Thresholds { used_mem, load_1m },
            database: Database { influxdb_url, influxdb_name, grafana_url }
        }
    }
}


#[derive(Deserialize)]
#[derive(Debug)]
pub struct Contacts {
    pub webhook: String, 
}

#[derive(Deserialize)]
#[derive(Debug)]
pub struct Timings {
    pub webhook_pause: u64,
    pub interval: u64,
}

#[derive(Deserialize)]
#[derive(Debug)]
pub struct Thresholds {
    pub used_mem: u8,
    pub load_1m: u32,
}


#[derive(Deserialize)]
#[derive(Debug)]
pub struct Database {
    pub influxdb_url: String,
    pub influxdb_name: String,
    pub grafana_url: String,
}


pub fn send_post(desc: String,url:&str) -> Result<reqwest::blocking::Response,reqwest::Error>{
    let mut map = HashMap::new();
    map.insert("content", desc);

    let client = Client::new();
    let resp = client.post(url)
        .json(&map)
        .send();

   resp 
}

pub fn create_default_toml()
{
    let mut file = File::create("snmpfetch_config.toml").expect("Unable to create file");
    file.write_all(b"[contacts]
webhook = \"\"
    
[timings]
# Seconds to wait before sending webhook
webhook_pause = 3600
# Seconds between snmpfetch executions
interval = 1

[thresholds]
# Percentage of used memory
used_mem = 80
# Load 1 minute value
load_1m = 500

[database]
influxdb_url = \"http://localhost:8086\"
influxdb_name = \"test\"
grafana_url = \"http://localhost:3000\"").expect("Unable to write to file");
}

pub fn check_time_passed(origin_secs: Instant, threshhold: u64) -> bool {
    let now = Instant::now();
    let diff = now.duration_since(origin_secs);
    let diff_secs = diff.as_secs();
    if diff_secs >= threshhold {
        return true;
    }
    else {
        return false;
    } 
}

pub fn cls(stdout:&mut Stdout)
{
    match stdout.execute(Clear(ClearType::All))
    {
        Ok(_) => {
            match stdout.execute(MoveTo(0,0))
            {
                _ => (),
            }
        },
        Err(_) => eprintln!("Error clearing screen"),
    }
}


#[allow(unused_assignments)]
pub fn sec_to_date(mut secs: u64) -> String {
    let mut years = 0;
    let mut days = 0;
    let mut hours = 0;
    let mut minutes = 0;
    let mut seconds = 0;
    let mut result = String::new();

    if secs >= 31536000 {
        years = secs / 31536000;
        secs = secs % 31536000;
        result.push_str(&format!("{}y ", years));
    }
    if secs >= 86400 {
        days = secs / 86400;
        secs = secs % 86400;
        result.push_str(&format!("{}d ", days));
    }
    if secs >= 3600 {
        hours = secs / 3600;
        secs = secs % 3600;
        result.push_str(&format!("{}h ", hours));
    }
    if secs >= 60 {
        minutes = secs / 60;
        secs = secs % 60;
        result.push_str(&format!("{}m ", minutes));
    }
    seconds = secs;
    result.push_str(&format!("{}s", seconds));

    result
}


#[derive(InfluxDbWriteable)]
pub struct ValueReading {
    pub time: DateTime<Utc>,
    pub value: u32,
}

#[tokio::main]
pub async fn write_to_db(client:&InfluxClient, data:ValueReading, table_name: &str)
{

    let result = client.query(data.into_query(table_name)).await; 
    match result
    {
        Ok(_) | Err(_) => (),//eprintln!("Error writing to the Database"),
    }
}

pub fn gen_url(db_name:&String) -> String
{
    format!("explore?orgId=1&left=%7B%22datasource%22:%22{}%22,%22queries%22:%5B%7B%22refId%22:%22A%22,%22policy%22:%22default%22,%22resultFormat%22:%22time_series%22,%22orderByTime%22:%22ASC%22,%22tags%22:%5B%5D,%22groupBy%22:%5B%7B%22type%22:%22time%22,%22params%22:%5B%2210s%22%5D%7D,%7B%22type%22:%22fill%22,%22params%22:%5B%22null%22%5D%7D%5D,%22select%22:%5B%5B%7B%22type%22:%22field%22,%22params%22:%5B%22value%22%5D%7D,%7B%22type%22:%22mean%22,%22params%22:%5B%5D%7D%5D%5D,%22measurement%22:%22cpu_load_1m%22%7D,%7B%22refId%22:%22B%22,%22policy%22:%22default%22,%22resultFormat%22:%22time_series%22,%22orderByTime%22:%22ASC%22,%22tags%22:%5B%5D,%22groupBy%22:%5B%7B%22type%22:%22time%22,%22params%22:%5B%2210s%22%5D%7D,%7B%22type%22:%22fill%22,%22params%22:%5B%22null%22%5D%7D%5D,%22select%22:%5B%5B%7B%22type%22:%22field%22,%22params%22:%5B%22value%22%5D%7D,%7B%22type%22:%22mean%22,%22params%22:%5B%5D%7D%5D%5D,%22measurement%22:%22memory_used_percentage%22%7D%5D,%22range%22:%7B%22from%22:%22now-5m%22,%22to%22:%22now%22%7D%7D",db_name)
}