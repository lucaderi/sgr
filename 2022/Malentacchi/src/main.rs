use clap::{Parser};
use std::{time::{Duration, Instant}, process::exit, io::stdout, thread};
use snmp::{SyncSession, Value};
use std::fs;
use std::path::Path;
use toml;


use influxdb::Client as InfluxClient;
use chrono::Utc;

mod utils;
use crate::utils::{funcs::*,constants::*};
#[derive(Parser)]
#[clap(name="snmpfetch",
    //author, 
    version="1.0", 
    about="SNMP", 
    long_about = None)]

struct Args {

    /// IP address
    host: String,

    /// SNMP community
    #[clap(short, long, default_value="public")]
    community: String,

    /// SNMP port
    #[clap(short, long, default_value="161")]
    port: u16,

    /// RAM usage outliers
    #[clap(short, long)]
    threshold: Option<f64>,

    /// Loop the program
    #[clap(short = 'L', long)]
    to_loop: bool,
}

struct Process {
    pid: u32,
    score: u32,
}

fn zscore(session: &mut SyncSession,threshold: f64) -> Vec<Process>
{
    let mut process_number = 0;
    let mut response = match session.get(HR_SYSTEM_PROCESSES)
    {
        Ok(r) => r,
        Err(_) => {
            eprintln!("The IP or community string is incorrect");
            exit(1);
        }
    };
    if let Some((_, Value::Unsigned32(descr))) = response.varbinds.next() {
        //println!("hrSystemProcesses: {}",descr);
        process_number = descr; 
    }

    let mut v = vec![];

    let mut temp = HR_SW_RUN_PERF_MEM.clone(); 
    let mut sum: usize =0;
    for _n in 0..process_number {
        response = session.getnext(&temp).expect("Error getting hrSWRunPerfMem");
        if let Some((_oid, Value::Integer(descr))) = response.varbinds.next() {
            temp[11] = _oid.to_string().split('.').last().unwrap().parse::<u32>().unwrap();
            sum += descr as usize;
            v.push(Process {
                pid: temp[11],
                score: descr as u32,
            });
            //println!("{} {} {}",_n,temp[11],descr);
        }
    }
    //println!("hrSWRunPerfMem: {}",sum);

    let average: f64 = sum as f64/ process_number as f64;
    //println!("average: {}",average);
    let variance: f64 = v.iter().map(|x| (x.score as f64 - average).powf(2.0)).sum::<f64>()/v.len() as f64;
    //println!("variance: {}",variance);
    let stddev: f64 = (variance as f64).sqrt();
    //println!("stddev: {}",stddev);
    let mut v_outliers: Vec<Process>= vec![];
    println!("Outliers: ");
    for n in 0..v.len()
    {
        let zscore = (v[n].score as f64 - average)/stddev;
        //println!("{} {} {}",v[n].pid,v[n].score,zscore);
        if zscore > threshold || zscore < -threshold {
            println!("|-> {{ PID({}) Memory-Allocated({} KB) }}",v[n].pid,v[n].score);
            // todo!("clone")
            v_outliers.push(Process { pid: v[n].pid, score: v[n].score }); 
        }
    }
    if v_outliers.is_empty()
    {
        println!("None");
    }

    v_outliers
}



fn main() {
    let args = Args::parse();
    let agent_addr = format!("{}:{}", args.host, args.port);
    let community = args.community.as_bytes();

    let timeout       = Duration::from_secs(2);

    let mut sess = SyncSession::new(agent_addr, community, Some(timeout), 0).expect("Error creating session");
    let mut now = Instant::now();

    let mut stdout = stdout();

    // --- Configs --- 
    let config_toml: Config;
    if Path::new("snmpfetch_config.toml").is_file()
    {
        let content = fs::read_to_string("snmpfetch_config.toml").expect("Error reading file");
        config_toml = match toml::from_str(&content)
        {
            Ok(c) => c,
            Err(_) => {
                eprintln!("Error parsing config file");
                exit(1);
            }
        };
    }
    else 
    {
        create_default_toml();
        config_toml = Config::new(String::from(""), 3600, 1,80,500,String::from("http://localhost:8086"),String::from("test"),String::from("http://localhost:3000"));
    }

    let client = InfluxClient::new(config_toml.database.influxdb_url, &config_toml.database.influxdb_name);
    now = now.checked_sub(Duration::from_secs(config_toml.timings.webhook_pause)).expect("Error subtracting duration");

    let url = gen_url(&config_toml.database.influxdb_name);
    if args.to_loop { cls(&mut stdout); }

    loop {





        let mut msg: String = String::from(""); 

        // --- Name ---
        let mut response = match sess.get(SYS_NAME) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("SNMP Error: {:?}",e);
                exit(1);
            }
        };
        if let Some((_, Value::OctetString(descr))) = response.varbinds.next() {
            println!("sysName: {}", String::from_utf8_lossy(descr));
            println!("{:-<1$}", "", descr.len() + 9);
        }

        // --- Description ---
        response = sess.get(SYS_DESCR).expect("Error getting sysDescr");
        if let Some((_, Value::OctetString(descr))) = response.varbinds.next() {
            println!("sysDescr: {}",String::from_utf8_lossy(descr));
        }

        // --- Uptime ---
        response = sess.get(SYS_UPTIME).expect("Error getting sysUptime");
        if let Some((_, Value::Timeticks(descr))) = response.varbinds.next() {
            println!("sysUptime: {} ({})",sec_to_date((descr/100).into()),descr);
        }

        response = sess.get(HR_SYSTEM_UPTIME).expect("Error getting hrSystemUptime");
        if let Some((_, Value::Timeticks(descr))) = response.varbinds.next() {
            println!("hrSystemUptime: {} ({})",sec_to_date((descr/100).into()),descr);
        }

        // --- Processes ---
        response = sess.get(HR_SYSTEM_PROCESSES).expect("Error getting hrSystemProcesses");
        if let Some((_, Value::Unsigned32(descr))) = response.varbinds.next() {
            println!("hrSystemProcesses: {}",descr);
        }

        // --- CPU ---
        response = sess.get(SS_CPU_NUM_CPUS).expect("Error getting ssCpuNumCpus");
        if let Some((_, Value::Integer(descr))) = response.varbinds.next() {
            println!("ssNumCPUs: {}",descr);
        }

        response = sess.getbulk(&[SS_CPU_RAW],0,4).expect("Error getting ssCpuRaw");
        let mut cpu_usage = vec![0;4]; 
        let mut sum_cpu = 0;
        for i in 0..4 {
            if let Some((_oid, Value::Counter32(descr))) = response.varbinds.next() {
                cpu_usage[i] = descr;
                sum_cpu += descr;
                //println!("|-> {}: {}",_oid,descr);
            }
        }
        if sum_cpu != 0
        {
            println!("cpuUsage:");
            let user = cpu_usage[0] as f32/sum_cpu as f32*100.0;  
            let system = cpu_usage[2] as f32/sum_cpu as f32*100.0;
            println!("|-> User: {:.2}%",user);
            println!("|-> Nice: {:.2}%",cpu_usage[1] as f32/sum_cpu as f32*100.0);
            println!("|-> System: {:.2}%",system);
            println!("|-> Idle: {:.2}%",cpu_usage[3] as f32/sum_cpu as f32*100.0);

        }
        
        // --- RAM ---
        let mut memory_size = 0;
        response = sess.get(MEM_TOTAL_REAL).expect("Error getting memTotalReal");
        if let Some((_, Value::Integer(descr))) = response.varbinds.next() {
            println!("memTotal: {:.2} GB ({} KB)",descr as f64/(1024.0 * 1024.0),descr);
            memory_size = descr;
        }
        
        response = sess.get(MEM_AVAIL_REAL).expect("Error getting memAvailReal");
        let mut current_free = 0;
        if let Some((_, Value::Integer(descr))) = response.varbinds.next() {
            current_free = descr;

        }

        response = sess.get(MEM_CACHED).expect("Error getting memCached");
        let mut current_cached = 0;
        if let Some((_, Value::Integer(descr))) = response.varbinds.next() {
            current_cached = descr;
        }

        response = sess.get(MEM_BUFFER).expect("Error getting memBuffer");
        if let Some((_, Value::Integer(descr))) = response.varbinds.next() {
            let mem_used = memory_size - (descr+current_free+current_cached);
            let mem_perc = (mem_used as f32/memory_size as f32)*100.0;

            let reading = ValueReading{ time: Utc::now(), value: mem_perc as u32 };
            if args.to_loop 
            {
                write_to_db(&client, reading, "memory_used_percentage");
                if mem_perc > config_toml.thresholds.used_mem as f32 {
                    msg.push_str(format!("Memory Used: {} GB ({:.1}%)\n",mem_used,mem_perc).as_str());
                }
            }
            println!("memUsed: {:.2} GB ({} KB) ({:.1}%)",mem_used as f64/(1024.0 * 1024.0),mem_used,mem_perc);
        } 


        // --- Load --- 
        response = sess.getbulk(&[LA_LOAD],0,3).expect("Error getting laLoad");
        for n in [1,5,15]
        {
            if let Some((_, Value::Integer(descr))) = response.varbinds.next() {
                if n == 1
                {
                    let reading = ValueReading{ time: Utc::now(), value: descr as u32 };
                    println!("Loads:");
                    if args.to_loop
                    {
                        write_to_db(&client, reading, "cpu_load_1m");
                        if descr as u32 > config_toml.thresholds.load_1m
                        {
                            msg.push_str(format!("Load 1m: {}\n",descr).as_str());
                        }
                    }
                }
                println!("|-> {}m: {}",n,descr);
            }
        }

        // --- Z-Score ---
        if args.threshold.is_some() == true
        {
            let threshold = args.threshold.unwrap();
            let n_outliers = zscore(&mut sess,threshold);
            if !n_outliers.is_empty()
            {
                msg.push_str("Outliers: [");
            }
            for i in 0..n_outliers.len()
            {
                msg.push_str(format!(" {{ PID({}) Memory-Allocated({} KB) }}",n_outliers[i].pid,n_outliers[i].score).as_str());
                if i != n_outliers.len()-1
                {
                    msg.push_str(",");
                }
            }
            msg.push_str("]\n");
        }

        if !args.to_loop { break; }

        if msg.len() > 0 && !config_toml.contacts.webhook.is_empty() && check_time_passed(now, config_toml.timings.webhook_pause)
        {
            msg.push_str(format!("[Graphs]({}/{})\n---\n",config_toml.database.grafana_url,url).as_str());
            match send_post(msg, &config_toml.contacts.webhook)
            {
                Ok(_) => {
                    now = Instant::now();
                }
                Err(_) => {
                    eprintln!("Error sending webhook");
                }
            }
        }

        thread::sleep(Duration::from_secs(config_toml.timings.interval));
        cls(&mut stdout);
    }

}

