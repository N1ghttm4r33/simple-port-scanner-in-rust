use tokio::net::TcpStream;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncWriteExt, AsyncReadExt, ErrorKind};
use tokio::io;
use std::str::FromStr;
use std::env;
use std::time::Duration;
use tokio::time::{timeout, Instant};
use std::sync::{Mutex, Arc};

#[derive(Debug, Clone, Copy)]
enum PortStatus {
  Open,
  Filtered,
  Closed,
  Discard,
}

async fn send_syn(addr: &SocketAddr) -> Result<(), io::Error> {
    let socket = TcpStream::connect(addr).await?;

    let (mut read_half, mut write_half) = socket.into_split();

    // Write the FIN packet
    write_half.write_all(&pnet::packet::tcp::TcpFlags::SYN.to_be_bytes()).await?;

    let mut buffer: Vec<u8> = [0; 4].to_vec();

    // Use `timeout` to set a deadline for reading
    let result = timeout(Duration::from_millis(1000), async {
        // Read the response
        read_half.read_to_end(&mut buffer).await
    }).await;

    match result {
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "Timeout")),
        Ok(test) => {
            let test_clone = &test;
            if test_clone.iter().next().is_some() {
                // Interpret the response
                let mut flags = 0u16;
                for i in 0..4 {
                    flags |= (buffer[i] as u16) << (8 * i);
                }

                if flags == (pnet::packet::tcp::TcpFlags::SYN | pnet::packet::tcp::TcpFlags::ACK).into() {
                    Ok(())
                } else if flags == (pnet::packet::tcp::TcpFlags::RST).into() {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "Connection reset",
                    ))
                } else if flags == (pnet::packet::tcp::TcpFlags::FIN).into() {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "Connection refused",
                    ))
                } else if flags == (pnet::packet::tcp::TcpFlags::PSH).into() {
                    Err(io::Error::new(io::ErrorKind::Other,
                        "Outro tipo de flag"))
                } else if flags == (pnet::packet::tcp::TcpFlags::URG).into() {
                    Err(io::Error::new(io::ErrorKind::Other,
                        "Outro tipo de flag"))
                } else if flags == (pnet::packet::tcp::TcpFlags::ECE).into() {
                    Err(io::Error::new(io::ErrorKind::Other,
                        "Outro tipo de flag"))
                } else if flags == (pnet::packet::tcp::TcpFlags::CWR).into() {
                    Err(io::Error::new(io::ErrorKind::Other,
                        "Outro tipo de flag"))
                } else {
                    Err(io::Error::new(io::ErrorKind::NotFound,
                        "Unknown error"))
                }    
            } else if test_clone.iter().next().is_none() {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "No response",
                ))
            } else {
                Err(io::Error::new(io::ErrorKind::NotFound,
                    "Unknown error"))
            }
        }
    }
}


async fn scan_port(host: &str, port: u16) -> PortStatus {
    let addr = SocketAddr::new(IpAddr::from_str(host).unwrap(), port);

    match send_syn(&addr).await {
        Ok(()) => PortStatus::Open,
        Err(ref e) if e.kind() == ErrorKind::ConnectionRefused => PortStatus::Closed,
        Err(ref e) if e.kind() == ErrorKind::AlreadyExists => PortStatus::Filtered,
        Err(ref e) if e.kind() == ErrorKind::ConnectionReset => PortStatus::Closed,
        Err(ref e) if e.kind() == ErrorKind::NotFound => PortStatus::Filtered,
        Err(ref e) if e.kind() == ErrorKind::TimedOut => PortStatus::Filtered,
        Err(ref e) if e.kind() == ErrorKind::Other => PortStatus::Discard,
        Err(_) => PortStatus::Filtered,
    }
}

#[tokio::main]
async fn main() {
    let start = Instant::now();
    let dst_ip_str = env::args().nth(1).expect("Informe o endereço IP de destino");
    let port_limit: u16 = env::args().nth(2).expect("Informe o limite de portas").parse::<u16>().unwrap();
    let hosts = vec![dst_ip_str];

    for host in hosts {
        let mut results: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let port_range = (1..=port_limit).collect::<Vec<_>>();
        let closed_ports = Arc::new(Mutex::new(Vec::new()));
        let discarted_ports = Arc::new(Mutex::new(Vec::new()));

        for &port in &port_range {
            let host_clone = host.clone();
            let closed_ports_clone = closed_ports.clone();
            let discarted_ports_clone = discarted_ports.clone();
            let task = tokio::spawn(async move {
                let status = scan_port(&host_clone, port).await;

                match status {
                    PortStatus::Open => println!("Port {}: Open", port),
                    PortStatus::Filtered => println!("Port {}: Filtered", port),
                    PortStatus::Closed => {
                        let mut guard = closed_ports_clone.lock().unwrap();
                        guard.push(1);
                    }
                    PortStatus::Discard => {
                        println!("Port {}: Discard", port);
                        let mut guard2 = discarted_ports_clone.lock().unwrap();
                        guard2.push(1);
                    }
                }  
            });
            results.push(task);
        }

        let _ = futures::future::join_all(results).await;
        let guard = closed_ports.lock().unwrap();
        let all_closed_ports = guard.len();
        let guard2 = discarted_ports.lock().unwrap();
        let discarted_ports = guard2.len();

        println!("\nPortas Fechadas: {:?}", all_closed_ports);
        println!("\nPortas Descartadas: {:?} \n", discarted_ports);
        println!("Portas Total: {}", &port_range.len());
        let elapsed = start.elapsed();
        println!("Elapsed time: {} seconds", elapsed.as_secs());
    }
}