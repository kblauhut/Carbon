use std::io::prelude::*;
use std::io::{self, Read};
use std::net::{TcpStream, SocketAddr, IpAddr, TcpListener, Shutdown, Ipv4Addr};

use rand::prelude::*;

const MAX_PEERS:u8 = 16;
const PING:u8 = 0x00;
const PONG:u8 = 0x01;
const REQ_PEER:u8 = 0x02;
const SND_PEER:u8 = 0x03;

fn main() -> std::io::Result<()> {
    let mut peers: Vec<SocketAddr> = vec![];
    peers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)), 7878));
    peers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 6)), 7878));
    println!("{:?}", peers);

    let listener = TcpListener::bind("0.0.0.0:7878")?;

    peer_connect("192.168.2.118:5000", &mut peers, REQ_PEER);
    for stream in listener.incoming() {
        handle_client(stream?, &peers);
    }
    Ok(())
}

fn handle_client(mut stream: TcpStream, peers: &Vec<SocketAddr>) {
    snd_peer_enc(stream.local_addr().unwrap());

    let mut buf = [0; 1024];
    let mut res = [0u8; 128];
    while match stream.read(&mut buf) {
        Ok(size) if size > 0 => {
            match buf[0] {
                PING => res[0] = PONG,
                REQ_PEER => {
                    let mut rng = thread_rng();
                    let rand = rng.gen_range(0..peers.len()-1);
                    let ip_enc = snd_peer_enc(peers[rand]);

                    res[0] = SND_PEER;
                    for (i) in (0..ip_enc.len()) {
                        res[1+i] = ip_enc[i];
                    }
                },
                _ => ()
            }
            stream.write(&res).unwrap();
            println!("{}", stream.peer_addr().unwrap());
            true
        },
        Ok(_) => false,
        Err(_) => {
            println!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
            stream.shutdown(Shutdown::Both).unwrap();
            false
        }
    } {}
}

fn peer_connect(addr: &str, peers: &mut Vec<SocketAddr>, msg_type: u8) -> std::io::Result<()> {
    let mut buf = [0u8; 128]; // just a placeholder
    let mut pkt_bytes = [0u8; 128]; // just a placeholder
    let mut stream = TcpStream::connect(addr)?;

    match msg_type {
        PING => pkt_bytes[0] = PING,
        REQ_PEER => pkt_bytes[0] = REQ_PEER,
        _ => ()
    }

    stream.write(&pkt_bytes)?;
    stream.read(&mut buf);
    
    println!("{:?}", buf);

    Ok(())
}

fn snd_peer_enc(addr: SocketAddr) -> [u8; 18] {
    let mut msg = [0u8; 18];
    match addr.ip() {
        IpAddr::V4(ip) => {
            msg[10] = 0xFF;
            msg[11] = 0xFF;
            for (i) in (0..ip.octets().len()) {
                msg[12+i] = ip.octets()[i];
            }
        },
        IpAddr::V6(ip) => {
            for (i) in (0..ip.octets().len()) {
                msg[i] = ip.octets()[i];
            }
        },
    }
    msg[16] = (addr.port() >> 8) as u8;
    msg[17] = addr.port() as u8;
    println!("{:X?}", msg);

    return msg;
}