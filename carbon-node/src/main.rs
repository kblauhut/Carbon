use std::io::prelude::*;
use std::io::{self, Read};
use std::net::{TcpStream, SocketAddr, IpAddr, TcpListener, Shutdown};

const MAX_PEERS:u8 = 16;
const PING:u8 = 0x00;
const PONG:u8 = 0x01;

fn main() -> std::io::Result<()> {
    let mut peers: Vec<&str> = vec![];

    let listener = TcpListener::bind("0.0.0.0:7878")?;
    connect_peer("192.168.2.118:5000", &[0x48, 0x65, 0x6c, 0x6c, 0x6f]);
    for stream in listener.incoming() {
        handle_client(stream?);
    }
    Ok(())
}

fn handle_client(mut stream: TcpStream) {
    net_msg_enc(stream.local_addr().unwrap());

    let mut buf = [0; 1024];
    while match stream.read(&mut buf) {
        Ok(size) if size > 0 => {
            stream.write(&buf[0..size]).unwrap();
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

fn connect_peer(addr: &str, message: &[u8]) -> std::io::Result<()> {
    let mut buf = [0; 128]; // just a placeholder
    let mut stream = TcpStream::connect(addr)?;
    stream.write(&message)?;
    stream.read(&mut buf);
    
    println!("{:?}", buf);

    Ok(())
}

fn msg_send() {

}

fn net_msg_enc(addr: SocketAddr) {
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
}