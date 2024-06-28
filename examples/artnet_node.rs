use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

use tiny_artnet::{Art, PortTypes};
use tiny_artnet::{Dmx, PortAddress};

fn main() {
    // Use the default ArtNet Port
    let port = tiny_artnet::PORT;
    let broadcast_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), port);

    // Lookup the local IP Address
    let ip_address: [u8; 4] = match local_ip_address::local_ip().unwrap() {
        IpAddr::V4(ip) => ip.octets(),
        IpAddr::V6(_ip) => unimplemented!("IPV6 support"),
    };

    // Lookup the mac address
    let mac_address_bytes = mac_address::get_mac_address().unwrap().unwrap().bytes();

    // Open the UDP socket
    let socket = UdpSocket::bind(SocketAddr::from((ip_address, port))).unwrap();
    socket.set_broadcast(true).unwrap();

    println!(
        "\n\nServer Started, listening on {}:{}",
        IpAddr::from(ip_address),
        port
    );

    // Receives a single datagram message on the socket. If `buf` is too small to hold
    // the message, it will be cut off.
    let mut buf = [0; 65_507];

    let poll_reply = tiny_artnet::PollReply {
        ip_address: &ip_address,
        port,
        firmware_version: 0x0700,
        short_name: "Watchout",
        long_name: "Dataton WATCHOUT 7",
        mac_address: &mac_address_bytes,
        // This Node has one port
        num_ports: 1,
        // This node has one output channel
        port_types: [PortTypes::DMX512; 4],
        // Report that data is being output correctly
        good_output_a: &[0b10000000, 0, 0, 0],
        ..Default::default()
    };

    loop {
        let (len, from_addr) = socket.recv_from(&mut buf).unwrap();

        match Art::from_slice(&buf[..len]) {
            Ok(Art::Dmx(dmx)) => {
                if dmx.port_address.universe() == 6 {
                    let out_dmx = Dmx {
                        sequence: dmx.sequence,
                        physical: dmx.physical,
                        port_address: PortAddress::new(
                            dmx.port_address.net(),
                            dmx.port_address.sub_net(),
                            8,
                        )
                        .unwrap(),
                        data: dmx.data,
                    };

                    println!("=> {}", &out_dmx);
                    let art = Art::Dmx(out_dmx);

                    let mut out_buf = [0; 2048];
                    art.serialize(&mut out_buf);
                    socket.send_to(&out_buf, broadcast_addr).unwrap();
                } else {
                    println!(">= {}", &dmx);
                }
            }
            Ok(Art::Sync) => {
                println!("RX: ArtSync");
            }
            Ok(Art::Poll(poll)) => {
                println!("RX: ArtPoll {:?}", poll);

                let msg_len = poll_reply.serialize(&mut buf);
                socket.send_to(&buf[..msg_len], &from_addr).unwrap();
            }
            Err(err) => {
                if let tiny_artnet::Error::UnsupportedOpCode(code) = err {
                    eprintln!("Unsupported OP_CODE = 0x{:0x}", code);
                } else {
                    eprintln!("Error: {:?}", err);
                }
            }
            msg => {
                println!("Something else! {:?}", msg);
            }
        };
    }
}
