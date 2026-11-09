use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use praetor::egress::{
    decode_frame, encode_connect, encode_frame, serve, EgressConfig, EGRESS_CLOSE, EGRESS_CONNECT,
    EGRESS_DATA, EGRESS_ERROR, EGRESS_OK,
};
use praetor::handshake;
use praetor::wire::{Received, SecureChannel, CELL_OVERHEAD};
use praetor::xwing;

const CELL_SIZE: usize = 1024;

#[test]
fn rust_egress_forwards_tcp_streams() {
    let (server_pk, server_sk) = xwing::keygen();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let egress_addr = listener.local_addr().unwrap();
    let server_pk_for_thread = server_pk.clone();
    thread::spawn(move || {
        let _ = serve(
            listener,
            server_pk_for_thread,
            server_sk,
            EgressConfig {
                cell_size: CELL_SIZE,
                max_message_bytes: 64 << 20,
                connect_timeout: Duration::from_secs(2),
                log: false,
            },
        );
    });

    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut socket, _)) = echo.accept() {
            let mut buf = [0u8; 4096];
            loop {
                match socket.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if socket.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    });

    let mut stream = TcpStream::connect(egress_addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    let (c1, mut client_state) = handshake::client_init(&server_pk).unwrap();
    write_handshake_frame(&mut stream, &c1);
    let s1 = read_handshake_frame(&mut stream);
    let (confirm, session) = handshake::client_finish(&mut client_state, &s1).unwrap();
    write_handshake_frame(&mut stream, &confirm);

    let mut channel = SecureChannel::new(
        session.send_chain,
        session.recv_chain,
        CELL_SIZE,
        1024,
        64 << 20,
    )
    .unwrap();

    let connect = encode_connect("127.0.0.1", echo_port).unwrap();
    send_egress_frame(&mut stream, &mut channel, 1, EGRESS_CONNECT, &connect);
    let (id, op, _) = receive_egress_frame(&mut stream, &mut channel);
    assert_eq!(id, 1);
    assert_eq!(op, EGRESS_OK);

    // 20 KB crosses the 1,008-byte cell payload several times, so this also
    // covers fragmentation and reassembly in both directions.
    let sent = vec![0x5a; 20_000];
    send_egress_frame(&mut stream, &mut channel, 1, EGRESS_DATA, &sent);
    let mut echoed = Vec::new();
    while echoed.len() < sent.len() {
        let (id, op, payload) = receive_egress_frame(&mut stream, &mut channel);
        assert_eq!(id, 1);
        assert_eq!(op, EGRESS_DATA);
        echoed.extend_from_slice(&payload);
    }
    assert_eq!(echoed, sent);

    send_egress_frame(&mut stream, &mut channel, 1, EGRESS_CLOSE, &[]);
    let (id, op, _) = receive_egress_frame(&mut stream, &mut channel);
    assert_eq!(id, 1);
    assert_eq!(op, EGRESS_CLOSE);

    // A refused target must come back as ERROR, not close the session.
    let closed_port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let bad = encode_connect("127.0.0.1", closed_port).unwrap();
    send_egress_frame(&mut stream, &mut channel, 2, EGRESS_CONNECT, &bad);
    let (id, op, _) = receive_egress_frame(&mut stream, &mut channel);
    assert_eq!(id, 2);
    assert_eq!(op, EGRESS_ERROR);
}

fn write_handshake_frame(stream: &mut TcpStream, body: &[u8]) {
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();
}

fn read_handshake_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).unwrap();
    let len = u32::from_be_bytes(head) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).unwrap();
    body
}

fn send_egress_frame(
    stream: &mut TcpStream,
    channel: &mut SecureChannel,
    stream_id: u32,
    op: u8,
    payload: &[u8],
) {
    let frame = encode_frame(stream_id, op, payload).unwrap();
    for cell in channel.send(&frame).unwrap() {
        stream.write_all(&cell).unwrap();
    }
    stream.flush().unwrap();
}

fn receive_egress_frame(stream: &mut TcpStream, channel: &mut SecureChannel) -> (u32, u8, Vec<u8>) {
    loop {
        let mut cell = vec![0u8; CELL_OVERHEAD + CELL_SIZE];
        stream.read_exact(&mut cell).unwrap();
        if let Received::Complete { data, .. } = channel.receive(&cell).unwrap() {
            let (stream_id, op, payload) = decode_frame(&data).unwrap();
            return (stream_id, op, payload.to_vec());
        }
    }
}
