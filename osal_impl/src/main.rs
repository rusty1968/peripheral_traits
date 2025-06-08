use std::thread;
use std::time::Duration;

use osal::ipc::{IpcSyscalls, IpcWaitResult};
mod ipc;

fn main() {
    let queue_name = "/example_queue";

    // Create the IPC object
    let ipc = ipc::PosixIpc::new(queue_name).expect("Failed to create message queue");

    // Clone for the receiver thread
    let ipc_receiver = ipc::PosixIpc::new(queue_name).expect("Failed to open message queue for receiver");

    // Spawn a thread to simulate receiving
    let handle = thread::spawn(move || {
        let mut buffer = vec![0u8; 128];
        match ipc_receiver.ipc_rcv(&mut buffer, 0, None, Some(Duration::from_secs(5))) {
            Ok(IpcWaitResult::MsgRcvd) => {
                println!("Received message: {}", String::from_utf8_lossy(&buffer));
            }
            _ => println!("No message received or error occurred"),
        }
    });

    // Give the receiver a moment to start
    thread::sleep(Duration::from_millis(100));

    // Send a message
    let message = b"Hello from sender!";
    ipc.ipc_send(String::from("unused_target"), message.as_ref(), None)
        .expect("Failed to send message");

    // Wait for the receiver to finish
    handle.join().unwrap();
}
