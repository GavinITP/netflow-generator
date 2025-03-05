# NetFlow Generator

This project simulates and generates NetFlow data, typically used for network monitoring and analysis. The generated NetFlow data can be sent to a remote server for further processing.

## Prerequisites

Before you start, make sure you have the following installed:

- **OS**: MacOS/Linux-based OS
- **Compiler**: GCC or Clang

## Setup Instructions

1. **Clone the repository:**

   ```bash
   git clone https://github.com/GavinITP/netflow-generator.git
   cd netflow-generator
   ```

2. **Compile the code:**

   This example use `g++` to compile the project files. Ensure that all `.cpp` files are compiled into an executable.

   ```bash
   g++ -o netflow-generator main.cpp netflow.cpp utils.cpp -std=c++11
   ```

3. **Run the program:**

   Execute the program with the following command:

   ```bash
   ./netflow-generator
   ```

   This will start generating NetFlow data and send it to a server.

## Code Overview

- **`main.cpp`**: The main entry point for the program. It sets up a UDP socket, generates the NetFlow data, serializes it, and sends it to the specified server.
- **`netflow.cpp`**: Contains the logic to generate and serialize NetFlow data, including header creation and payload generation for different network protocols.
- **`utils.cpp`**: Provides utility functions like generating random numbers and converting IP addresses to `uint32_t`.

## Set up NetFlow Collector for testing
Note: You can set up a VM to be your NetFlow collector.

- **Install recommend packages:**

```bash
sudo apt update
sudo apt install wireshark
sudo apt-get install nfdump
```
- View Netflow data using nfcapd from nfdump
```bash
# nfcapd -E  -p <port> -l <directory>
nfcapd -E  -p 9995 -l ./Desktop/netflow-log
```
- [View NetFlow data in wireshark](https://helpdesk.kaseya.com/hc/en-gb/articles/115003522631-How-to-view-NetFlow-in-WireShark)
```bash
sudo wireshark
```
