# NetFlow Generator

This project simulates and generates NetFlow data in pcap file, typically used for network monitoring and analysis.

## Setup Instructions

1. **Clone the repository:**

   ```bash
   git clone https://github.com/GavinITP/netflow-generator.git
   cd netflow-generator
   ```

2. **Compile the code:**

   ```bash
   clang++ -std=c++20 -O3 main.cpp netflow.cpp utils.cpp -o netflow_pcap_writer
   ```

   or

   ```bash
   g++ -std=c++20 -O3 main.cpp netflow.cpp utils.cpp -o netflow_pcap_writer
   ```

3. **Run the program:**

   ```bash
   ./netflow_pcap_writer
   ```

## Code Overview

- **`main.cpp`**: Generate raw packets with NetFlow data and writing them to a .pcap file.
- **`netflow.cpp`**: Contains the logic to generate and serialize NetFlow data.
- **`utils.cpp`**: Provides utility functions like generating random numbers and converting IP addresses to `uint32_t`.
