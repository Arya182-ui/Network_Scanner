# Network Scanner

**Overview**

The Network Scanner is a Python-based tool designed for scanning and analyzing network devices. It enables users to scan IP ranges for open ports, detect operating systems and services, create visual network maps, and export scan results. The tool also features a graphical user interface (GUI) built with Tkinter and supports scheduled scans.

## Features

- **Network Scanning:** Scan specified IP ranges and ports to detect active devices and open ports.
- **OS and Services Detection:** Utilize `nmap` to identify the operating system and services running on detected devices.
- **Visual Network Mapping:** Generate network maps with `Graphviz` to visualize network structure and services.
- **Result Export:** Export scan results to CSV or JSON files for easy analysis.
- **Notifications:** Receive desktop notifications upon scan completion.
- **GUI Interface:** A simple and intuitive interface for configuring scans and viewing results.
- **Scheduled Scanning:** Automate scans using the `schedule` library.

## Requirements

- **Python 3.x**
- **nmap**: Install using `pip install python-nmap`
- **psutil**: Install using `pip install psutil`
- **graphviz**: Install Graphviz from the [Graphviz official website](https://graphviz.gitlab.io/download/) and the Python package using `pip install graphviz`
- **plyer**: Install using `pip install plyer`
- **schedule**: Install using `pip install schedule`
- **tqdm**: Install using `pip install tqdm`

## Installation

1. **Clone the Repository:**

    ```bash
    git clone https://github.com/Arya182-ui/network-scanner.git
    cd network-scanner
    ```

2. **Install Dependencies:**

    Create a `requirements.txt` file with the required Python packages and run:

    ```bash
    pip install -r requirements.txt
    ```

3. **Install Graphviz:**

    Download and install Graphviz from the [Graphviz official website](https://graphviz.gitlab.io/download/). Ensure the Graphviz `bin` directory is added to your system `PATH`.

## Usage

### Command-Line Arguments

Run the script from the command line with the following arguments:

- `-r` or `--range`: Network range to scan (default: `192.168.206.0/24`)
- `-p` or `--ports`: List of ports to scan (default: `22 80 443 8080`)
- `-o` or `--output`: Output file name (CSV or JSON) (default: `results.csv`)

**Example:**

```bash
python network_scanner.py -r 192.168.1.0/24 -p 22 80 443 -o results.json
