# Network Traffic Analyzer

![Network Analysis](https://github.com/rudrakshmohanty/Network-Traffic-Analysis/blob/main/assests/Gemini_Generated_Image_bybkbmbybkbmbybk.jpeg?height=100&width=100)

A high-performance, memory-efficient network traffic analysis tool built with PySpark and Scapy for processing large PCAP files and real-time network streams.

## 🚀 Features

- **Memory-Efficient Processing**: Analyzes large PCAP files in batches to minimize memory usage
- **Comprehensive Traffic Analysis**: Extracts detailed network metrics and protocol statistics
- **Machine Learning Integration**: Performs K-means clustering to identify traffic patterns
- **Interactive Visualizations**: Generates rich, interactive dashboards with Plotly
- **Real-time Monitoring**: Supports streaming analysis of live network traffic
- **Spark Integration**: Leverages Apache Spark for distributed processing and performance

## 📊 Interactive Dashboard

The analyzer generates an interactive HTML dashboard that provides comprehensive visualizations of your network traffic data.

![Dashboard Preview](https://github.com/rudrakshmohanty/Network-Traffic-Analysis/blob/main/assests/Screenshot%20from%202025-04-16%2023-34-23.png)

### Dashboard Features:

- **Protocol Distribution**: Visual breakdown of traffic by protocol type
- **Traffic Metrics**: Comparative analysis of packet counts and sizes
- **Clustering Results**: Visual representation of traffic pattern clusters
- **Source/Destination Analysis**: IP address distribution and connection patterns

### Viewing the Dashboard:

1. After running the analyzer, find the dashboard files in your output directory:
   - `network_traffic_dashboard.html` - Main traffic analysis dashboard
   - `protocol_analysis_dashboard.html` - Detailed protocol analysis

2. Open the HTML files in any modern web browser to interact with the visualizations:
   ```bash
   # On Linux/macOS
   open network_analysis_output/network_traffic_dashboard.html
   
   # On Windows
   start network_analysis_output/network_traffic_dashboard.html
