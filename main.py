import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import time
import gc
from tqdm import tqdm

from pyspark.sql import SparkSession
from pyspark.sql.types import StructType, StructField, StringType, FloatType, IntegerType
from pyspark.ml.feature import VectorAssembler
from pyspark.ml.clustering import KMeans
from pyspark.ml.evaluation import ClusteringEvaluator

from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP

import base64
import io

import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.express as px
import json
import socket
from pyspark.streaming import StreamingContext
from pyspark.sql.functions import col, explode, window
from pyspark.sql import functions as F
from datetime import datetime
import threading

class MemoryEfficientPcapAnalyzer:
    def __init__(self, pcap_file, output_dir='network_analysis_output', memory_cap_mb=8000):
        """
        Initialize PCAP analyzer with staged processing for memory efficiency
        
        Args:
            pcap_file (str): Path to the PCAP file
            output_dir (str): Directory to save analysis results
            memory_cap_mb (int): Memory cap in MB
        """
        # Create output directory
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        
        # PCAP file path
        self.pcap_file = pcap_file
        
        # Memory cap
        self.memory_cap_mb = memory_cap_mb
        self.packet_batch_size = 10000  # Process packets in batches
        
        # Create event log directory for history server
        spark_event_log_dir = os.path.join(os.path.dirname(output_dir), "spark-events")
        os.makedirs(spark_event_log_dir, exist_ok=True)
        
        # Initialize Spark Session with memory constraints and UI enhancements
        self.spark = SparkSession.builder \
            .appName("MemoryEfficientPcapAnalysis") \
            .config("spark.executor.memory", f"{int(memory_cap_mb*0.7)}m") \
            .config("spark.driver.memory", f"{int(memory_cap_mb*0.7)}m") \
            .config("spark.memory.offHeap.enabled", "true") \
            .config("spark.memory.offHeap.size", f"{int(memory_cap_mb*0.2)}m") \
            .config("spark.sql.shuffle.partitions", "10") \
            .config("spark.default.parallelism", "10") \
            .config("spark.ui.enabled", "true") \
            .config("spark.ui.port", "4040") \
            .config("spark.ui.showConsoleProgress", "true") \
            .config("spark.eventLog.enabled", "true") \
            .config("spark.eventLog.dir", spark_event_log_dir) \
            .getOrCreate()
        
        # Get the Spark UI URL
        try:
            spark_ui_url = self.spark._jsc.sc().uiWebUrl().get()
            print(f"📊 Spark UI Dashboard is available at: {spark_ui_url}")
        except:
            print("📊 Spark UI available at http://localhost:4040 (default)")
        
        print(f"⚙️ Initialized with {memory_cap_mb}MB memory cap")
        
        # Features schema
        self.schema = StructType([
            StructField("filename", StringType(), True),
            StructField("packet_count", IntegerType(), True),
            StructField("total_bytes", FloatType(), True),
            StructField("unique_src_ips", IntegerType(), True),
            StructField("unique_dst_ips", IntegerType(), True),
            StructField("tcp_packet_count", IntegerType(), True),
            StructField("udp_packet_count", IntegerType(), True),
            StructField("icmp_packet_count", IntegerType(), True),
            StructField("http_packet_count", IntegerType(), True),
            StructField("dns_packet_count", IntegerType(), True),
            StructField("avg_packet_size", FloatType(), True),
            StructField("protocol_diversity", FloatType(), True),
            StructField("connection_density", FloatType(), True),
            StructField("syn_flood_indicator", FloatType(), True)
        ])
    
    def extract_features_in_stages(self):
        """
        Extract network features from PCAP file in memory-efficient stages
        
        Returns:
            dict: Comprehensive network traffic features
        """
        print(f"📊 Analyzing {self.pcap_file} in stages...")
        
        # Feature tracking
        features = {
            'filename': os.path.basename(self.pcap_file),
            'packet_count': 0,
            'total_bytes': 0,
            'unique_src_ips': set(),
            'unique_dst_ips': set(),
            'tcp_packet_count': 0,
            'udp_packet_count': 0,
            'icmp_packet_count': 0,
            'http_packet_count': 0,
            'dns_packet_count': 0,
            'protocol_types': set(),
            'connections': set(),
            'syn_packets': 0
        }
        
        # Stage 1: Process packets in batches to conserve memory
        try:
            with PcapReader(self.pcap_file) as pcap_reader:
                batch = []
                packet_count = 0
                
                # Process in small batches
                for packet in tqdm(pcap_reader, desc="Processing packets"):
                    batch.append(packet)
                    packet_count += 1
                    
                    # Process current batch when it reaches the batch size
                    if len(batch) >= self.packet_batch_size:
                        self._process_packet_batch(batch, features)
                        batch = []  # Clear batch to free memory
                        gc.collect()  # Force garbage collection
                        
                        # Print progress to show activity
                        if packet_count % (self.packet_batch_size * 5) == 0:
                            print(f"🔄 Processed {packet_count} packets so far...")
                
                # Process any remaining packets
                if batch:
                    self._process_packet_batch(batch, features)
                    
            features['packet_count'] = packet_count
            
            # Stage 2: Convert sets to integers and calculate derived metrics
            features['unique_src_ips'] = len(features['unique_src_ips'])
            features['unique_dst_ips'] = len(features['unique_dst_ips'])
            features['avg_packet_size'] = features['total_bytes'] / features['packet_count'] if features['packet_count'] > 0 else 0
            features['protocol_diversity'] = len(features['protocol_types']) / 5.0  # Normalize by max protocols
            
            unique_connections = len(features['connections'])
            features['connection_density'] = unique_connections / features['packet_count'] if features['packet_count'] > 0 else 0
            features['syn_flood_indicator'] = features['syn_packets'] / features['packet_count'] if features['packet_count'] > 0 else 0
            
            # Clean up temporary set data to free memory
            del features['protocol_types']
            del features['connections']
            del features['syn_packets']
            
            print(f"✅ Completed analysis: {features['packet_count']} packets processed")
            
            return features
            
        except Exception as e:
            print(f"❌ Error processing PCAP file: {e}")
            return None
    
    def _process_packet_batch(self, batch, features):
        """
        Process a batch of packets to update features
        
        Args:
            batch (list): List of packets
            features (dict): Features dictionary to update
        """
        for packet in batch:
            # Update total bytes
            features['total_bytes'] += len(packet)
            
            # Check for IP layer
            if IP in packet:
                features['unique_src_ips'].add(packet[IP].src)
                features['unique_dst_ips'].add(packet[IP].dst)
                features['connections'].add((packet[IP].src, packet[IP].dst))
            
            # Count protocol types
            if TCP in packet:
                features['tcp_packet_count'] += 1
                features['protocol_types'].add('TCP')
                
                # Check for SYN flags
                if packet[TCP].flags == 'S':
                    features['syn_packets'] += 1
                    
            if UDP in packet:
                features['udp_packet_count'] += 1
                features['protocol_types'].add('UDP')
                
            if ICMP in packet:
                features['icmp_packet_count'] += 1
                features['protocol_types'].add('ICMP')
                
            if DNS in packet:
                features['dns_packet_count'] += 1
                features['protocol_types'].add('DNS')
                
            if HTTP in packet:
                features['http_packet_count'] += 1
                features['protocol_types'].add('HTTP')
    
    def perform_clustering(self, features_df):
        """
        Perform K-means clustering on network features with memory efficiency
        
        Args:
            features_df (pyspark.sql.DataFrame): DataFrame with network features
        
        Returns:
            dict: Clustering results and visualizations
        """
        print("🔍 Performing clustering...")
        
        # Prepare features for clustering
        feature_columns = [
            'packet_count', 'total_bytes', 'unique_src_ips', 'unique_dst_ips',
            'tcp_packet_count', 'udp_packet_count', 'icmp_packet_count',
            'http_packet_count', 'dns_packet_count', 'avg_packet_size',
            'protocol_diversity', 'connection_density', 'syn_flood_indicator'
        ]
        
        # Vector assembler
        assembler = VectorAssembler(
            inputCols=feature_columns,
            outputCol="features"
        )
        
        features_vector_df = assembler.transform(features_df)
        
        # Use a reasonable K value based on data size
        rows = features_df.count()
        k_value = min(3, max(2, int(rows/2)))  # At least 2, at most 3 clusters
        
        # K-means clustering with limited iterations
        kmeans = KMeans(k=k_value, 
                        featuresCol="features", 
                        predictionCol="cluster",  # Changed from "cluster" to "prediction"
                        maxIter=10,  # Limit iterations for memory efficiency
                        seed=42)
        
        model = kmeans.fit(features_vector_df)
        
        # Add cluster predictions
        clustered_df = model.transform(features_vector_df)
        
        # Cluster evaluation - now this will work correctly
        evaluator = ClusteringEvaluator(predictionCol="prediction", featuresCol="features")
        silhouette = evaluator.evaluate(clustered_df)
        
        print(f"📊 Silhouette score: {silhouette:.4f} (closer to 1 is better)")
        
        # Save the execution plan to show in Spark UI
        print("📊 Creating query execution plan visualization (visible in Spark UI)")
        clustered_df.explain(True)  # Shows detailed execution plan in Spark UI
        
        # Visualization preparation (convert to Pandas for visualization)
        # Use only necessary columns to save memory
        mini_df = clustered_df.select('filename', 'packet_count', 'total_bytes', 'prediction').toPandas()
        
        # Create cluster visualization
        plt.figure(figsize=(10, 6))
        scatter = plt.scatter(
            mini_df['packet_count'], 
            mini_df['total_bytes'], 
            c=mini_df['prediction'],  # Changed from "cluster" to "prediction" 
            cmap='viridis'
        )
        
        # Add file labels to the points
        for i, filename in enumerate(mini_df['filename']):
            plt.annotate(filename, 
                         (mini_df['packet_count'].iloc[i], mini_df['total_bytes'].iloc[i]),
                         fontsize=8)
            
        plt.title('Network Traffic Clustering')
        plt.xlabel('Packet Count')
        plt.ylabel('Total Bytes')
        plt.colorbar(scatter, label='Cluster')
        
        # Save plot to buffer
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        plot_bytes = buf.getvalue()
        
        # Save directly to file to avoid base64 overhead
        plt.savefig(f"{self.output_dir}/cluster_visualization.png")
        print(f"📊 Cluster visualization saved to {self.output_dir}/cluster_visualization.png")
        plt.close()
        
        # Free memory
        del mini_df
        gc.collect()
        
        return {
            'silhouette_score': silhouette,
            'clustered_dataframe': clustered_df
        }
    
    def create_report(self, features_df, clustering_results):
        """
        Create a text-based report with clustering insights
        
        Args:
            features_df (pyspark.sql.DataFrame): Features DataFrame
            clustering_results (dict): Clustering analysis results
        """
        print("\n📋 Generating analysis report...")
        
        # Create a view for SQL queries
        features_df.createOrReplaceTempView("network_features")
        
        # Get basic statistics using SQL
        stats = self.spark.sql("""
            SELECT 
                filename,
                packet_count,
                total_bytes,
                unique_src_ips,
                unique_dst_ips,
                tcp_packet_count,
                udp_packet_count,
                icmp_packet_count,
                http_packet_count,
                dns_packet_count,
                protocol_diversity,
                connection_density
            FROM network_features
        """).collect()
        
        # Write report to file
        report_path = f"{self.output_dir}/analysis_report.txt"
        with open(report_path, 'w') as f:
            f.write("=== Network Traffic Analysis Report ===\n\n")
            
            for row in stats:
                f.write(f"File: {row['filename']}\n")
                f.write(f"Total Packets: {row['packet_count']}\n")
                f.write(f"Total Bytes: {row['total_bytes']:.2f}\n")
                f.write(f"Unique Source IPs: {row['unique_src_ips']}\n")
                f.write(f"Unique Destination IPs: {row['unique_dst_ips']}\n")
                f.write("\nProtocol Distribution:\n")
                f.write(f"  - TCP: {row['tcp_packet_count']} packets\n")
                f.write(f"  - UDP: {row['udp_packet_count']} packets\n")
                f.write(f"  - ICMP: {row['icmp_packet_count']} packets\n")
                f.write(f"  - HTTP: {row['http_packet_count']} packets\n")
                f.write(f"  - DNS: {row['dns_packet_count']} packets\n")
                f.write(f"\nProtocol Diversity: {row['protocol_diversity']:.2f}\n")
                f.write(f"Connection Density: {row['connection_density']:.4f}\n")
                f.write("\n---\n\n")
            
            # Add clustering information
            f.write("=== Clustering Results ===\n\n")
            f.write(f"Silhouette Score: {clustering_results['silhouette_score']:.4f}\n")
            f.write("\n(See cluster_visualization.png for the visual representation)\n")
        
        print(f"📝 Report generated at {report_path}")

    def create_interactive_dashboard(self, features_df, clustering_results):
        """
        Create an interactive HTML dashboard with Plotly visualizations
        
        Args:
            features_df (pyspark.sql.DataFrame): Features DataFrame
            clustering_results (dict): Clustering analysis results
        """
        print("\n📊 Generating interactive dashboard...")
        
        # Convert to pandas for visualization
        df = features_df.toPandas()
        
        # Create a multi-panel dashboard
        fig = make_subplots(
            rows=3, cols=2,
            subplot_titles=(
                "Packet Count by File", 
                "Protocol Distribution",
                "Traffic Metrics Comparison", 
                "Packet Size Analysis",
                "Traffic by Protocol", 
                "Clustering Results"
            ),
            specs=[
                [{"type": "bar"}, {"type": "pie"}],
                [{"type": "bar"}, {"type": "bar"}],
                [{"type": "bar"}, {"type": "scatter"}]
            ],
            vertical_spacing=0.1,
            horizontal_spacing=0.05
        )
        
        # 1. Packet Count by File (Bar Chart)
        fig.add_trace(
            go.Bar(
                x=df['filename'], 
                y=df['packet_count'],
                text=df['packet_count'],
                textposition='auto',
                marker_color='royalblue',
                name='Packet Count'
            ),
            row=1, col=1
        )
        
        # 2. Protocol Distribution (Pie Chart)
        protocols = ['tcp_packet_count', 'udp_packet_count', 'icmp_packet_count', 'http_packet_count', 'dns_packet_count']
        protocol_names = ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS']
        
        # Get total protocol counts across all files
        protocol_counts = [df[p].sum() for p in protocols]
        
        fig.add_trace(
            go.Pie(
                labels=protocol_names, 
                values=protocol_counts,
                textinfo='percent+label',
                hole=0.3,
                marker_colors=['#66c2a5', '#fc8d62', '#8da0cb', '#e78ac3', '#a6d854']
            ),
            row=1, col=2
        )
        
        # 3. Traffic Metrics Comparison (Bar Chart)
        for i, file in enumerate(df['filename']):
            fig.add_trace(
                go.Bar(
                    x=['Source IPs', 'Destination IPs'],
                    y=[df['unique_src_ips'][i], df['unique_dst_ips'][i]],
                    name=file,
                    text=[df['unique_src_ips'][i], df['unique_dst_ips'][i]],
                    textposition='auto'
                ),
                row=2, col=1
            )
        
        # 4. Packet Size Analysis (Bar Chart)
        fig.add_trace(
            go.Bar(
                x=df['filename'], 
                y=df['avg_packet_size'],
                text=[f"{size:.2f}" for size in df['avg_packet_size']],
                textposition='auto',
                marker_color='teal',
                name='Avg Packet Size (bytes)'
            ),
            row=2, col=2
        )
        
        # 5. Traffic by Protocol (Stacked Bar Chart)
        for i, (protocol, name) in enumerate(zip(protocols, protocol_names)):
            fig.add_trace(
                go.Bar(
                    x=df['filename'], 
                    y=df[protocol],
                    name=name
                ),
                row=3, col=1
            )
        
        # 6. Clustering Results (Scatter Plot)
        # Get the clustered data
        clustered_df = clustering_results['clustered_dataframe']
        scatter_df = clustered_df.select('filename', 'packet_count', 'total_bytes', 'prediction').toPandas()
        
        fig.add_trace(
            go.Scatter(
                x=scatter_df['packet_count'], 
                y=scatter_df['total_bytes'],
                mode='markers+text',
                text=scatter_df['filename'],
                textposition='top center',
                marker=dict(
                    size=15,
                    color=scatter_df['prediction'],
                    colorscale='Viridis',
                    showscale=True,
                    colorbar=dict(title='Cluster')
                ),
                hovertemplate='<b>File:</b> %{text}<br>'
                              '<b>Packets:</b> %{x}<br>'
                              '<b>Bytes:</b> %{y}<br>'
                              '<b>Cluster:</b> %{marker.color}'
            ),
            row=3, col=2
        )
        
        # Update layout for better visualization
        fig.update_layout(
            title_text="Network Traffic Analysis Dashboard",
            height=1000,
            width=1400,
            showlegend=True,
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=-0.2,
                xanchor="center",
                x=0.5
            ),
            template="plotly_white"
        )
        
        # Add annotations for dataset summary
        total_packets = df['packet_count'].sum()
        total_bytes = df['total_bytes'].sum()
        avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0
        
        summary_text = (
            f"Summary: {len(df)} Files, {total_packets:,} Packets, "
            f"{total_bytes/1e9:.2f} GB, {avg_packet_size:.2f} bytes/packet"
        )
        
        fig.add_annotation(
            xref="paper", yref="paper",
            x=0.5, y=1.05,
            text=summary_text,
            showarrow=False,
            font=dict(size=14)
        )
        
        # Add clustering metrics
        fig.add_annotation(
            xref="paper", yref="paper",
            x=0.75, y=0.32,
            text=f"Silhouette Score: {clustering_results['silhouette_score']:.4f}",
            showarrow=False,
            font=dict(size=12)
        )
        
        # Save the interactive dashboard
        dashboard_path = os.path.join(self.output_dir, 'network_traffic_dashboard.html')
        fig.write_html(dashboard_path, include_plotlyjs='cdn')
        print(f"📊 Interactive dashboard saved to {dashboard_path}")
        
        # Create detailed protocol analysis dashboard as well
        self._create_protocol_dashboard(df)
        
        return dashboard_path

    def _create_protocol_dashboard(self, df):
        """
        Create a separate dashboard focusing on protocol analysis
        
        Args:
            df (pandas.DataFrame): Features DataFrame
        """
        # Create a DataFrame with protocol information
        protocol_df = pd.DataFrame()
        
        # Extract protocol data
        for i, row in df.iterrows():
            file = row['filename']
            protocols = {
                'TCP': row['tcp_packet_count'],
                'UDP': row['udp_packet_count'],
                'ICMP': row['icmp_packet_count'],
                'HTTP': row['http_packet_count'],
                'DNS': row['dns_packet_count']
            }
            
            # Add to the DataFrame
            for protocol, count in protocols.items():
                new_row = pd.DataFrame([{
                    'filename': file,
                    'protocol': protocol,
                    'count': count,
                    'percentage': (count / row['packet_count']) * 100 if row['packet_count'] > 0 else 0
                }])
                protocol_df = pd.concat([protocol_df, new_row], ignore_index=True)
        
        # Create the protocol dashboard
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=(
                "Protocol Distribution by File", 
                "Protocol Percentage by File",
                "Protocol Comparison", 
                "Protocol Trends"
            ),
            specs=[
                [{"type": "bar"}, {"type": "bar"}],
                [{"type": "bar"}, {"type": "line"}]
            ],
            vertical_spacing=0.15
        )
        
        # 1. Protocol Distribution by File
        for protocol in ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS']:
            protocol_data = protocol_df[protocol_df['protocol'] == protocol]
            fig.add_trace(
                go.Bar(
                    x=protocol_data['filename'], 
                    y=protocol_data['count'],
                    name=protocol
                ),
                row=1, col=1
            )
        
        # 2. Protocol Percentage by File
        for protocol in ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS']:
            protocol_data = protocol_df[protocol_df['protocol'] == protocol]
            fig.add_trace(
                go.Bar(
                    x=protocol_data['filename'], 
                    y=protocol_data['percentage'],
                    name=protocol,
                    text=[f"{p:.1f}%" for p in protocol_data['percentage']],
                    textposition='auto'
                ),
                row=1, col=2
            )
        
        # 3. Protocol Comparison (Grouped bar chart)
        fig.add_trace(
            go.Bar(
                x=['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS'],
                y=[protocol_df[protocol_df['protocol'] == p]['count'].sum() for p in ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS']],
                name='Total Count',
                text=[f"{protocol_df[protocol_df['protocol'] == p]['count'].sum():,}" for p in ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS']],
                textposition='auto'
            ),
            row=2, col=1
        )
        
        # 4. Protocol Trends (Line chart)
        for protocol in ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS']:
            protocol_data = protocol_df[protocol_df['protocol'] == protocol]
            fig.add_trace(
                go.Scatter(
                    x=protocol_data['filename'], 
                    y=protocol_data['count'],
                    mode='lines+markers',
                    name=protocol
                ),
                row=2, col=2
            )
        
        # Update layout
        fig.update_layout(
            title_text="Protocol Analysis Dashboard",
            height=900,
            width=1400,
            barmode='group',
            showlegend=True,
            template="plotly_white"
        )
        
        # Save the protocol dashboard
        dashboard_path = os.path.join(self.output_dir, 'protocol_analysis_dashboard.html')
        fig.write_html(dashboard_path, include_plotlyjs='cdn')
        print(f"📊 Protocol analysis dashboard saved to {dashboard_path}")

class NetworkStreamProcessor:
    """
    Process network packets in real-time using Spark Streaming
    """
    def __init__(self, output_dir='network_stream_output', memory_cap_mb=4000, 
                 batch_interval=5, duration=60, interface='eth0'):
        """
        Initialize the network stream processor with Spark Streaming
        
        Args:
            output_dir (str): Directory to save analysis results
            memory_cap_mb (int): Memory cap in MB
            batch_interval (int): Streaming batch interval in seconds
            duration (int): Total duration to capture in seconds
            interface (str): Network interface to monitor
        """
        # Create output directory
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Streaming settings
        self.batch_interval = batch_interval
        self.duration = duration
        self.interface = interface
        
        # Create event log directory for history server
        spark_event_log_dir = os.path.join(os.path.dirname(output_dir), "spark-events")
        os.makedirs(spark_event_log_dir, exist_ok=True)
        
        # Initialize Spark Session with memory constraints and UI enhancements
        self.spark = SparkSession.builder \
            .appName("NetworkStreamProcessor") \
            .config("spark.executor.memory", f"{int(memory_cap_mb*0.7)}m") \
            .config("spark.driver.memory", f"{int(memory_cap_mb*0.7)}m") \
            .config("spark.memory.offHeap.enabled", "true") \
            .config("spark.memory.offHeap.size", f"{int(memory_cap_mb*0.2)}m") \
            .config("spark.sql.shuffle.partitions", "10") \
            .config("spark.default.parallelism", "10") \
            .config("spark.ui.enabled", "true") \
            .config("spark.ui.port", "4041") \
            .config("spark.ui.showConsoleProgress", "true") \
            .config("spark.eventLog.enabled", "true") \
            .config("spark.eventLog.dir", spark_event_log_dir) \
            .getOrCreate()
        
        # Get the Spark UI URL
        try:
            spark_ui_url = self.spark._jsc.sc().uiWebUrl().get()
            print(f"📊 Spark Streaming UI available at: {spark_ui_url}")
        except:
            print("📊 Spark Streaming UI available at http://localhost:4041 (default)")
            
        # Create a Spark Streaming Context
        self.ssc = StreamingContext(self.spark.sparkContext, self.batch_interval)
        
        # Initialize packet capture
        self.server_socket = None
        self.is_running = False
        self.packet_stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'http_packets': 0,
            'dns_packets': 0,
            'total_bytes': 0
        }
        
        # Define schema for streaming data
        self.schema = StructType([
            StructField("timestamp", FloatType(), True),
            StructField("protocol", StringType(), True),
            StructField("src_ip", StringType(), True),
            StructField("dst_ip", StringType(), True),
            StructField("packet_size", IntegerType(), True)
        ])
    
    def _packet_listener(self, port):
        """
        Listen for packets and forward them to Spark Streaming
        
        Args:
            port (int): Port to listen on
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('localhost', port))
            self.server_socket.listen(5)
            
            print(f"📡 Packet listener started on port {port}")
            
            # Accept client connections
            client_socket, address = self.server_socket.accept()
            print(f"📡 Client connected from {address}")
            
            # Capture packets from specified interface using scapy
            from scapy.sendrecv import sniff
            
            def packet_callback(packet):
                """Handle each captured packet"""
                if not self.is_running:
                    return
                
                packet_data = {}
                packet_data['timestamp'] = time.time()
                packet_data['protocol'] = 'OTHER'
                packet_data['src_ip'] = 'unknown'
                packet_data['dst_ip'] = 'unknown'
                packet_data['packet_size'] = len(packet)
                
                # Extract protocol information
                if IP in packet:
                    packet_data['src_ip'] = packet[IP].src
                    packet_data['dst_ip'] = packet[IP].dst
                    
                    if TCP in packet:
                        packet_data['protocol'] = 'TCP'
                        self.packet_stats['tcp_packets'] += 1
                    elif UDP in packet:
                        packet_data['protocol'] = 'UDP'
                        self.packet_stats['udp_packets'] += 1
                    elif ICMP in packet:
                        packet_data['protocol'] = 'ICMP'
                        self.packet_stats['icmp_packets'] += 1
                
                if DNS in packet:
                    packet_data['protocol'] = 'DNS'
                    self.packet_stats['dns_packets'] += 1
                elif HTTP in packet:
                    packet_data['protocol'] = 'HTTP'
                    self.packet_stats['http_packets'] += 1
                
                # Update packet statistics
                self.packet_stats['total_packets'] += 1
                self.packet_stats['total_bytes'] += packet_data['packet_size']
                
                # Send data to Spark Streaming
                try:
                    # Format as CSV for simple parsing
                    packet_line = f"{packet_data['timestamp']},{packet_data['protocol']},{packet_data['src_ip']},{packet_data['dst_ip']},{packet_data['packet_size']}\n"
                    client_socket.send(packet_line.encode('utf-8'))
                except:
                    pass
            
            # Start packet sniffing
            print(f"📡 Starting packet capture on interface {self.interface}")
            sniff(iface=self.interface, prn=packet_callback, count=0, store=0)
            
        except Exception as e:
            print(f"❌ Error in packet listener: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
    
    def start_streaming(self, port=9999):
        """
        Start Spark Streaming to process network packets in real-time
        
        Args:
            port (int): Port to use for streaming
        """
        try:
            print(f"🚀 Starting Spark Streaming analysis for {self.duration} seconds...")
            
            # Set running flag
            self.is_running = True
            
            # Start packet listener in a separate thread
            listener_thread = threading.Thread(target=self._packet_listener, args=(port,))
            listener_thread.daemon = True
            listener_thread.start()
            
            # Give listener time to start
            time.sleep(2)
            
            # Create DStream from socket data
            lines = self.ssc.socketTextStream('localhost', port)
            
            # Process each line (packet)
            def process_packet(line):
                try:
                    parts = line.split(',')
                    if len(parts) == 5:
                        timestamp, protocol, src_ip, dst_ip, packet_size = parts
                        return [
                            float(timestamp), 
                            protocol, 
                            src_ip, 
                            dst_ip, 
                            int(packet_size)
                        ]
                    return None
                except:
                    return None
            
            # Transform RDD and filter out None values
            packets = lines.map(process_packet).filter(lambda x: x is not None)
            
            # Window operations for analysis
            window_duration = self.batch_interval * 4  # e.g., 20 seconds
            sliding_duration = self.batch_interval  # e.g., 5 seconds
            
            # Count packets by protocol in sliding window
            protocol_counts = packets.map(lambda p: (p[1], 1)).reduceByKeyAndWindow(
                lambda x, y: x + y,
                lambda x, y: x - y,
                windowDuration=window_duration,
                slidingDuration=sliding_duration
            )
            
            # Calculate average packet size in sliding window
            packet_sizes = packets.map(lambda p: (1, p[4])).reduceByKeyAndWindow(
                lambda x, y: x + y,
                lambda x, y: x - y,
                windowDuration=window_duration,
                slidingDuration=sliding_duration
            )
            
            packet_counts = packets.countByWindow(window_duration, sliding_duration)
            
            # Print packet counts by protocol
            protocol_counts.pprint()
            
            # Print average packet size
            packet_sizes.pprint()
            
            # Print total packet count
            packet_counts.pprint()
            
            # Start streaming
            self.ssc.start()
            
            # Wait for the specified duration
            self.ssc.awaitTerminationOrTimeout(self.duration)
            
            # Stop streaming
            self.ssc.stop(stopSparkContext=False, stopGraceFully=True)
            
            # Reset running flag
            self.is_running = False
            
            print(f"✅ Spark Streaming analysis completed")
            
        except Exception as e:
            print(f"❌ Error in Spark Streaming: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()

def main():
    """
    Main function for memory-efficient PCAP analysis
    """
    # List of PCAP files to analyze one by one
    pcap_files = [
        "/media/zuesdrax/T7/Rudraksh/Bigdata_Dataset/OneDrive_2_3-27-2025/1.pcap",
        "/media/zuesdrax/T7/Rudraksh/Bigdata_Dataset/OneDrive_2_3-27-2025/10.pcap"
    ]
    
    # Create output directory
    output_dir = "network_analysis_output"
    os.makedirs(output_dir, exist_ok=True)
    
    # Initialize a list to store features from all files
    all_features = []
    
    print("\n🚀 Starting PCAP Analysis - Check Spark UI at http://localhost:4040 during processing")
    
    # Process each file sequentially
    for pcap_file in pcap_files:
        if not os.path.exists(pcap_file):
            print(f"⚠️ File not found: {pcap_file}")
            continue
            
        print(f"\n🔍 Processing {pcap_file}...")
        file_start_time = time.time()
        
        # Initialize analyzer with memory constraints
        analyzer = MemoryEfficientPcapAnalyzer(
            pcap_file=pcap_file,
            output_dir=output_dir,
            memory_cap_mb=8000  # 4GB memory cap
        )
        
        print("\n👀 You can view the Spark UI Dashboard during processing at http://localhost:4040")
        print("   - The 'Jobs' tab shows active and completed jobs")
        print("   - The 'Stages' tab shows task progress")
        print("   - The 'Environment' tab shows configuration")
        print("   - The 'Executors' tab shows memory usage\n")
        
        # Extract features with staged processing
        features = analyzer.extract_features_in_stages()
        
        if features:
            # Fix data types before adding to all_features
            features['total_bytes'] = float(features['total_bytes'])  # Convert to float
            all_features.append(features)
            
        file_end_time = time.time()
        print(f"⏱️ File processed in {file_end_time - file_start_time:.2f} seconds")
        
        # Explicitly stop the Spark session to free memory
        analyzer.spark.stop()
        del analyzer
        gc.collect()
        time.sleep(1)  # Brief pause to ensure resources are released
    
    # After processing all files, create a new session for the final analysis
    if all_features:
        print("\n🔄 Creating combined analysis...")
        
        final_analyzer = MemoryEfficientPcapAnalyzer(
            pcap_file="combined_analysis",  # Placeholder
            output_dir=output_dir,
            memory_cap_mb=8000
        )
        
        # Display dashboard information more clearly
        print("\n" + "=" * 60)
        print("📊 SPARK DASHBOARD INFORMATION")
        print("=" * 60)
        print("   The Spark UI is now available for exploring cluster behavior")
        print("   URL: http://localhost:4040")
        print("   Key tabs to inspect:")
        print("   - Jobs: Monitor running and completed jobs")
        print("   - Stages: View task distribution and skew")
        print("   - Storage: Check cached data")
        print("   - Environment: View configuration")
        print("=" * 60 + "\n")
        
        # Give user time to open dashboard
        print("🕒 Waiting 5 seconds for you to open the dashboard...")
        time.sleep(5)
        
        try:
            # Convert all features to DataFrame - fix type conversion
            for feature_dict in all_features:
                # Ensure all values match the schema types
                feature_dict['total_bytes'] = float(feature_dict['total_bytes'])
                feature_dict['avg_packet_size'] = float(feature_dict['avg_packet_size'])
                feature_dict['protocol_diversity'] = float(feature_dict['protocol_diversity'])
                feature_dict['connection_density'] = float(feature_dict['connection_density'])
                feature_dict['syn_flood_indicator'] = float(feature_dict['syn_flood_indicator'])
            
            # Create the DataFrame
            features_df = final_analyzer.spark.createDataFrame(all_features, final_analyzer.schema)
            
            print("✅ Successfully created features DataFrame")
            print(f"📊 Check Spark UI at http://localhost:4040 to see the DataFrame in the 'SQL' tab")
            
            # Create a temporary view for SQL exploration in Dashboard
            features_df.createOrReplaceTempView("network_traffic")
            print("📊 SQL table 'network_traffic' created - explore in Spark UI")
            
            # Run a query that will show in the Spark UI SQL tab
            final_analyzer.spark.sql("SELECT * FROM network_traffic").explain(True)
            
            # Perform clustering on all data
            clustering_results = final_analyzer.perform_clustering(features_df)
            
            # Create a comprehensive report
            final_analyzer.create_report(features_df, clustering_results)
            
            # Create an interactive dashboard
            final_analyzer.create_interactive_dashboard(features_df, clustering_results)
            
            # Give user time to check the Spark UI
            print(f"📊 Analysis complete. Spark UI still available at http://localhost:4040")
            print("   Take a moment to review the Spark UI Dashboard for execution details.")
            print("   Look at the completed jobs and their execution times.")
            time.sleep(5)  # Give user time to check UI
            
        except Exception as e:
            print(f"❌ Error during analysis: {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            # Before stopping Spark, note the history server option
            print("\n📊 To view historical Spark jobs later, start the history server with:")
            print("   spark-history-server.sh /path/to/spark-events")
            
            # Stop the Spark session
            final_analyzer.spark.stop()
            
        print("\n✅ Analysis complete. Check the output directory for results.")

if __name__ == "__main__":
    main()