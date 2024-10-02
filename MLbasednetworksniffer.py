import csv
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from scapy.all import sniff, wrpcap, rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

class PacketSniffer:
    def __init__(self):
        self.packet_count = 0
        self.protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self.captured_packets = []
        self.packet_data = []
        self.anomaly_detection = None
        self.gui = None
        self.is_sniffing = False
        self.pcap_file_name = None
        self.filter_str = None

    def analyze_packet(self, packet):
        try:
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                protocol = packet[IP].proto

                row = [ip_src, ip_dst]

                if protocol == 6:  # TCP protocol
                    row += ['TCP', packet[TCP].sport, packet[TCP].dport]
                    self.protocol_counts["TCP"] += 1
                elif protocol == 17:  # UDP protocol
                    row += ['UDP', packet[UDP].sport, packet[UDP].dport]
                    self.protocol_counts["UDP"] += 1
                elif protocol == 1:  # ICMP protocol
                    row += ['ICMP', '', '']
                    self.protocol_counts["ICMP"] += 1
                else:
                    row += [f'Other Protocol {protocol}', '', '']
                    self.protocol_counts["Other"] += 1

                self.packet_count += 1
                self.captured_packets.append(packet)

                # Feature extraction
                features = [self.packet_count, self.protocol_counts['TCP'], self.protocol_counts['UDP'], self.protocol_counts['ICMP']]

                # Real-time anomaly detection
                if self.anomaly_detection.model:
                    anomaly_score = self.anomaly_detection.model.decision_function(np.array([features]))[0]
                    row.insert(0, anomaly_score)  # Prepend anomaly score

                self.packet_data.append(row)

                # Log the packet to CSV
                with open(f'{self.pcap_file_name}.csv', mode='a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(row)

                # Update the GUI
                packet_info = f"{row[2]} Packet: {ip_src} -> {ip_dst}"
                self.gui.text_box.insert(tk.END, packet_info + "\n")
                self.gui.text_box.see(tk.END)
                self.gui.update_statistics()
        except Exception as e:
            print(f"Error analyzing packet: {e}")

    def start_sniffing(self):
        try:
            self.pcap_file_name = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
            if not self.pcap_file_name:
                return

            with open(f'{self.pcap_file_name}.csv', mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['Anomaly Score', 'Source IP', 'Destination IP', 'Protocol', 'Source Port', 'Destination Port'])

            sniff(filter=self.filter_str, prn=self.analyze_packet, stop_filter=lambda x: not self.is_sniffing)
        except Exception as e:
            print(f"Error starting sniffing: {e}")

    def stop_sniffing(self):
        self.is_sniffing = False
        self.gui.text_box.insert(tk.END, "Packet sniffing stopped.\n")
        self.gui.text_box.see(tk.END)

class AnomalyDetection:
    def __init__(self):
        self.model = None

    def train_model(self, packet_data):
        try:
            if not packet_data:
                messagebox.showwarning("No Data", "No packet data to train the model.")
                return

            # Add a default anomaly score if missing
            fixed_packet_data = []
            for row in packet_data:
                if len(row) == 5:
                    row.insert(0, 0)
                fixed_packet_data.append(row)

            # Create DataFrame with appropriate columns
            df = pd.DataFrame(fixed_packet_data, columns=['Anomaly Score', 'Source IP', 'Destination IP', 'Protocol', 'Source Port', 'Destination Port'])

            # Convert IP addresses to integers, replacing non-numeric values with 0
            def ip_to_int(ip):
                try:
                    return int(''.join(f'{int(octet):08b}' for octet in ip.split('.')), 2)
                except:
                    return 0

            df['Source IP'] = df['Source IP'].apply(ip_to_int)
            df['Destination IP'] = df['Destination IP'].apply(ip_to_int)

            # Convert ports to integers, replacing empty or invalid entries with 0
            df['Source Port'] = pd.to_numeric(df['Source Port'], errors='coerce').fillna(0).astype(int)
            df['Destination Port'] = pd.to_numeric(df['Destination Port'], errors='coerce').fillna(0).astype(int)

            # Extract features for the model
            X = df[['Source IP', 'Destination IP', 'Source Port', 'Destination Port']].values

            # Train the model
            self.model = IsolationForest(contamination=0.01)
            self.model.fit(X)
        except Exception as e:
            print(f"Error training model: {e}")

    def detect_anomalies(self, packet_data):
        try:
            if not self.model:
                messagebox.showwarning("No Model", "No anomaly detection model trained.")
                return

            # Add a default anomaly score if missing
            fixed_packet_data = []
            for row in packet_data:
                if len(row) == 5:
                    row.insert(0, 0)
                fixed_packet_data.append(row)

            # Create DataFrame with appropriate columns
            df = pd.DataFrame(fixed_packet_data, columns=['Anomaly Score', 'Source IP', 'Destination IP', 'Protocol', 'Source Port', 'Destination Port'])

            # Convert IP addresses to integers, replacing non-numeric values with 0
            def ip_to_int(ip):
                try:
                    return int(''.join(f'{int(octet):08b}' for octet in ip.split('.')), 2)
                except:
                    return 0

            df['Source IP'] = df['Source IP'].apply(ip_to_int)
            df['Destination IP'] = df['Destination IP'].apply(ip_to_int)

            # Convert ports to integers, replacing empty or invalid entries with 0
            df['Source Port'] = pd.to_numeric(df['Source Port'], errors='coerce').fillna(0).astype(int)
            df['Destination Port'] = pd.to_numeric(df['Destination Port'], errors='coerce').fillna(0).astype(int)

            # Extract features for the model
            X = df[['Source IP', 'Destination IP', 'Source Port', 'Destination Port']].values

            # Detect anomalies using trained model
            anomaly_scores = self.model.decision_function(X)

            return anomaly_scores
        except Exception as e:
            print(f"Error detecting anomalies: {e}")

class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.packet_sniffer = PacketSniffer()
        self.anomaly_detection = AnomalyDetection()
        self.packet_sniffer.anomaly_detection = self.anomaly_detection
        self.packet_sniffer.gui = self

        # Create GUI components
        self.filter_label = tk.Label(root, text="Filter:")
        self.filter_label.pack()
        self.filter_entry = tk.Entry(root, width=50)
        self.filter_entry.pack()
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack()
        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.packet_sniffer.stop_sniffing)
        self.stop_button.pack()
        self.text_box = tk.Text(root, height=20, width=60)
        self.text_box.pack()
        self.stats_label = tk.Label(root, text="Statistics:")
        self.stats_label.pack()
        self.stats_text = tk.Text(root, height=5, width=60)
        self.stats_text.pack()
        self.train_button = tk.Button(root, text="Train Model", command=self.train_model)
        self.train_button.pack()
        self.detect_button = tk.Button(root, text="Detect Anomalies", command=self.detect_anomalies)
        self.detect_button.pack()

    def start_sniffing(self):
        self.packet_sniffer.filter_str = self.filter_entry.get()
        if not self.packet_sniffer.filter_str:
            messagebox.showwarning("No Filter", "Please enter a filter string.")
            return

        self.packet_sniffer.is_sniffing = True
        threading.Thread(target=self.packet_sniffer.start_sniffing).start()

    def update_statistics(self):
        stats = f"Packets Captured: {self.packet_sniffer.packet_count}\n"
        stats += f"TCP Packets: {self.packet_sniffer.protocol_counts['TCP']}\n"
        stats += f"UDP Packets: {self.packet_sniffer.protocol_counts['UDP']}\n"
        stats += f"ICMP Packets: {self.packet_sniffer.protocol_counts['ICMP']}\n"
        stats += f"Other Packets: {self.packet_sniffer.protocol_counts['Other']}"
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats)

    def train_model(self):
        self.anomaly_detection.train_model(self.packet_sniffer.packet_data)

    def detect_anomalies(self):
        anomaly_scores = self.anomaly_detection.detect_anomalies(self.packet_sniffer.packet_data)
        if anomaly_scores is not None:
            self.text_box.insert(tk.END, "Anomaly Detection Results:\n")
            for i, score in enumerate(anomaly_scores):
                self.text_box.insert(tk.END, f"Packet {i+1}: Anomaly Score = {score}\n")
            self.text_box.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    gui = GUI(root)
    root.mainloop()
