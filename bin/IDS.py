from scapy.all import *
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report

# Function to extract features from a packet
def extract_features(packet):
    features = []
    if packet.haslayer(IP):
        features.append(packet[IP].len)
        features.append(packet[IP].ttl)
    if packet.haslayer(TCP):
        features.append(packet[TCP].sport)
        features.append(packet[TCP].dport)
    if packet.haslayer(UDP):
        features.append(packet[UDP].sport)
        features.append(packet[UDP].dport)
    return features