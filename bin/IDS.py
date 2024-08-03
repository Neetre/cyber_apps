from scapy.all import *
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report


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


def main():
    packets = sniff(count=1000)

    # Extract features and labels
    features = []
    labels = []
    for packet in packets:
        features.append(extract_features(packet))
        labels.append(0 if packet.haslayer(TCP) or packet.haslayer(UDP) else 1)  # 0 for normal, 1 for attack

    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)

    # Train a decision tree classifier
    clf = DecisionTreeClassifier()
    clf.fit(X_train, y_train)

    # Predict labels for testing set
    y_pred = clf.predict(X_test)

    # Print classification report
    print(classification_report(y_test, y_pred))
