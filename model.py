import matplotlib.pyplot as plt
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from database import create_table, insert_packets


# Reading data for model learning
def load_and_train():
    packets = rdpcap("data/testwire.pcapng")
    packet_data = []
    for pkt in packets:
        try:
            length = len(pkt)
            proto = pkt.proto if hasattr(pkt, 'proto') else 0
            time_pkt = pkt.time
            src_ip = pkt[IP].src if IP in pkt else "0.0.0.0"
            dst_ip = pkt[IP].dst if IP in pkt else "0.0.0.0"
            src_port = pkt.sport if TCP in pkt or UDP in pkt else 0
            dst_port = pkt.dport if TCP in pkt or UDP in pkt else 0
            syn_flag = 1 if TCP in pkt and pkt[TCP].flags == "S" else 0
            udp_flood = 1 if UDP in pkt and length > 1000 else 0

            packet_data.append({
                "time": time_pkt,
                "length": length,
                "protocol": proto,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "syn_flood": syn_flag,
                "udp_flood": udp_flood
            })
        except:
            continue

    df = pd.DataFrame(packet_data)

    # dataframe coppy
    print("____________________BASE DF______________________________")
    df_copy = df.copy()
    print(df_copy)

    # Hashing
    df["src_ip_hash"] = df["src_ip"].apply(lambda x: hash(x) % 10000)
    df["dst_ip_hash"] = df["dst_ip"].apply(lambda x: hash(x) % 10000)

    # remove old columns
    df = df.drop(columns=["src_ip", "dst_ip"])

    # convert object data types to numerical
    # Step 1: Convert to float
    df['time'] = pd.to_numeric(df['time'], errors='coerce')

    # Step 2: Convert to datetime from Unix timestamp (seconds)
    df['time'] = pd.to_datetime(df['time'], unit='s')

    print("____________________INFO______________________________")
    print(df.info())
    print("____________________DESCRIBE__________________________")
    print(df.describe())
    print("____________________NULL CHECK________________________")
    print(df.isnull())
    print("____________________NULL CHECK SUM____________________")
    print(df.isnull().sum())
    print("____________________NULL CHECK PERCENT____________________")
    print(df.isnull().mean())

    # Standardization of data
    features = ["length", "protocol", "src_port", "dst_port", "src_ip_hash", "dst_ip_hash", "syn_flood", "udp_flood"] # on  which is atken as anomalies and split will be done
    scaler = StandardScaler()
    scaler.fit(df[features]) # training
    X_scaled_new_data = scaler.transform(df[features])

    # Anomaly detection model
    model = IsolationForest(contamination=0.05, random_state=42) # contamination - how many is anomaly 0-0.5 /
    model.fit(X_scaled_new_data)# training
    df["anomaly"] = model.predict(X_scaled_new_data) # anomaly score asigment

    # treningowy walidacyjny i testowy

    # Test data split - classification data check
    X_train, X_test, y_train, y_test = train_test_split(X_scaled_new_data, (df["anomaly"] == -1).astype(int), test_size=0.3, random_state=42)
    clf = RandomForestClassifier()
    clf.fit(X_train, y_train)
    score = clf.score(X_test, y_test)
    print(f"Dokładność klasyfikatora: {score:.2f}")

    # Display anomaly vs normal traffic
    normal = df[df["anomaly"] == 1]
    attacks = df[df["anomaly"] == -1]

    plt.figure(figsize=(12, 6))
    plt.scatter(normal.index, normal["length"], c="green", alpha=0.5, s=10, label="Normalny ruch")
    plt.scatter(attacks.index, attacks["length"], c="red", alpha=0.5, s=10, label="Atak (DoS/DDoS)")
    plt.title("Wykrywanie anomalii DoS/DDoS - ruch normalny vs ataki")
    plt.xlabel("Nr pakietu")
    plt.ylabel("Rozmiar pakietu")
    plt.legend()
    plt.tight_layout()
    plt.show()
    plt.close()
    #
    # create_table()
    # insert_packets(df)
    return model, scaler, clf



if __name__ == '__main__':
    model, scaler, clf = load_and_train()
# data source https://www.unb.ca/cic/datasets/ids-2017.html
