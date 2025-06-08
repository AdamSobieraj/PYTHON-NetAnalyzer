import matplotlib.pyplot as plt  # biblioteka do tworzenia wykresów
import pandas as pd  # biblioteka do manipulacji danymi (DataFrame)
from scapy.all import rdpcap, IP, TCP, UDP  # biblioteka Scapy do wczytywania i analizy pakietów sieciowych
from sklearn.ensemble import IsolationForest, RandomForestClassifier  # modele ML: jeden do anomalii, drugi do klasyfikacji
from sklearn.model_selection import train_test_split  # podział danych na zbiory treningowe/testowe
from sklearn.preprocessing import StandardScaler  # normalizacja danych
import sys

# Redirect stdout to a text file
sys.stdout = open("output.txt", "w")

# Główna funkcja: ładowanie danych i trenowanie modeli
def load_and_train():
    packets = rdpcap("data/testwire.pcapng") # wczytanie pliku PCAP z pakietami
    packet_data = [] # lista do przechowywania przetworzonych pakietów

    print("____________________RAW DATA______________________________")

    for pkt in packets:  # iteracja po każdym pakiecie
        print(pkt)
        try:
            length = len(pkt)  # długość pakietu (bajty)
            proto = pkt.proto if hasattr(pkt, 'proto') else 0  # numer protokołu (jeśli istnieje)
            time_pkt = pkt.time  # czas odebrania pakietu (znacznik czasu UNIX)
            src_ip = pkt[IP].src if IP in pkt else "0.0.0.0"  # adres źródłowy IP
            dst_ip = pkt[IP].dst if IP in pkt else "0.0.0.0"  # adres docelowy IP
            src_port = pkt.sport if TCP in pkt or UDP in pkt else 0  # port źródłowy TCP/UDP
            dst_port = pkt.dport if TCP in pkt or UDP in pkt else 0  # port docelowy TCP/UDP
            syn_flag = 1 if TCP in pkt and pkt[TCP].flags == "S" else 0  # flaga SYN (SYN flood)
            udp_flood = 1 if UDP in pkt and length > 1000 else 0  # heurystyka: duży pakiet UDP = potencjalny atak

            packet_data.append({  # dodanie przetworzonych danych do listy
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
            continue # pomijanie pakietów, które wywołują wyjątki (np. uszkodzone)

    df = pd.DataFrame(packet_data)

    # dataframe coppy
    print("____________________BASE DF______________________________")
    df_copy = df.copy() # kopia DataFrame'u do podglądu surowych danych
    print(df_copy)

    # Hashing
    df["src_ip_hash"] = df["src_ip"].apply(lambda x: hash(x) % 10000) # skrócony hash IP źródłowego
    df["dst_ip_hash"] = df["dst_ip"].apply(lambda x: hash(x) % 10000) # skrócony hash IP docelowego

    # usunięcie adresów IP (zamienione hashami)
    df = df.drop(columns=["src_ip", "dst_ip"])

    # convert object data types to numerical
    # Step 1: Convert to float
    df['time'] = pd.to_numeric(df['time'], errors='coerce')

    # Step 2: Convert to datetime from Unix timestamp (seconds)
    df['time'] = pd.to_datetime(df['time'], unit='s')

    print("____________________INFO______________________________")
    print(df.info())  # wyświetlenie informacji o kolumnach i typach danych
    print("____________________DESCRIBE__________________________")
    print(df.describe())  # statystyki opisowe (średnie, min/max itd.)
    print("____________________NULL CHECK________________________")
    print(df.isnull())  # sprawdzenie brakujących wartości
    print("____________________NULL CHECK SUM____________________")
    print(df.isnull().sum())  # suma braków w kolumnach
    print("____________________NULL CHECK PERCENT____________________")
    print(df.isnull().mean())  # procent braków w kolumnach

    # lista cech używana do uczenia modelu
    features = ["length", "protocol", "src_port", "dst_port", "src_ip_hash", "dst_ip_hash", "syn_flood", "udp_flood"]

    scaler = StandardScaler()  # normalizacja danych
    scaler.fit(df[features])  # dopasowanie normalizacji do danych
    X_scaled_new_data = scaler.transform(df[features])  # przeskalowanie danych

    # Anomaly detection model
    model = IsolationForest(contamination=0.05, random_state=42)  # model detekcji anomalii (5% jako anomalie)
    model.fit(X_scaled_new_data)  # uczenie modelu
    df["anomaly"] = model.predict(X_scaled_new_data)  # -1 = anomalia, 1 = normalne dane

    # Diagnostyka rozkładu klas
    print("____________________CLASS DISTRIBUTION____________________")
    print(df["anomaly"].value_counts())
    print("Proporcja anomalii: {:.2%}".format((df["anomaly"] == -1).mean()))

    # treningowy walidacyjny i testowy

    # podział danych na treningowe/testowe do klasyfikacji (czy pakiet to anomalia)
    y = df["anomaly"].apply(lambda x: 1 if x == -1 else 0)
    X_train, X_test, y_train, y_test = train_test_split(X_scaled_new_data, y, test_size=0.3, random_state=42,shuffle=True)

    print("Dystrybucja klas w y_train:", pd.Series(y_train).value_counts())
    print("Dystrybucja klas w y_test:", pd.Series(y_test).value_counts())

    clf = RandomForestClassifier(class_weight="balanced") # klasyfikator Random Forest
    clf.fit(X_train, y_train) # uczenie modelu klasyfikacyjnego
    score = clf.score(X_test, y_test) # ocena skuteczności modelu
    print(f"Dokładność klasyfikatora: {score:.2f}") # wyświetlenie dokładności

    # podział na ruch normalny i anomalie
    normal = df[df["anomaly"] == 1]
    attacks = df[df["anomaly"] == -1]

    # tworzenie wykresu
    plt.figure(figsize=(12, 6))
    plt.scatter(normal.index, normal["length"], c="green", alpha=0.5, s=10, label="Normalny ruch")
    plt.scatter(attacks.index, attacks["length"], c="red", alpha=0.5, s=10, label="Atak (DoS/DDoS)")
    plt.title("Wykrywanie anomalii DoS/DDoS - ruch normalny vs ataki")
    plt.xlabel("Nr pakietu")
    plt.ylabel("Rozmiar pakietu")
    plt.legend()
    plt.tight_layout()
    plt.show()  # wyświetlenie wykresu
    plt.close()  # zamknięcie wykresu

    # create_table()  # tworzenie tabeli w bazie danych – obecnie zakomentowane
    # insert_packets(df)  # zapis wyników do bazy danych – obecnie zakomentowane

    return model, scaler, clf  # zwrócenie wytrenowanych modeli



if __name__ == '__main__':
    model, scaler, clf = load_and_train()
# data source https://www.unb.ca/cic/datasets/ids-2017.html
