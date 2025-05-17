# Anomaly Detector (DoS/DDoS Network Monitor)

## Opis
Projekt służy do wykrywania anomalii w sieciach Ethernet na podstawie plików `.pcap` 
lub w czasie rzeczywistym. Wykrywa potencjalne ataki typu DoS i DDoS (SYN flood, UDP flood) 
z użyciem modeli ML.

## Funkcje
- Import danych z `.pcap` (Wireshark)
- Wykrywanie anomalii przy pomocy Isolation Forest
- Klasyfikacja anomalii vs normalny ruch (RandomForest)
- Rozpoznawanie SYN flood i UDP flood
- Zapis danych do PostgreSQL
- Webowy interfejs Flask:
  - Filtrowanie po IP i porcie
  - Wykres ruchu
  - Eksport do JSON, Excel, CSV (pełne dane)
  - Automatyczne odświeżanie co 10 sekund
- Sniffing w czasie rzeczywistym (opcja)

## Uruchomienie (Docker)
```bash
docker compose up
```

## Wymagania lokalne
```bash

```

## Przykład
Wejdź w przeglądarce na `http://localhost:5000`

## Pliki
- `anomaly_detector.py`: Główny skrypt
- `requirements.txt`: Wymagane biblioteki
- `Dockerfile`: Konfiguracja kontenera

---
Projekt edukacyjny do celów demonstracyjnych.
