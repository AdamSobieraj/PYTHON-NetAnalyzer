import os
import pandas as pd
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = (
    f"postgresql+psycopg2://{os.getenv('PG_USER', 'admin')}:"
    f"{os.getenv('PG_PASS', 'admin')}@"
    f"{os.getenv('PG_HOST', 'localhost')}:"
    f"{os.getenv('PG_PORT', '5432')}/"
    f"{os.getenv('PG_DB', 'netdb')}"
)

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

Base = declarative_base()

class Packet(Base):
    __tablename__ = 'packets'

    id = Column(Integer, primary_key=True, autoincrement=True)
    time = Column(Float)
    length = Column(Integer)
    protocol = Column(Integer)
    src_ip = Column(String(50))
    dst_ip = Column(String(50))
    src_port = Column(Integer)
    dst_port = Column(Integer)
    syn_flood = Column(Integer)
    udp_flood = Column(Integer)
    src_ip_hash = Column(Integer)
    dst_ip_hash = Column(Integer)
    anomaly = Column(Integer)

def create_table():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

def insert_packets(df: pd.DataFrame):
    packets = [Packet(**row.to_dict()) for _, row in df.iterrows()]
    session.bulk_save_objects(packets)
    session.commit()

if __name__ == "__main__":
    create_table()

    df = pd.DataFrame([
        {
            "time": 123.456,
            "length": 60,
            "protocol": 6,
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.100",
            "src_port": 443,
            "dst_port": 8080,
            "syn_flood": 0,
            "udp_flood": 0,
            "src_ip_hash": 12345,
            "dst_ip_hash": 67890,
            "anomaly": 0
        }
    ])

    insert_packets(df)

    packets = session.query(Packet).all()
    for pkt in packets:
        print(f"ID: {pkt.id}, SRC: {pkt.src_ip} -> DST: {pkt.dst_ip}, LENGTH: {pkt.length}")
