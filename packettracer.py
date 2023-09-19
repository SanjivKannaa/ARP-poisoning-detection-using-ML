import pyshark
import sqlite3

# Define the database connection and cursor
conn = sqlite3.connect('packet_capture.db')
cursor = conn.cursor()

# Create a table to store packet data
cursor.execute('''
    CREATE TABLE IF NOT EXISTS packets (
        timestamp TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        protocol TEXT,
        length INT
    )
''')
conn.commit()

# Capture packets using pyshark
capture = pyshark.LiveCapture(interface='wlan0', display_filter='dns')

try:
    for packet in capture.sniff_continuously():
        if 'IP' in packet:# and packet.transport_layer == "DNS":
            timestamp = packet.sniff_time
            source_ip = packet.ip.src
            destination_ip = packet.ip.dst
            protocol = packet.transport_layer
            length = packet.length

            # Insert packet data into the database
            cursor.execute('''
                INSERT INTO packets (timestamp, source_ip, destination_ip, protocol, length)
                VALUES (?, ?, ?, ?, ?)
            ''', (timestamp, source_ip, destination_ip, protocol, length))
            conn.commit()

except KeyboardInterrupt:
    pass

# Close the database connection
conn.close()
