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

# Function to process packets from a .pcap file
def process_pcap_file(file_path):
    capture = pyshark.FileCapture(file_path, display_filter='dns')

    for packet in capture:
        if 'IP' in packet:
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

# Main menu
while True:
    print("Options:")
    print("1. Capture live traffic")
    print("2. Process an existing .pcap file")
    print("3. Quit")
    choice = input("Enter your choice (1/2/3): ")

    if choice == "1":
        # Capture packets using pyshark (live traffic)
        print("Press ctrl + Z to stop capture...")
        capture = pyshark.LiveCapture(interface='wlan0', display_filter='dns')

        try:
            for packet in capture.sniff_continuously():
                if 'IP' in packet:
                    print(packet)
                    print("\n\n\n\n")
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

    elif choice == "2":
        # Process an existing .pcap file
        file_path = input("Enter the path to the .pcap file: ")
        process_pcap_file(file_path)

    elif choice == "3":
        # Quit the program
        break

# Close the database connection
conn.close()
