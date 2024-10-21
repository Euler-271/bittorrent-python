import hashlib
import bencodepy
import requests
import socket
import struct
import math
import os

class MessageIDs:
    UNCHOKE = 1
    INTERESTED = 2
    BITFIELD = 5
    REQUEST = 6
    PIECE = 7

class TorrentClient:
    def __init__(self):
        self.peer_id = '-PC0001-' + ''.join([str(i) for i in range(12)])

    def fetch_torrent_info(self, torrent_file):
        with open(torrent_file, "rb") as f:
            torrent_data = bencodepy.decode(f.read())
        info = torrent_data[b'info']
        info_hash = hashlib.sha1(bencodepy.encode(info)).digest()
        tracker_url = torrent_data[b'announce'].decode('utf-8')
        piece_length = info[b'piece length']
        num_pieces = len(info[b'pieces']) // 20
        file_length = info[b'length']
        return info_hash, tracker_url, file_length, piece_length, num_pieces

    def get_peers(self, tracker_url, info_hash, peer_id):
        params = {
            'info_hash': info_hash,
            'peer_id': peer_id.encode('utf-8'),
            'port': 6881,
            'uploaded': 0,
            'downloaded': 0,
            'left': 0,
            'compact': 1,
            'event': 'started'
        }
        response = requests.get(tracker_url, params=params)
        tracker_data = bencodepy.decode(response.content)
        peers_binary = tracker_data[b'peers']
        peers = []
        for i in range(0, len(peers_binary), 6):
            ip = socket.inet_ntoa(peers_binary[i:i + 4])
            port = struct.unpack('!H', peers_binary[i + 4:i + 6])[0]
            peers.append((ip, port))
        return peers

    def send_handshake(self, sock, info_hash, peer_id):
        pstrlen = 19
        pstr = b"BitTorrent protocol"
        reserved = b'\x00' * 8
        handshake = struct.pack(">B19s8x20s20s", pstrlen, pstr, info_hash, peer_id.encode('utf-8'))
        sock.send(handshake)
        response = sock.recv(68)
        return response

    def receive_data(self, sock):
        length = sock.recv(4)
        length = int.from_bytes(length, byteorder='big')
        data = sock.recv(length)
        return data

    def send_interested(self, sock):
        interested_message = struct.pack(">I1B", 1, MessageIDs.INTERESTED)
        sock.send(interested_message)

    def download_piece(self, sock, piece_index, piece_length):
        block_size = 2 ** 14  # 16 KB block size
        offset = 0
        piece_data = b''
        while offset < piece_length:
            block = min(block_size, piece_length - offset)
            request = struct.pack(">I1BIII", 13, MessageIDs.REQUEST, piece_index, offset, block)
            sock.send(request)
            data = self.receive_data(sock)
            piece_data += data[9:]
            offset += block
        return piece_data

    def save_piece(self, file_name, piece_index, piece_data):
        with open(file_name, 'r+b') as f:
            f.seek(piece_index * len(piece_data))
            f.write(piece_data)

    def download_torrent_file(self, torrent_file, output_file):
        info_hash, tracker_url, file_length, piece_length, num_pieces = self.fetch_torrent_info(torrent_file)
        peers = self.get_peers(tracker_url, info_hash, self.peer_id)

        if not os.path.exists(output_file):
            with open(output_file, 'wb') as f:
                f.write(b'\x00' * file_length)  # Allocate file size

        for peer in peers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(peer)
                self.send_handshake(sock, info_hash, self.peer_id)
                self.send_interested(sock)

                for piece_index in range(num_pieces):
                    piece_data = self.download_piece(sock, piece_index, piece_length)
                    self.save_piece(output_file, piece_index, piece_data)

                sock.close()
                print(f"Downloaded torrent to {output_file}.")
                break  # Exit once the file is downloaded successfully
            except Exception as e:
                print(f"Failed to download from {peer}: {e}")
                continue


def main():
    command = sys.argv[1]
    torrent_client = TorrentClient()

    if command == "download":
        output_file = sys.argv[3]
        torrent_file = sys.argv[2]
        torrent_client.download_torrent_file(torrent_file, output_file)
    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()