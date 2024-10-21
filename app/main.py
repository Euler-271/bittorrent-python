import json
import sys
import hashlib
import bencodepy
import binascii
import requests
import struct
import ipaddress
import math
import socket
class MessageIDs:
    UNCHOKE = 1
    INTEREDSTED = 2
    BITFIELD = 5
    REQUEST = 6
    PIECE = 7
class Splitter:
    def __init__(self):
        self.TYPE_TO_SPLITTER_MAP = {
            BencodedTypes.INTEGER: self.split_off_bencoded_integer,
            BencodedTypes.STRING: self.split_off_bencoded_string,
            BencodedTypes.LIST: self.split_bencoded_list,
            BencodedTypes.DICT: self.split_bencoded_dictionary,
        }
    def split_off_bencoded_integer(self, bencoded_list):
        end_of_int = bencoded_list.find(b"e")
        return bencoded_list[: end_of_int + 1], bencoded_list[end_of_int + 1 :]
    def split_off_bencoded_string(self, bencoded_list):
        first_colon_index = bencoded_list.find(b":")
        end_of_string = 1 + first_colon_index + int(bencoded_list[:first_colon_index])
        return bencoded_list[:end_of_string], bencoded_list[end_of_string:]
    def split_bencoded_list(self, bencoded_list, depth=0):
        elements = []
        while len(bencoded_list) > 0:
            bencoded_type = BencodedTypes().get_bencoded_type(bencoded_list)
            if bencoded_type == BencodedTypes.INTEGER:
                element, bencoded_list = self.split_off_bencoded_integer(bencoded_list)
                elements.append(element)
            elif bencoded_type == BencodedTypes.STRING:
                element, bencoded_list = self.split_off_bencoded_string(bencoded_list)
                elements.append(element)
            elif bencoded_type == BencodedTypes.LIST:
                bencoded_list = bencoded_list[1:]
                element, bencoded_list = self.split_bencoded_list(bencoded_list, depth + 1)
                elements.append(element)
            elif bencoded_type == BencodedTypes.END_OF_LIST:
                return elements, bencoded_list[1:]
            if depth == 0:
                break
        if depth == 0:
            return elements[0], b""
        return elements, b""
    def split_dict_keys_and_values(self, bencoded_dictionary, depth=0):
        dict_key, bencoded_dictionary = self.TYPE_TO_SPLITTER_MAP[BencodedTypes().get_bencoded_type(bencoded_dictionary)](bencoded_dictionary)
        dict_value, bencoded_dictionary = self.TYPE_TO_SPLITTER_MAP[BencodedTypes().get_bencoded_type(bencoded_dictionary)](bencoded_dictionary)
        return dict_key, dict_value, bencoded_dictionary
    def split_bencoded_dictionary(self, bencoded_dictionary, depth=0):
        result = {}
        while len(bencoded_dictionary) > 2:
            bencoded_type = BencodedTypes().get_bencoded_type(bencoded_dictionary)
            if bencoded_type == BencodedTypes.DICT:
                bencoded_dictionary = bencoded_dictionary[1:]
                while bencoded_type != BencodedTypes.END_OF_LIST:
                    k, v, bencoded_dictionary = self.split_dict_keys_and_values(bencoded_dictionary)
                    result[k] = v
                    if bencoded_dictionary != b'':
                        bencoded_type = BencodedTypes().get_bencoded_type(bencoded_dictionary)
                    else:
                        break
                
                bencoded_dictionary = bencoded_dictionary[1:]
        return result, b''
class Converter:
    def convert_decoded_integer_and_string_bytes(self, data):
        potential_str = data.decode('utf-8', errors='ignore')
        if potential_str.isdecimal() or potential_str[1:].isdecimal():
            return int(potential_str)
        else:
            return potential_str
    def convert_decoded_bytes(self, data: bytes):
        if isinstance(data, bytes):
            return self.convert_decoded_integer_and_string_bytes(data)
        elif isinstance(data, list):
            result = []
            for element in data:
                result.append(self.convert_decoded_bytes(element))
            return result
        elif isinstance(data, dict):
            result = {}
            for k, v in data.items():
                k = self.convert_decoded_bytes(k)
                v = self.convert_decoded_bytes(v)
                result[k] = v
            return result
        
        raise TypeError(f"Type not serializable: {type(data)}")
class BencodedTypes:
    STRING = "string"
    INTEGER = "integer"
    LIST = "list"
    END_OF_LIST = "end_of_list"
    DICT = "dictionary"
    def get_bencoded_type(self, bencoded_value):
        if not isinstance(bencoded_value, bytes):
            raise TypeError(f"Bencoded value should be of type bytes, instead got : {type(bencoded_value)}")
        first_char = chr(bencoded_value[0])
        if first_char.isdigit():
            return self.STRING
        elif first_char == "i":
            return self.INTEGER
        elif first_char == "l":
            return self.LIST
        elif first_char == "e":
            return self.END_OF_LIST
        elif first_char == "d":
            return self.DICT
        raise ValueError(f"Unsupported bencoded value type {bencoded_value}")
class Decoder:
    def __init__(self):
        self.TYPE_TO_DECODER_MAP = {
            BencodedTypes.STRING: self.decode_bencoded_string,
            BencodedTypes.INTEGER: self.decode_bencoded_integer,
            BencodedTypes.LIST: self.decode_bencoded_list,
            BencodedTypes.DICT: self.decode_bencoded_dictionary,
        }
        self.splitter = Splitter()
        self.converter = Converter()
        self.bencoded_types = BencodedTypes()
    def decode_bencoded_string(self, bencoded_value):
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded string value")
        return bencoded_value[
            1
            + first_colon_index : 1
            + first_colon_index
            + int(bencoded_value[:first_colon_index])
        ]
    def decode_bencoded_integer(self, bencoded_value):
        end_index = bencoded_value.find(b"e")
        if end_index == -1:
            raise ValueError("Invalid encoded integer value")
        return bencoded_value[1:end_index]
    def decode_bencoded_list_elements(self, bencoded_split_list):
        decoded_elements = []
        for bv in bencoded_split_list:
            if isinstance(bv, list):
                decoded_elements.append(self.decode_bencoded_list_elements(bv))
            else:
                decoded_elements.append(self.TYPE_TO_DECODER_MAP[self.bencoded_types.get_bencoded_type(bv)](bv))
        return decoded_elements
    def decode_bencoded_list(self, bencoded_list):
        split_bencoded_values, _ = self.splitter.split_bencoded_list(bencoded_list)
        return self.decode_bencoded_list_elements(split_bencoded_values)
    def decode_bencoded_dict_elements(self, bencoded_split_dict):
        result = {}
        for k,v in bencoded_split_dict.items():
            
            k = self.converter.convert_decoded_integer_and_string_bytes(self.decode_bencoded_string(k))
            if isinstance(v, dict):
                v = self.decode_bencoded_dict_elements(v)
            elif isinstance(v, list):
                v = self.decode_bencoded_list_elements(v)
            else:
                v = self.TYPE_TO_DECODER_MAP[self.bencoded_types.get_bencoded_type(v)](v)
            result[k] = v
        return result
    def decode_bencoded_dictionary(self, bencoded_dictionary):
        bencoded_split_dict, _ = self.splitter.split_bencoded_dictionary(bencoded_dictionary)
        return self.decode_bencoded_dict_elements(bencoded_split_dict)
    def decode_bencode(self, bencoded_value):
        try:
            return self.TYPE_TO_DECODER_MAP[self.bencoded_types.get_bencoded_type(bencoded_value)](bencoded_value)
        except ValueError as e:
            print(f"Error during decoding with message: {e}")
        except KeyError as e:
            print(f"Unsupported type of decoder with mesage : {e}")
        raise NotImplementedError(
            f"Given type of bencoded string not supported: {bencoded_value}"
        )
    
    # should return the fully converted bencoded value
    def decode_bencoded_value(self, bencoded_value):
        
        return json.loads(json.dumps(self.decode_bencode(bencoded_value), default=self.converter.convert_decoded_bytes))
class Commands:
    DECODE = "decode"
    INFO = "info"
    PEERS = "peers"
    HANDSHAKE = "handshake"  
    DOWNLOAD_PIECE = "download_piece"
    DOWNLOAD = "download"
class TorrentClient:
    def __init__(self) -> None:
        self.decoder = Decoder()
    def fetch_torrent_info(self, file_name):
        if not file_name:
            raise ValueError("Invalid file path")
        
        with open(file_name, 'rb') as f:
            read_data = f.read()
            torrent_info_dict = Decoder().decode_bencoded_value(read_data)
            torrent_info = Decoder().decode_bencode(read_data)
            piece_length = torrent_info_dict.get('info').get('piece length')
            pieces = torrent_info.get('info').get('pieces')
            piece_hashes = [pieces[i:i+20] for i in range(0, len(pieces), 20)]
            piece_hashes_in_hex = [binascii.hexlify(piece).decode() for piece in piece_hashes]
            if 'info' not in torrent_info:
                raise ValueError("Invalid torrent file: 'info' field is missing")
            
            start_index = read_data.index(b'4:info') + 6
            end_index = start_index + len(bencodepy.encode(torrent_info['info']))
            raw_info_dict = read_data[start_index:end_index]
            
            info_hash = hashlib.sha1(raw_info_dict).hexdigest()
            tracker_url = torrent_info_dict['announce']
            torrent_length = torrent_info_dict['info']['length']
            print(f"Tracker URL: {tracker_url}")
            print(f"Length: {torrent_length}")
            print(f"Info Hash: {info_hash}")
            print(f"Piece Length: {piece_length}")
            print("Piece Hashes:")
            for piece_hash in piece_hashes_in_hex:
                print(piece_hash)
            return hashlib.sha1(raw_info_dict), tracker_url, torrent_length, piece_length, len(piece_hashes_in_hex)
        
    def fetch_peer_info(self, torrent_file):
        peers = []
        info_hash, tracker_url, torrent_length, pl, l = self.fetch_torrent_info(torrent_file)
        peer_id = '00112233445566778897' # random value of peer_id
        uploaded = 0
        downloaded = 0
        parsed_hash = info_hash.digest()
        params = {
            'info_hash': parsed_hash,
            'peer_id': peer_id,
            'port': 6881,
            'uploaded': uploaded,
            'downloaded': downloaded,
            'left': torrent_length,
            'compact': 1
        }
        raw_resp = requests.get(url=tracker_url, params=params)
        peers_bytes = self.decoder.decode_bencode(raw_resp.content).get('peers')
        peers = [ peers_bytes[i:i+6] for i in range(0,len(peers_bytes), 6)]
        res = []
        for p in peers:
            ip, port = struct.unpack('!IH', p)
            ip = ipaddress.ip_address(ip)
            res.append(f'{ip}:{port}')
        
        for r in res:
            print(r)
        return res
    
    def recieve_data(sefl, soc):
        length = b''
        while not length or not int.from_bytes(length, 'big'):
            length = soc.recv(4)
        
        length = int.from_bytes(length, 'big')
        data = soc.recv(length)
        while len(data) < length:
            data += soc.recv(length)
        message_id = int.from_bytes(data[:1], 'big')
        payload = data[1:]
        return message_id, payload
    
    def get_peer_id(self, torrent_file, peer_ip_and_port):
        ip, port = peer_ip_and_port.split(':')
        info_hash, tracker_url, torrent_length, piece_length, num_pieces = self.fetch_torrent_info(torrent_file)
        bit_protocol_req = bytearray()
        bit_protocol_req.extend([19])
        bit_protocol_req.extend('BitTorrent protocol'.encode())
        for _ in range(8):
            bit_protocol_req.extend([0])
        
        bit_protocol_req.extend(info_hash.digest())
        bit_protocol_req.extend('00112233445566778899'.encode())  # peer_id
        pid = ''
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, int(port)))
            s.sendall(bit_protocol_req)
            # Receive the handshake response
            data = s.recv(1024)
            pid = data[-20:]
            return binascii.hexlify(pid).decode()
        
    def wait_for_peer_messag(self, soc, message_id):
        reciveved_id, data = self.recieve_data(soc)
        while message_id != reciveved_id:
            reciveved_id, data = self.recieve_data(soc)
        
        return data
    
    def wait_for_unchoke(self, soc):
        return self.wait_for_peer_messag(soc, MessageIDs.UNCHOKE)
    
    def wait_for_bitfield(self, soc):
        return self.wait_for_peer_messag(soc, MessageIDs.BITFIELD)
    
    def get_block(self, soc, index, begin, block_length):
        request_message = b'\x00\x00\x00\x0d\x06'
        request_message += index.to_bytes(4, byteorder='big')
        request_message += begin.to_bytes(4, byteorder='big')
        request_message += block_length.to_bytes(4, byteorder='big')
        soc.sendall(request_message)
        messageid, recieved_block_content = self.recieve_data(soc)
        return recieved_block_content[8:]
    
    def send_interested_message(self, soc):
        request_message = b'\x00\x00\x00\x01\x02'
        soc.sendall(request_message)
        
    def download_piece(self, torrent_file: str, peer_ip_and_port: str, piece_index: int, output_file: str):
        ip, port = peer_ip_and_port.split(':')
        block_length = 16*1024
        info_hash, tracker_url, torrent_length, piece_length, num_pieces = self.fetch_torrent_info(torrent_file)
        bit_protocol_req = bytearray()
        bit_protocol_req.extend([19])
        bit_protocol_req.extend('BitTorrent protocol'.encode())
        for _ in range(8):
            bit_protocol_req.extend([0])
        
        bit_protocol_req.extend(info_hash.digest())
        bit_protocol_req.extend('00112233445566778899'.encode())
        piece_data = bytearray()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, int(port)))
            s.sendall(bit_protocol_req)
            d = s.recv(68) # Handshake 
            bitfield = self.wait_for_bitfield(s)
            self.send_interested_message(s)
            # recieve unchoke
            unchoke_message = self.wait_for_unchoke(s)
            if piece_index == num_pieces - 1:
                    piece_length = (torrent_length%piece_length) or piece_length
            else:
                piece_length = piece_length
            
            number_of_blocks = math.ceil(piece_length / block_length)
            
            for block_index in range(number_of_blocks):
                if block_index == number_of_blocks - 1:  # This is the last block
                    offset = piece_length - min(block_length, piece_length - block_length * block_index)
                else:
                    offset = block_length * block_index
                bl = min(block_length, piece_length - offset)
                block_data = self.get_block(s, piece_index, offset, bl)
                piece_data.extend(block_data)
            # Send have message
            have_message = b'\x00\x00\x00\x05\x04'
            have_message += piece_index.to_bytes(4, byteorder='big')
            s.sendall(have_message)
        with open(output_file, 'wb') as f:
            f.write(piece_data)
        return piece_data
        
    def download_torrent_file(self, torrent_file: str, output_file: str):
        info_hash, tracker_url, torrent_length, piece_length, num_pieces = self.fetch_torrent_info(torrent_file)
        peer_ips = self.fetch_peer_info(torrent_file)
        peer_ip = peer_ips[0]
        torrent = bytearray()
        for piece_index in range(num_pieces):
            
            torrent.extend(self.download_piece(torrent_file, peer_ip, piece_index, output_file))
        with open(output_file, 'wb') as f:
            f.write(torrent)
def main():
    command = sys.argv[1]
    bencoded_decoder = Decoder()
    torrent_client = TorrentClient()
    if command == Commands.DECODE:
        bencoded_value = sys.argv[2].encode()
        print(json.dumps(bencoded_decoder.decode_bencoded_value(bencoded_value)))
    elif command == Commands.INFO:
        file_name = sys.argv[2]
        torrent_client.fetch_torrent_info(file_name)
    elif command == Commands.PEERS:
        file_name = sys.argv[2]
        torrent_client.fetch_peer_info(file_name)
    elif command == Commands.HANDSHAKE:
        file_name = sys.argv[2]
        peer = sys.argv[3]
        peer_id = torrent_client.get_peer_id(file_name, peer)
        print(f'Peer ID: {peer_id}')
    elif command == Commands.DOWNLOAD_PIECE:
        output_file = sys.argv[3]
        torrent_file = sys.argv[4]
        piece_number = sys.argv[5]
        peer_ip = torrent_client.fetch_peer_info(torrent_file)[0]
        result = torrent_client.download_piece(torrent_file, peer_ip, int(piece_number), output_file)
        print(f'Piece {piece_number} downloaded to {output_file}.')
    elif command == Commands.DOWNLOAD:
        output_file = sys.argv[3]
        torrent_file = sys.argv[4]
        torrent_client.download_torrent_file(torrent_file, output_file)
        print(f'Downloaded {torrent_file} to {output_file}.')
    else:
        raise NotImplementedError(f"Unknown command {command}")
if __name__ == "__main__":
    main()