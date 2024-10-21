import json
import sys
import bencodepy
import hashlib
# import requests - available if you need it!
def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        length = int(bencoded_value.split(b":")[0])
        return bencoded_value.split(b":")[1][:length]
    elif chr(bencoded_value[0]) == "i":
        return int(bencoded_value[1:-1])
    elif chr(bencoded_value[0]) == "l":
        return bencodepy.decode(bencoded_value)
    elif chr(bencoded_value[0]) == "d":
        return bencodepy.BencodeDecoder(encoding="utf-8").decode(bencoded_value)
    else:
        raise NotImplementedError("Only strings are supported at the moment")
def main():
    command = sys.argv[1]
    def bytes_to_str(data):
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace")
        elif isinstance(data, int):
            return data
        elif isinstance(data, list):
            return [bytes_to_str(item) for item in data]
        elif isinstance(data, dict):
            return {
                bytes_to_str(key): bytes_to_str(value) for key, value in data.items()
            }
        else:
            raise TypeError(f"Type not serializable: {type(data)}")
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        file = sys.argv[2].encode()
        with open(file, "rb") as file:
            content = file.read()
        decoded_content = bencodepy.decode(content)
        data = bytes_to_str(decoded_content)
        print(f'Tracker URL: {data["announce"]}')
        print(f'Length: {data["info"]["length"]}')
        print(
            f'Info Hash: {hashlib.sha1(bencodepy.encode(decoded_content[b"info"])).hexdigest()}'
        )
        print(f'Piece Length: {data["info"]["piece length"]}')
        print(f"Piece Hashes: ")
        for i in range(0, len(decoded_content[b"info"][b"pieces"]), 20):
            print(decoded_content[b"info"][b"pieces"][i : i + 20].hex())
    else:
        raise NotImplementedError(f"Unknown command {command}")