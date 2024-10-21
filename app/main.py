from typing import Tuple
import json
import sys
# import bencodepy - available if you need it!
# import requests - available if you need it!
# lli4eei5ee
# li4eei5e
def decode_bencode_helper(bencoded_value, start) -> Tuple[str, int]:
    if chr(bencoded_value[start]).isdigit():
        first_colon_index = start + bencoded_value[start:].find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        str_length = int(bencoded_value[start:first_colon_index])
        value = bencoded_value[
            first_colon_index + 1 : first_colon_index + str_length + 1
        ]
        return value, first_colon_index + str_length + 1
    elif chr(bencoded_value[start]) == "i":
        end = start + bencoded_value[start:].find(ord("e"))
        if end == -1:
            raise ValueError("Non terminated integer")
        value = bencoded_value[start + 1 : end]
        return int(value), end + 1
    elif chr(bencoded_value[start]) == "l":
        next_start = start + 1
        items = []
        while next_start < len(bencoded_value):
            if chr(bencoded_value[next_start]) == "e":
                break
            next_item, next_start = decode_bencode_helper(bencoded_value, next_start)
            items.append(next_item)
        return items, next_start + 1
    elif chr(bencoded_value[start]) == "d":
        value = {}
        next_start = start + 1
        current_key = None
        while next_start < len(bencoded_value):
            if chr(bencoded_value[next_start]) == "e":
                break
            next_item, next_start = decode_bencode_helper(bencoded_value, next_start)
            if current_key is None:
                current_key = next_item.decode("utf-8")
            elif current_key is not None:
                value[current_key] = next_item
                current_key = None
        return value, next_start + 1
    else:
        raise NotImplementedError(f"Unsupported value type {bencoded_value}")
# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value):
    result, _ = decode_bencode_helper(bencoded_value, 0)
    return result
def main():
    command = sys.argv[1]
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
            raise TypeError(f"Type not serializable: {type(data)}")
        # Uncomment this block to pass the first stage
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        with open(sys.argv[2], "rb") as f:
            data = f.read()
            parsed = decode_bencode(data)
            print("Tracker URL:", parsed["announce"].decode("utf-8"))
            print("Length:", parsed["info"]["length"])
    else:
        raise NotImplementedError(f"Unknown command {command}")