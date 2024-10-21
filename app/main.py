from typing import Tuple
import json
import sys

def decode_bencode_helper(bencoded_value, start) -> Tuple[str, int]:
    if chr(bencoded_value[start]).isdigit():
        first_colon_index = start + bencoded_value[start:].find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        str_length = int(bencoded_value[start:first_colon_index])
        value = bencoded_value[first_colon_index + 1:first_colon_index + str_length + 1]
        return value, first_colon_index + str_length + 1
    elif chr(bencoded_value[start]) == "i":
        end = start + bencoded_value[start:].find(ord("e"))
        if end == -1:
            raise ValueError("Non terminated integer")
        value = bencoded_value[start + 1:end]
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

def decode_bencode(bencoded_value):
    result, _ = decode_bencode_helper(bencoded_value, 0)
    return result

def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
            raise TypeError(f"Type not serializable: {type(data)}")
        
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))

    elif command == "info":
        with open(sys.argv[2], "rb") as f:
            data = f.read()
            parsed = decode_bencode(data)

            # Handle decoding of announce URL carefully
            tracker_url = parsed.get("announce", None)
            if tracker_url:
                try:
                    tracker_url = tracker_url.decode("utf-8")
                except UnicodeDecodeError:
                    tracker_url = tracker_url.hex()

            # Output the expected information
            print("Tracker URL:", tracker_url)
            print("Length:", parsed["info"]["length"])
    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()