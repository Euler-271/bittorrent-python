import json
import sys
import bencodepy

# Initialize Bencode with no forced encoding to handle raw bytes
bc = bencodepy.Bencode(encoding=None)

def decode_bencode(bencoded_value):
    return bc.decode(bencoded_value)

def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # Convert bytes to string for JSON output, handling non-UTF8 bytes
        def bytes_to_str(data):
            if isinstance(data, bytes):
                try:
                    return data.decode("utf-8")  # Try decoding as UTF-8
                except UnicodeDecodeError:
                    return data.hex()  # If decoding fails, return a hex string
            return data

        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))

    elif command == "info":
        with open(sys.argv[2], "rb") as f:
            data = f.read()
            parsed = decode_bencode(data)
            
            # Decode the announce field as UTF-8 if possible, otherwise handle the error
            try:
                tracker_url = parsed["announce"].decode("utf-8")
            except UnicodeDecodeError:
                tracker_url = parsed["announce"].hex()  # Return as hex string if decoding fails

            # Print out the announce URL and file length
            print("Tracker URL:", tracker_url)
            print("Length:", parsed["info"]["length"])
    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()