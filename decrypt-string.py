import sys
import base64

def decode_string(encoded_string):
    decoded_bytes = base64.b64decode(encoded_string)
    decoded_string = ""

    for encoded_char in decoded_bytes:
        decoded_char = (encoded_char - 0x24) ^ 0x25
        decoded_string += chr(decoded_char)

    return decoded_string

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Please provide the string as the first argument.")
        sys.exit(1)

    input_string = sys.argv[1]
    result = decode_string(input_string)
    print(result)
