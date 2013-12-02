import struct
import binascii
from hashlib import sha256


def calculate_hash(data, debug=True):
    bige_data = struct.unpack(">20I", data[:80])
    header_bin = struct.pack("<20I", *bige_data)
    
    if debug:
        print "hashing:", header_bin.encode("hex")
    
    return sha256(sha256(header_bin).digest()).digest()


if __name__ == "__main__":
    data = binascii.unhexlify(b"00000001c3bf95208a646ee98a"+\
                                "58cf97c3a0c4b7bf5de4c89ca"+\
                                "04495000005200000000024d1"+\
                                "fff8d5d73ae11140e4e48032c"+\
                                "d88ee01d48c67147f9a09cd41"+\
                                "fdec2e25824f5c038d1a0b350c5eb01f04")
    
    # some data from block 64
    # -----------------------
    exp_hash = "0000000031975f17c5642a9c7e53ae4201a70a6ba6363036b55497b8754d1866"
    version = 1
    prev_block = "00000000ebff91c88984bff39511f544a1c4ef6ec4f33e2ea531e47c2685628e"
    mrkl_root =  "ebdb8335d5b148e9cc1b1bb795ee619a649bd1638e5514fdfc3004b1c56fd6a4"
    time = 1231624107
    bits = 486604799
    nonce = 82803279
    
    print "len(prev_block):",len(prev_block)
    
    # create a hex version of this header
    hex_hdr = "%8x" % version +\
                prev_block[::-1] +\
                mrkl_root[::-1] +\
                b"%8x%8x%8x" % (time, bits, nonce)
    
    hex_hdr = hex_hdr.replace(" ","0")
    
    print "hex_hdr:", hex_hdr
    
    # create a binary version of that hex header
    data = binascii.unhexlify(hex_hdr)
    
    
    target = ("00000000FFFF0000000000000000000000000000000"+\
                "000000000000000000000").decode("hex")
                
    print "target:",target.encode("hex")
    
    print "starting with %d bytes" % len(data)
    
    print "hashing..."
    
    hash_val = calculate_hash(data)
    
    print "value:    ",hash_val.encode("hex")[::-1]
    print "expecting:",exp_hash
    
    if hash_val[::-1] > target:
        print "hash didn't meet difficulty"
    else:
        print "hash was a block solution"