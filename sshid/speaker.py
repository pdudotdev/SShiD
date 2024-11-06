#!/usr/bin/env python3
"""
Speaker Script for SShiD

This script allows a user to broadcast a message via Wi-Fi beacon frames.
It constructs a beacon frame with a custom SSID and includes an encrypted message
in the Vendor-Specific Information Element.

Requirements:
- Python 3
- scapy
- cryptography
- root privileges to send raw packets

Usage:
sudo python3 speaker.py
"""

import os
import sys
import base64
import random
import struct
import hashlib
import logging
import subprocess
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
#logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')

def derive_key(password, salt, iterations=100000):
    """
    Derives a cryptographic key from a password using PBKDF2HMAC.

    Args:
        password (str): The password provided by the user.
        salt (bytes): A unique salt value for key derivation.
        iterations (int): The number of iterations for the KDF (default: 100,000).

    Returns:
        bytes: A 256-bit (32-byte) key derived from the password.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password.encode())
    return key

def generate_ssid_identifier(password):
    """
    Generates an SSID identifier by hashing the password and encoding it.

    Args:
        password (str): The secret password provided by the user.

    Returns:
        str: A Base64 URL-safe encoded string used as the SSID.
    """
    # Use a fixed salt for the SSID hash to ensure both parties generate the same SSID
    ssid_salt = b'sshid_ssid_salt'
    ssid_hash = hashlib.sha256(password.encode() + ssid_salt).digest()
    # Use Base64 URL-safe encoding and truncate to 10 characters
    ssid = base64.urlsafe_b64encode(ssid_hash).decode('utf-8').rstrip('=')[:10]
    return ssid

def encrypt_message(message, key):
    """
    Encrypts a plaintext message using ChaCha20-Poly1305.

    Args:
        message (str): The plaintext message to encrypt.
        key (bytes): The encryption key derived from the password.

    Returns:
        tuple: A tuple containing the nonce (bytes) and ciphertext (bytes).
    """
    # Generate a random 12-byte nonce
    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key)
    ciphertext = aead.encrypt(nonce, message.encode('utf-8'), None)
    return nonce, ciphertext

def encode_data(nonce, ciphertext):
    """
    Encodes the nonce and ciphertext into a Base64 URL-safe string.

    Args:
        nonce (bytes): The nonce used during encryption.
        ciphertext (bytes): The encrypted message.

    Returns:
        str: The Base64 URL-safe encoded string containing the nonce and ciphertext.
    """
    data = nonce + ciphertext
    encoded_data = base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')
    return encoded_data

def get_wireless_interface():
    """
    Detects and returns the name of the wireless interface.

    Returns:
        str: The name of the wireless interface to use.

    Raises:
        SystemExit: If no wireless interfaces are found or an invalid selection is made.
    """
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        interfaces = [line.strip().split(' ')[1] for line in lines if 'Interface' in line]
        if not interfaces:
            logging.error('No wireless interfaces found.')
            sys.exit(1)
        elif len(interfaces) == 1:
            return interfaces[0]
        else:
            logging.info('Multiple wireless interfaces detected:')
            for idx, iface in enumerate(interfaces):
                logging.info(f'{idx + 1}: {iface}')
            choice = int(input('[INPUT] Select interface [1-{}]: '.format(len(interfaces))))
            if 1 <= choice <= len(interfaces):
                return interfaces[choice - 1]
            else:
                logging.error('Invalid selection.')
                sys.exit(1)
    except Exception as e:
        logging.error(f'Error detecting wireless interface: {e}')
        sys.exit(1)

def generate_random_mac():
    mac = [0x00, 0x16, 0x3e,
           random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: "%02x" % x, mac))

def broadcast_beacon(iface, ssid, encoded_data, channel=1):
    """
    Constructs and sends beacon frames with the given SSID, Vendor-Specific IE, and channel.

    Args:
        iface (str): The wireless interface to use.
        ssid (str): The SSID to broadcast.
        encoded_data (str): The Base64 encoded encrypted message to include in the Vendor-Specific IE.
        channel (int): The Wi-Fi channel to broadcast on (default: 1).
    """
    # Use a locally administered OUI (e.g., 0xACDE48)
    vendor_oui = 0xACDE48
    vendor_oui_bytes = vendor_oui.to_bytes(3, byteorder='big')
    vendor_oui_type = b'\x00'  # Optional OUI type

    # Ensure encoded_data is bytes
    if isinstance(encoded_data, str):
        encoded_data_bytes = encoded_data.encode('utf-8')
    else:
        encoded_data_bytes = encoded_data

    # Build the Vendor-Specific IE info field
    vendor_ie_info = vendor_oui_bytes + vendor_oui_type + encoded_data_bytes
    
    # Create the Vendor-Specific IE
    vendor_ie = Dot11Elt(ID=221, info=vendor_ie_info)

    # Build the DS Parameter Set IE to specify the channel
    dsset = Dot11Elt(ID='DSset', info=chr(channel).encode('utf-8'))

    # Generate a random globally unique MAC address
    source_mac = generate_random_mac()

    # Construct the beacon frame
    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
                  addr2=source_mac, addr3=source_mac)
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID', info=ssid.encode('utf-8'))

    # RSN Information Element Fields
    rsn_version = struct.pack('<H', 1)       # RSN Version 1 (2 bytes, little-endian)
    group_cipher_suite = b'\x00\x0f\xac\x04' # Group Cipher Suite: AES (4 bytes)
    pairwise_cipher_suite_count = struct.pack('<H', 1)  # Pairwise Cipher Suite Count: 1 (2 bytes, little-endian)
    pairwise_cipher_suite = b'\x00\x0f\xac\x04'         # Pairwise Cipher Suite: AES (4 bytes)
    akm_suite_count = struct.pack('<H', 1)    # AKM Suite Count: 1 (2 bytes, little-endian)
    akm_suite = b'\x00\x0f\xac\x02'           # AKM Suite: Pre-Shared Key (PSK) (4 bytes)
    rsn_capabilities = struct.pack('<H', 0)   # RSN Capabilities (2 bytes, little-endian)

    # Assemble the RSN IE
    rsn_info = (
        rsn_version +
        group_cipher_suite +
        pairwise_cipher_suite_count +
        pairwise_cipher_suite +
        akm_suite_count +
        akm_suite +
        rsn_capabilities
    )

    # Create the RSN Information Element
    rsn = Dot11Elt(ID='RSNinfo', info=rsn_info)

    frame = RadioTap()/dot11/beacon/essid/rsn/dsset/vendor_ie

    # Send the frame a fixed number of times
    num_frames = 50  # You can adjust this number as needed
    logging.info(f'Sending {num_frames} beacon frames...')
    sendp(frame, iface=iface, count=num_frames, inter=0.1, verbose=0)
    logging.info('Beacon transmission completed.')

def speaker_main():
    """
    Main function for the Speaker script.

    - Obtains the wireless interface.
    - Prompts the user for the secret password and message.
    - Generates the SSID and encryption key.
    - Encrypts the message.
    - Starts broadcasting beacon frames with the SSID and encrypted message.
    """
    iface = get_wireless_interface()
    password = getpass('[INPUT] Enter secret password: ')
    ssid = generate_ssid_identifier(password)
    logging.info(f'Using interface: {iface}')
    logging.info(f'SSID to broadcast: {ssid}')

    # Derive encryption key
    encryption_salt = b'sshid_encryption_salt'
    key = derive_key(password, encryption_salt)

    message = input('[INPUT] Enter message to broadcast (max 100 characters): ')
    if len(message) > 100:
        logging.warning('Message too long, truncating to 100 characters.')
        message = message[:100]

    # Encrypt the message
    nonce, ciphertext = encrypt_message(message, key)
    # Encode the encrypted data
    encoded_data = encode_data(nonce, ciphertext)
    logging.info(f'Encoded encrypted message length: {len(encoded_data)} characters')

    # Specify the channel (e.g., 1)
    channel = 1

    # Send a fixed number of beacon frames
    broadcast_beacon(iface, ssid, encoded_data, channel)

    logging.info('Message broadcast completed.')
    logging.info('Closing the Speaker. Bye!')

if __name__ == '__main__':
    speaker_main()
