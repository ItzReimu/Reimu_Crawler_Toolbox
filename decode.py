import base64
import binascii
from Crypto.Cipher import AES, DES, DES3, ARC4, Blowfish
from Crypto.Util.Padding import unpad
import hashlib
import zlib
import quopri
import urllib.parse
import codecs
import html
import argparse
import re
import jwt
from collections import defaultdict
import string

class AdvancedMultiDecoder:
    MORSE_CODE_DICT = { 
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
        'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
        'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
        'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
        'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
        'Z': '--..', '1': '.----', '2': '..---', '3': '...--',
        '4': '....-', '5': '.....', '6': '-....', '7': '--...',
        '8': '---..', '9': '----.', '0': '-----', ',': '--..--',
        '.': '.-.-.-', '?': '..--..', '/': '-..-.', '-': '-....-',
        '(': '-.--.', ')': '-.--.-', ' ': '/'
    }
    
    # 反转摩斯电码字典用于解码
    REVERSE_MORSE_DICT = {v: k for k, v in MORSE_CODE_DICT.items()}

    def __init__(self):
        self.common_keys = [
            b'', b' ', b'0', b'1', b'123', b'1234', b'12345', 
            b'123456', b'1234567', b'12345678', b'123456789',
            b'password', b'admin', b'root', b'key', b'secret',
            b'qwerty', b'abc123', b'letmein', b'welcome'
        ]
        
        # 初始化所有支持的算法
        self.decoders = [
            self.try_base64, self.try_url, self.try_html, self.try_hex,
            self.try_binary, self.try_octal, self.try_quoted_printable,
            self.try_base32, self.try_base85, self.try_ascii85,
            self.try_base58, self.try_base45, self.try_ascii, 
            self.try_unicode_escape, self.try_morse_code, self.try_jwt, 
            self.try_rot13, self.try_caesar_cipher, self.try_caesar_5shift,
            self.try_atbash, self.try_bacon, self.try_compression, 
            self.try_encryption, self.identify_hash, self.try_reverse, 
            self.try_uuencode, self.try_xxencode, self.try_rot47,
            self.try_vigenere, self.try_affine, self.try_railfence,
            self.try_binary_to_text, self.try_hexdump, self.try_manchester, self.try_unicode_codepoint
        ]
    
    # ========== 编码/解码方法 ==========
    
    def try_base64(self, data):
        try:
            return base64.b64decode(data).decode('utf-8', errors='ignore')
        except:
            try:
                return base64.b64decode(data + b'=' * (-len(data) % 4)).decode('utf-8', errors='ignore')
            except:
                return None
    
    def try_base32(self, data):
        try:
            return base64.b32decode(data).decode('utf-8', errors='ignore')
        except:
            return None
    
    def try_base16(self, data):
        try:
            return base64.b16decode(data).decode('utf-8', errors='ignore')
        except:
            return None
    
    def try_base85(self, data):
        try:
            return base64.b85decode(data).decode('utf-8', errors='ignore')
        except:
            return None
    
    def try_ascii85(self, data):
        try:
            return base64.a85decode(data).decode('utf-8', errors='ignore')
        except:
            return None
    
    def try_base58(self, data):
        # 需要安装base58库: pip install base58
        try:
            import base58
            return base58.b58decode(data).decode('utf-8', errors='ignore')
        except:
            return None
    
    def try_base45(self, data):
        try:
            from base45 import b45decode
            return b45decode(data).decode('utf-8', errors='ignore')
        except:
            return None
    
    def try_hex(self, data):
        try:
            return bytes.fromhex(data.decode()).decode('utf-8', errors='ignore')
        except:
            return None
    
    def try_url(self, data):
        try:
            return urllib.parse.unquote(data.decode())
        except:
            return None
    
    def try_html(self, data):
        try:
            return html.unescape(data.decode())
        except:
            return None
    
    def try_quoted_printable(self, data):
        try:
            return quopri.decodestring(data).decode('utf-8', errors='ignore')
        except:
            return None
    
    def try_rot13(self, data):
        try:
            return codecs.decode(data.decode(), 'rot13')
        except:
            return None
    
    def try_rot47(self, data):
        try:
            decoded = []
            for char in data.decode():
                ord_char = ord(char)
                if 33 <= ord_char <= 126:
                    decoded_char = chr(33 + ((ord_char + 14) % 94))
                    decoded.append(decoded_char)
                else:
                    decoded.append(char)
            return ''.join(decoded)
        except:
            return None
    
    def try_zlib(self, data):
        try:
            return zlib.decompress(data).decode('utf-8', errors='ignore')
        except:
            return None
    
    def try_gzip(self, data):
        try:
            return zlib.decompress(data, 16+zlib.MAX_WBITS).decode('utf-8', errors='ignore')
        except:
            return None
    
    def try_binary(self, data):
        try:
            binary_str = data.decode().replace(' ', '')
            if not all(c in '01' for c in binary_str):
                return None
            # 将二进制字符串分割成8位一组
            n = 8
            bytes_list = [binary_str[i:i+n] for i in range(0, len(binary_str), n)]
            # 将每组转换为字符
            return ''.join([chr(int(byte, 2)) for byte in bytes_list])
        except:
            return None
    
    def try_octal(self, data):
        try:
            octal_str = data.decode().replace(' ', '')
            if not all(c in '01234567' for c in octal_str):
                return None
            # 将八进制字符串分割成3位一组
            n = 3
            bytes_list = [octal_str[i:i+n] for i in range(0, len(octal_str), n)]
            # 将每组转换为字符
            return ''.join([chr(int(byte, 8)) for byte in bytes_list])
        except:
            return None
    
    def try_ascii(self, data):
        try:
            return ''.join([chr(c) for c in data])
        except:
            return None
    
    def try_unicode_escape(self, data):
        try:
            return data.decode('unicode_escape')
        except:
            return None
    
    def try_morse_code(self, data):
        try:
            morse_code = data.decode().strip()
            # 检查是否是有效的摩斯电码
            if not all(c in '.-/ ' for c in morse_code):
                return None
            
            words = morse_code.split('/')
            decoded_message = []
            for word in words:
                letters = word.split()
                decoded_word = []
                for letter in letters:
                    decoded_word.append(self.REVERSE_MORSE_DICT.get(letter, ''))
                decoded_message.append(''.join(decoded_word))
            return ' '.join(decoded_message)
        except:
            return None
    
    def try_jwt(self, data):
        try:
            decoded = jwt.decode(data.decode(), options={"verify_signature": False})
            return str(decoded)
        except:
            return None
    # 4/30新加unicode码点解密和字符偏移
    def try_unicode_codepoint(self, data):
        try:
            text = data.decode('utf-8', errors='ignore')
            decoded = []
            i = 0
            n = len(text)
            
            while i < n:
                if i + 2 < n and text[i] == '\\' and text[i+1] == 'u':

                    hex_str = text[i+2:i+6]
                    if len(hex_str) == 4 and all(c in string.hexdigits for c in hex_str):
                        decoded.append(chr(int(hex_str, 16)))
                        i += 6
                        continue
                elif i + 2 < n and text[i].upper() == 'U' and text[i+1] == '+':

                    j = i + 2
                    hex_str = ''
                    while j < n and len(hex_str) < 5 and text[j] in string.hexdigits:
                        hex_str += text[j]
                        j += 1
                    if hex_str:
                        decoded.append(chr(int(hex_str, 16)))
                        i = j
                        continue
                elif i + 3 < n and text[i] == '&' and text[i+1] == '#' and text[i+2] == 'x':

                    end = text.find(';', i+3)
                    if end != -1:
                        hex_str = text[i+3:end]
                        if 1 <= len(hex_str) <= 5 and all(c in string.hexdigits for c in hex_str):
                            decoded.append(chr(int(hex_str, 16)))
                            i = end + 1
                            continue
                
                decoded.append(text[i])
                i += 1
            
            return ''.join(decoded)
        except:
            return None


    def try_char_shift(self, data):
        try:
            text = data.decode('utf-8', errors='ignore')
            for offset in range(1, 6):
                decoded_forward = self._apply_char_shift(text, offset)
                if self._looks_valid(decoded_forward):
                    return f"Forward shift {offset}: {decoded_forward}"
                
                decoded_backward = self._apply_char_shift(text, -offset)
                if self._looks_valid(decoded_backward):
                    return f"Backward shift {offset}: {decoded_backward}"
            return None
        except:
            return None

    def _apply_char_shift(self, text, offset):
        result = []
        for char in text:
            new_code = ord(char) + offset
            if new_code < 0:
                new_code += 0x110000
            new_code %= 0x110000
            result.append(chr(new_code))
        return ''.join(result)

    def _looks_valid(self, text):
        if not text:
            return False
        valid_chars = 0
        for char in text:
            code = ord(char)
            if (32 <= code <= 126) or (0x4E00 <= code <= 0x9FFF):
                valid_chars += 1
        return valid_chars / len(text) > 0.5  
    def try_caesar_cipher(self, data):
        try:
            text = data.decode()
            if not text.isalpha():
                return None
            
            results = []
            for shift in range(1, 26):
                decrypted = []
                for char in text:
                    if char.isupper():
                        decrypted.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
                    elif char.islower():
                        decrypted.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
                    else:
                        decrypted.append(char)
                results.append(f"Shift {shift}: {''.join(decrypted)}")
            return "\n".join(results)
        except:
            return None
    
    def try_caesar_5shift(self, data):
        try:
            text = data.decode()
            if not text.isalpha():
                return None
            
            shift = 5
            decrypted = []
            for char in text:
                if char.isupper():
                    decrypted.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
                elif char.islower():
                    decrypted.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
                else:
                    decrypted.append(char)
            return ''.join(decrypted)
        except:
            return None
    
    def try_atbash(self, data):
        try:
            text = data.decode()
            atbash_map = str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba'
            )
            return text.translate(atbash_map)
        except:
            return None
    
    def try_bacon(self, data):
        try:
            bacon_code = data.decode().upper()
            if not all(c in 'AB ' for c in bacon_code):
                return None
            
            bacon_dict = {
                'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D', 'AABAA': 'E',
                'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H', 'ABAAA': 'I', 'ABAAB': 'J',
                'ABABA': 'K', 'ABABB': 'L', 'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O',
                'ABBBB': 'P', 'BAAAA': 'Q', 'BAAAB': 'R', 'BAABA': 'S', 'BAABB': 'T',
                'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X', 'BBAAA': 'Y',
                'BBAAB': 'Z'
            }
            
            words = bacon_code.split()
            decoded = []
            for word in words:
                # 补全到5的倍数长度
                word = word.ljust((len(word) + 4) // 5 * 5, 'A')
                # 分割成5个一组
                groups = [word[i:i+5] for i in range(0, len(word), 5)]
                for group in groups:
                    decoded.append(bacon_dict.get(group, ''))
            return ''.join(decoded)
        except:
            return None
    
    def try_compression(self, data):
        # 尝试各种压缩算法
        result = self.try_zlib(data)
        if result: return {"zlib": result}
        
        result = self.try_gzip(data)
        if result: return {"gzip": result}
        
        return None
    
    def try_encryption(self, data):
        # 尝试各种加密算法
        results = {}
        
        for key in self.common_keys:
            # AES
            aes_result = self._try_aes(data, key)
            if aes_result: results[f"AES-{key.decode(errors='ignore')}"] = aes_result
            
            # DES
            des_result = self._try_des(data, key)
            if des_result: results[f"DES-{key.decode(errors='ignore')}"] = des_result
            
            # 3DES
            des3_result = self._try_3des(data, key)
            if des3_result: results[f"3DES-{key.decode(errors='ignore')}"] = des3_result
            
            # Blowfish
            bf_result = self._try_blowfish(data, key)
            if bf_result: results[f"Blowfish-{key.decode(errors='ignore')}"] = bf_result
            
            # RC4
            rc4_result = self._try_rc4(data, key)
            if rc4_result: results[f"RC4-{key.decode(errors='ignore')}"] = rc4_result
        
        return results if results else None
    
    def identify_hash(self, data):
        try:
            data_str = data.decode().strip()
            length = len(data_str)
            
            # 常见哈希模式识别
            hash_types = {
                32: 'MD5',
                40: 'SHA1',
                56: 'SHA224',
                64: 'SHA256',
                96: 'SHA384',
                128: 'SHA512',
                28: 'MySQL 4.1+',
                16: 'MySQL 3.2.3',
                34: 'Cisco PIX',
                60: 'Blowfish',
                57: 'DES(Unix)'
            }
            
            # 检查是否是十六进制字符串
            if all(c in string.hexdigits for c in data_str):
                hash_type = hash_types.get(length, 'Unknown')
                return f"Possible {hash_type} hash"
            else:
                return None
        except:
            return None
    
    def try_reverse(self, data):
        try:
            return data.decode()[::-1]
        except:
            return None
    
    def try_uuencode(self, data):
        try:
            if not data.startswith(b'begin '):
                return None
                
            lines = data.splitlines()
            decoded = bytearray()
            
            for line in lines[1:-1]:
                if not line:
                    continue
                    
                length = line[0] - 32
                if length <= 0:
                    continue
                    
                for i in range(1, len(line), 4):
                    chunk = line[i:i+4]
                    while len(chunk) < 4:
                        chunk += b' '
                    
                    a, b, c, d = (x - 32 for x in chunk)
                    decoded.append((a << 2) | (b >> 4))
                    if length > 1:
                        decoded.append((b << 4) | (c >> 2))
                    if length > 2:
                        decoded.append((c << 6) | d)
                    length -= 3
                    
            return decoded.decode('utf-8', errors='ignore')
        except:
            return None
        
    def try_xxencode(self, data):
        try:
            from xx import xxdecode
            return xxdecode(data.decode())
        except:
            return None
    
    def try_vigenere(self, data):
        try:
            text = data.decode()
            if not text.isalpha():
                return None
            
            def decrypt(ciphertext, key):
                key_length = len(key)
                key_as_int = [ord(i) for i in key]
                ciphertext_int = [ord(i) for i in ciphertext]
                plaintext = ''
                for i in range(len(ciphertext_int)):
                    value = (ciphertext_int[i] - key_as_int[i % key_length]) % 26
                    plaintext += chr(value + ord('A'))
                return plaintext
            
            results = []
            for key in ['KEY', 'SECRET', 'PASSWORD', 'CRYPTO']:
                results.append(f"Key '{key}': {decrypt(text.upper(), key.upper())}")
            
            return "\n".join(results)
        except:
            return None
    
    def try_affine(self, data):
        try:
            text = data.decode()
            if not text.isalpha():
                return None
            
            def decrypt(ciphertext, a, b):
                a_inv = 0
                for i in range(26):
                    if (a * i) % 26 == 1:
                        a_inv = i
                        break
                
                plaintext = ""
                for char in ciphertext:
                    if char.isupper():
                        plaintext += chr(((a_inv * (ord(char) - ord('A') - b)) % 26 + ord('A')))
                    elif char.islower():
                        plaintext += chr(((a_inv * (ord(char) - ord('a') - b)) % 26 + ord('a')))
                    else:
                        plaintext += char
                return plaintext
            
            results = []
            for a in [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]:
                for b in range(26):
                    results.append(f"a={a}, b={b}: {decrypt(text, a, b)}")
            
            return "\n".join(results[:10])
        except:
            return None
    
    def try_railfence(self, data):
        try:
            text = data.decode()
            
            def decrypt(cipher, rails):
                fence = [[] for _ in range(rails)]
                rail = 0
                direction = 1
                
                for char in cipher:
                    fence[rail].append(char)
                    rail += direction
                    if rail == rails - 1 or rail == 0:
                        direction = -direction
                
                indices = []
                for i in range(rails):
                    indices.extend(fence[i])
                
                result = [''] * len(cipher)
                pos = 0
                for i in range(rails):
                    for j in range(len(fence[i])):
                        result[indices[pos]] = fence[i][j]
                        pos += 1
                
                return ''.join(result)
            
            results = []
            for rails in range(2, 6):
                results.append(f"Rails={rails}: {decrypt(text, rails)}")
            
            return "\n".join(results)
        except:
            return None
    
    def try_binary_to_text(self, data):
        try:
            binary_str = data.decode().replace(' ', '')
            if len(binary_str) % 8 != 0:
                return None
            bytes_list = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
            return ''.join([chr(int(byte, 2)) for byte in bytes_list])
        except:
            return None
    
    def try_hexdump(self, data):
        try:
            # 尝试解析hexdump格式
            hex_str = re.sub(r'[^0-9a-fA-F]', '', data.decode())
            if len(hex_str) % 2 != 0:
                return None
            return bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
        except:
            return None
    
    def try_manchester(self, data):
        try:
            binary_str = data.decode().replace(' ', '')
            if len(binary_str) % 2 != 0:
                return None
            # 曼彻斯特解码：01->1, 10->0
            decoded_bits = []
            for i in range(0, len(binary_str), 2):
                pair = binary_str[i:i+2]
                if pair == '01':
                    decoded_bits.append('1')
                elif pair == '10':
                    decoded_bits.append('0')
                else:
                    return None
            # 将二进制转换为文本
            binary_str = ''.join(decoded_bits)
            bytes_list = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
            return ''.join([chr(int(byte, 2)) for byte in bytes_list])
        except:
            return None
    
    # ========== 加密算法辅助方法 ==========
    
    def _try_aes(self, data, key, mode='ECB'):
        try:
            key = self._adjust_key_length(key, 32)
            
            if mode == 'ECB':
                cipher = AES.new(key, AES.MODE_ECB)
                decrypted = cipher.decrypt(data)
                return self._try_unpad(decrypted).decode('utf-8', errors='ignore')
            elif mode == 'CBC':
                iv = data[:16]
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                decrypted = cipher.decrypt(data[16:])
                return self._try_unpad(decrypted).decode('utf-8', errors='ignore')
        except:
            return None
    
    def _try_des(self, data, key, mode='ECB'):
        try:
            key = self._adjust_key_length(key, 8)
            
            if mode == 'ECB':
                cipher = DES.new(key, DES.MODE_ECB)
                decrypted = cipher.decrypt(data)
                return self._try_unpad(decrypted).decode('utf-8', errors='ignore')
            elif mode == 'CBC':
                iv = data[:8]
                cipher = DES.new(key, DES.MODE_CBC, iv=iv)
                decrypted = cipher.decrypt(data[8:])
                return self._try_unpad(decrypted).decode('utf-8', errors='ignore')
        except:
            return None
    
    def _try_3des(self, data, key, mode='ECB'):
        try:
            key = self._adjust_key_length(key, 24)
            
            if mode == 'ECB':
                cipher = DES3.new(key, DES3.MODE_ECB)
                decrypted = cipher.decrypt(data)
                return self._try_unpad(decrypted).decode('utf-8', errors='ignore')
            elif mode == 'CBC':
                iv = data[:8]
                cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
                decrypted = cipher.decrypt(data[8:])
                return self._try_unpad(decrypted).decode('utf-8', errors='ignore')
        except:
            return None
    
    def _try_blowfish(self, data, key):
        try:
            key = self._adjust_key_length(key, 16)
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
            decrypted = cipher.decrypt(data)
            return self._try_unpad(decrypted).decode('utf-8', errors='ignore')
        except:
            return None
    
    def _try_rc4(self, data, key):
        try:
            cipher = ARC4.new(key)
            decrypted = cipher.decrypt(data)
            return decrypted.decode('utf-8', errors='ignore')
        except:
            return None
    
    def _adjust_key_length(self, key, desired_length):
        if len(key) > desired_length:
            return key[:desired_length]
        elif len(key) < desired_length:
            return key + b'\0' * (desired_length - len(key))
        return key
    
    def _try_unpad(self, data):
        for pad_style in ['pkcs7', 'x923', 'iso7816']:
            try:
                return unpad(data, AES.block_size, style=pad_style)
            except:
                continue
        return data
    
    # ========== 主解码方法 ==========
    
    def decode(self, data, algorithm=None):
        if not isinstance(data, bytes):
            data = str(data).encode('utf-8')
        
        results = []
        
        if algorithm:
            decoder = getattr(self, f"try_{algorithm}", None)
            if decoder:
                result = decoder(data)
                if result:
                    return {algorithm: result}
                else:
                    return f"Failed to decode with {algorithm}"
            else:
                return f"Unsupported algorithm: {algorithm}"
        else:
            for decoder_func in self.decoders:
                result = decoder_func(data)
                if result:
                    if isinstance(result, dict):
                        results.append(result)
                    else:
                        algo_name = decoder_func.__name__[4:] if decoder_func.__name__.startswith('try_') else decoder_func.__name__
                        results.append({algo_name: result})
            return results if results else "Failed to decode with any algorithm"

def main():
    parser = argparse.ArgumentParser(description='Advanced Multi-Algorithm Decoder Tool')
    parser.add_argument('input', help='Input string or file to decode')
    parser.add_argument('-a', '--algorithm', help='Specify algorithm to try')
    parser.add_argument('-f', '--file', action='store_true', help='Input is a file')
    
    args = parser.parse_args()
    
    decoder = AdvancedMultiDecoder()
    
    if args.file:
        try:
            with open(args.input, 'rb') as f:
                data = f.read()
        except IOError:
            print(f"Error: Could not read file {args.input}")
            return
    else:
        data = args.input.encode()
    
    result = decoder.decode(data, args.algorithm)
    
    if isinstance(result, list):
        print("Possible decodings found:")
        for i, r in enumerate(result, 1):
            print(f"\nOption {i}:")
            for k, v in r.items():
                print(f"  {k}: {v}")
    elif isinstance(result, dict):
        print("Decoding result:")
        for k, v in result.items():
            print(f"  {k}: {v}")
    else:
        print(result)


def process_input(text):
    decoder = AdvancedMultiDecoder()
    decoded = decoder.decode(text)
    if isinstance(decoded, list) and decoded:
        return {'status': 'success', 'results': decoded}
    if isinstance(decoded, dict):
        return {'status': 'success', 'results': [decoded]}
    return {'status': 'failed', 'message': str(decoded) or '未找到可能的解码结果.'}

def process_binary(data):
    try:
        text = data.decode('utf-8')
        return process_input(text)
    except Exception:
        try:
            text = data.decode('latin-1')
            return process_input(text)
        except Exception:
            pass
    try:
        import base64
        b64 = base64.b64encode(data).decode('ascii')
        return process_input(b64)
    except Exception as e:
        return {'status': 'failed', 'message': f'处理二进制数据错误: {e}'}