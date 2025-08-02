import re
import sqlite3
import hashlib
import random
import base64
import codecs
import binascii
import struct
from datetime import datetime, timezone
from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
from typing import Optional
from astrbot.api.all import *
from urllib.parse import quote, unquote
from encodings import idna

class Cipher2Server:  # 保留旧版加密
    def __init__(self, db_path='./data/cipher.db'):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS cipher_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    version INTEGER DEFAULT 2,
                    mode TEXT CHECK(mode IN ('encrypt', 'decrypt')),
                    content TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # 检查并添加缺失的version列
            cursor = conn.execute("PRAGMA table_info(cipher_logs)")
            columns = [row[1] for row in cursor.fetchall()]
            if 'version' not in columns:
                conn.execute("ALTER TABLE cipher_logs ADD COLUMN version INTEGER DEFAULT 2")

    def _log_operation(self, user_id: str, mode: str, content: str, version=2):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                'INSERT INTO cipher_logs (user_id, mode, content, version) VALUES (?, ?, ?, ?)',
                (user_id, mode, content, version)
            )

    def generate_maps(self, key: str):
        chars = ['我', '要', '吃', '饭']
        seed = int(hashlib.sha256(key.encode()).hexdigest(), 16)
        random.seed(seed)
        shuffled = chars.copy()
        random.shuffle(shuffled)
        return {
            '00': shuffled[0],
            '01': shuffled[1],
            '10': shuffled[2],
            '11': shuffled[3]
        }, {v: k for k, v in zip(['00', '01', '10', '11'], shuffled)}

    def encrypt_text(self, text: str, key: str) -> str:
        binary_map, _ = self.generate_maps(key)
        bytes_data = text.encode('utf-8')
        binary = ''.join([bin(byte)[2:].zfill(8) for byte in bytes_data])
        return ''.join([binary_map.get(binary[i:i+2], '我') for i in range(0, len(binary), 2)])

    def decrypt_text(self, cipher: str, key: str) -> str:
        _, text_map = self.generate_maps(key)
        binary = []
        for char in cipher:
            bits = text_map.get(char)
            if bits is None:
                raise ValueError("包含无效字符")
            binary.append(bits)
        binary_str = ''.join(binary)
        if len(binary_str) % 8 != 0:
            raise ValueError("无效的密文长度")
        bytes_list = [int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8)]
        try:
            return bytes(bytes_list).decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("解密失败：无效的字节序列")

class Cipher3Server:  # 新版加密
    CHAR_SET = ['哦', '齁', '❤', '咿', '啊', '呃', '~', '！']
    
    def _crc32(self, data: str) -> int:
        return binascii.crc32(data.encode()) & 0xFFFFFFFF
        
    def generate_maps(self, key: str):
        seed_hash = hashlib.sha256(key.encode()).hexdigest()
        state = int(seed_hash[:8], 16)
        shuffled = self.CHAR_SET.copy()
        n = len(shuffled)
        for i in range(n - 1, 0, -1):
            state = self._crc32(f"{seed_hash}{state}")
            j = state % (i + 1)
            shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
        
        binary_map = {
            '000': shuffled[0],
            '001': shuffled[1],
            '010': shuffled[2],
            '011': shuffled[3],
            '100': shuffled[4],
            '101': shuffled[5],
            '110': shuffled[6],
            '111': shuffled[7]
        }
        text_map = {v: k for k, v in binary_map.items()}
        return binary_map, text_map
    
    def generate_key_stream(self, length: int, key: str) -> bytes:
        stream = b''
        current_hash = key.encode()
        while len(stream) < length:
            current_hash = hashlib.sha256(current_hash).digest()
            stream += current_hash
        return stream[:length]
    
    def encrypt_text(self, text: str, key: str) -> str:
        if not re.fullmatch(r'^[\x21-\x7E]{1,20}$', key):
            raise ValueError("密钥必须为1-20位可打印ASCII字符（不含空格）")
        bytes_data = text.encode('utf-8')
        key_stream = self.generate_key_stream(len(bytes_data), key)
        binary_map, _ = self.generate_maps(key)
        encrypted_bytes = bytes([
            byte ^ key_stream[i] 
            for i, byte in enumerate(bytes_data)
        ])
        binary_str = ''.join([bin(b)[2:].zfill(8) for b in encrypted_bytes])
        padding = (3 - len(binary_str) % 3) % 3 
        binary_str += '0' * padding      
        cipher = ''.join(
            binary_map.get(binary_str[i:i+3], '哦')
            for i in range(0, len(binary_str), 3)
        )
        return cipher
    
    def decrypt_text(self, cipher: str, key: str) -> str:
        if not re.fullmatch(r'^[\x21-\x7E]{1,20}$', key):
            raise ValueError("密钥必须为1-20位可打印ASCII字符（不含空格）")       
        _, text_map = self.generate_maps(key)       
        binary_str = ''
        for char in cipher:
            if bits := text_map.get(char):
                binary_str += bits
            else:
                raise ValueError(f"包含无效字符: {char}")       
        original_bit_length = len(binary_str) - (len(binary_str) % 8)
        binary_str = binary_str[:original_bit_length]       
        byte_array = bytearray()
        for i in range(0, len(binary_str), 8):
            byte_chunk = binary_str[i:i+8]
            byte_array.append(int(byte_chunk, 2))      
        key_stream = self.generate_key_stream(len(byte_array), key)
        decrypted = bytes([b ^ key_stream[i] for i, b in enumerate(byte_array)])
        
        try:
            return decrypted.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("解密结果包含无效UTF-8序列")

@register("cipher", "Yuki Soffd", "集合多种加解密功能的astrbot插件", "2.0.0", "https://github.com/Soffd/astrbot_plugin_encipherer")
class CipherPlugin(Star):
    server_v2 = Cipher2Server()  
    server_v3 = Cipher3Server()  
    
    def __init__(self, context: Context):
        super().__init__(context)
    
    @filter.command("加密")
    async def encrypt_command(self, event: AstrMessageEvent):
        full_text = event.message_str.strip()
        args = full_text.split(maxsplit=2)
        
        if len(args) < 3:
            yield event.plain_result("❌ 格式错误，请使用：加密 密钥 明文内容")
            return
        
        _, key, plaintext = args
        if not re.fullmatch(r'^[A-Za-z0-9]{1,12}$', key):
            yield event.plain_result("❌ 密钥格式错误，必须为1-12位字母或数字组合")
            return
        
        user_id = event.get_sender_id()
        try:
            cipher = self.server_v2.encrypt_text(plaintext, key)
            self.server_v2._log_operation(user_id, 'encrypt', plaintext, 2)
            yield event.plain_result(f"🔒 [v2] 加密结果：\n{cipher}")
        except Exception as e:
            logger.error(f"v2加密失败: {str(e)}", exc_info=True)
            yield event.plain_result(f"❌ v2加密失败: {str(e)}")

    @filter.command("解密")
    async def decrypt_command(self, event: AstrMessageEvent):
        full_text = event.message_str.strip()
        args = full_text.split(maxsplit=2)
        
        if len(args) < 3:
            yield event.plain_result("❌ 格式错误，请使用：解密 密钥 密文内容")
            return
        
        _, key, ciphertext = args
        if not re.fullmatch(r'^[A-Za-z0-9]{1,12}$', key):
            yield event.plain_result("❌ 密钥格式错误，必须为1-12位字母或数字组合")
            return
        
        user_id = event.get_sender_id()
        try:
            plaintext_result = self.server_v2.decrypt_text(ciphertext, key)
            self.server_v2._log_operation(user_id, 'decrypt', ciphertext, 2)
            yield event.plain_result(f"🔓 [v2] 解密结果：\n{plaintext_result}")
        except ValueError as e:
            yield event.plain_result(f"❌ v2解密失败：{str(e)}")
        except Exception as e:
            logger.error(f"v2解密失败: {str(e)}", exc_info=True)
            yield event.plain_result("❌ v2解密失败，请检查密文格式或密钥是否正确")
    
    @filter.command("魅魔语加密")
    async def encrypt3_command(self, event: AstrMessageEvent):
        full_text = event.message_str.strip()
        args = full_text.split(maxsplit=2)
        
        if len(args) < 3:
            yield event.plain_result("❌ 格式错误，请使用：魅魔语加密 密钥 明文内容")
            return
        
        _, key, plaintext = args
        user_id = event.get_sender_id()
        try:
            cipher = self.server_v3.encrypt_text(plaintext, key)
            self.server_v2._log_operation(user_id, 'encrypt', plaintext, 3)
            yield event.plain_result(f"🔒 [v3] 加密结果：\n{cipher}")
        except ValueError as e:
            yield event.plain_result(f"❌ v3加密失败：{str(e)}")
        except Exception as e:
            logger.error(f"v3加密失败: {str(e)}", exc_info=True)
            yield event.plain_result("❌ v3加密失败，请检查输入内容")

    @filter.command("魅魔语解密")
    async def decrypt3_command(self, event: AstrMessageEvent):
        full_text = event.message_str.strip()
        args = full_text.split(maxsplit=2)
        
        if len(args) < 3:
            yield event.plain_result("❌ 格式错误，请使用：魅魔语解密 密钥 密文内容")
            return
        
        _, key, ciphertext = args
        user_id = event.get_sender_id()
        try:
            plaintext = self.server_v3.decrypt_text(ciphertext, key)
            self.server_v2._log_operation(user_id, 'decrypt', ciphertext, 3)
            yield event.plain_result(f"🔓 [v3] 解密结果：\n{plaintext}")
        except ValueError as e:
            yield event.plain_result(f"❌ v3解密失败：{str(e)}")
        except Exception as e:
            logger.error(f"v3解密失败: {str(e)}", exc_info=True)
            yield event.plain_result("❌ v3解密失败，请检查密文格式或密钥是否正确")

    @filter.command("Base64编码")
    async def base64_encrypt(self, event: AstrMessageEvent):
        full_text = event.message_str.strip()
        args = full_text.split(maxsplit=1)
        
        if len(args) < 2:
            yield event.plain_result("❌ 格式错误，请使用：Base64编码 明文")
            return
        
        _, plaintext = args
        try:
            encoded = base64.b64encode(plaintext.encode('utf-8')).decode('utf-8')
            yield event.plain_result(f"🔒 Base64编码结果：\n{encoded}")
        except Exception as e:
            logger.error(f"Base64编码失败: {str(e)}", exc_info=True)
            yield event.plain_result("❌ 编码失败，请检查输入内容")

    @filter.command("Base64解码")
    async def base64_decrypt(self, event: AstrMessageEvent):
        full_text = event.message_str.strip()
        args = full_text.split(maxsplit=1)
        
        if len(args) < 2:
            yield event.plain_result("❌ 格式错误，请使用：Base解码 密文")
            return
        
        _, ciphertext = args
        try:
            decoded = base64.b64decode(ciphertext).decode('utf-8')
            yield event.plain_result(f"🔓 Base64解码结果：\n{decoded}")
        except base64.binascii.Error:
            yield event.plain_result("❌ 解码失败：无效的Base64格式")
        except UnicodeDecodeError:
            yield event.plain_result("❌ 解码失败：内容无法转换为UTF-8文本")
        except Exception as e:
            logger.error(f"Base64解码失败: {str(e)}", exc_info=True)
            yield event.plain_result("❌ 解码失败，发生未知错误")

    @filter.command("URL编码")
    async def url_encrypt_command(self, event: AstrMessageEvent):
        full_text = event.message_str.strip()
        args = full_text.split(maxsplit=1)
        
        if len(args) < 2:
            yield event.plain_result("❌ 格式错误，请使用：URL编码 明文")
            return
        
        _, plaintext = args
        try:
            encoded = quote(plaintext, safe='', encoding='utf-8')
            yield event.plain_result(f"🔗 URL编码结果：\n{encoded}")
        except UnicodeEncodeError:
            yield event.plain_result("❌ 编码失败：包含无法处理的字符")
        except Exception as e:
            logger.error(f"URL编码失败: {str(e)}", exc_info=True)
            yield event.plain_result("❌ 编码失败，发生未知错误")

    @filter.command("URL解码")
    async def url_decrypt_command(self, event: AstrMessageEvent):
        full_text = event.message_str.strip()
        args = full_text.split(maxsplit=1)
        
        if len(args) < 2:
            yield event.plain_result("❌ 格式错误，请使用：URL解码 密文")
            return
        
        _, ciphertext = args
        try:
            decoded = unquote(ciphertext, encoding='utf-8', errors='replace')
            yield event.plain_result(f"🔗 URL解码结果：\n{decoded}")
        except UnicodeDecodeError:
            yield event.plain_result("❌ 解码失败：包含无效的编码序列")
        except Exception as e:
            logger.error(f"URL解码失败: {str(e)}", exc_info=True)
            yield event.plain_result("❌ 解码失败，请检查输入格式")

    @filter.command("Pun编码")
    async def punycode_encrypt(self, event: AstrMessageEvent):
        full_text = event.message_str.strip()
        args = full_text.split(maxsplit=1)
        
        if len(args) < 2:
            yield event.plain_result("❌ 格式错误，请使用：Pun编码 明文")
            return
        
        _, plaintext = args
        try:
            encoded_parts = []
            for part in plaintext.split('.'):
                if part.isascii():
                    encoded_parts.append(part)
                else:
                    encoded_parts.append(idna.ToASCII(part).decode('utf-8'))
            encoded = '.'.join(encoded_parts)
            yield event.plain_result(f"🔣 Punycode编码结果：\n{encoded}")
        except UnicodeError:
            yield event.plain_result("❌ 编码失败：包含无效的Unicode字符")
        except Exception as e:
            logger.error(f"Punycode编码失败: {str(e)}", exc_info=True)
            yield event.plain_result("❌ 编码失败，发生未知错误")

    @filter.command("Pun解码")
    async def punycode_decrypt(self, event: AstrMessageEvent):
        full_text = event.message_str.strip()
        args = full_text.split(maxsplit=1)
        
        if len(args) < 2:
            yield event.plain_result("❌ 格式错误，请使用：Pun解码 密文")
            return
        
        _, ciphertext = args
        try:
            decoded_parts = []
            for part in ciphertext.split('.'):
                if part.startswith('xn--'):
                    decoded_parts.append(idna.ToUnicode(part.encode('utf-8')))
                else:
                    decoded_parts.append(part)
            decoded = '.'.join(decoded_parts)
            yield event.plain_result(f"🔣 Punycode解码结果：\n{decoded}")
        except idna.IDNAError as e:
            yield event.plain_result(f"❌ 解码失败：{str(e)}")
        except Exception as e:
            logger.error(f"Punycode解码失败: {str(e)}", exc_info=True)
            yield event.plain_result("❌ 解码失败，请检查输入格式")

    @filter.command("加解密帮助")
    async def help_command(self, event: AstrMessageEvent):
        help_text = (
            "📖 加密插件使用说明\n"
            "——集合多种加解密工具——\n\n"
            "🔹 作者：Yuki Soffd\n"
            "🔹 版本：2.0.0\n\n"
            "📌 使用指令：\n"
            "1. 加密 <1-12位密钥> <明文> - [旧版] 使用「我要吃饭」加密\n"
            "2. 解密 <1-12位密钥> <密文> - [旧版] 解密\n"
            "3. 魅魔语加密 <1-20位密钥> <明文> - [新版] 使用魅魔语加密\n"
            "4. 魅魔语解密 <1-20位密钥> <密文> - [新版] 解密\n"
            "5. Base64编码 <明文> - Base64编码\n"
            "6. Base64解码 <密文> - Base64解码\n"
            "7. URL编码 <明文> - URL百分号编码\n"
            "8. URL解码 <密文> - URL百分号解码\n"
            "9. Pun编码 <明文> - Punycode编码\n"  
            "10. Pun解码 <密文> - Punycode解码\n\n"  
            "自定义加解密说明：\n"
            "- 旧版：保留历史版本，密钥1-12位字母数字\n"
            "- 新版：更安全难破解，密钥1-20位ASCII字符\n"
            "- 注意：两套系统不兼容，请勿"
        )
        yield event.plain_result(help_text)

    
