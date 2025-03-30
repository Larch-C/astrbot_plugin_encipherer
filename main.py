import re
import sqlite3
import hashlib
import random
import base64
import codecs
from datetime import datetime, timezone
from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
from typing import Optional
from astrbot.api.all import *
from urllib.parse import quote, unquote
from encodings import idna


class CipherServer:
    def __init__(self, db_path='./data/cipher.db'):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS cipher_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    mode TEXT CHECK(mode IN ('encrypt', 'decrypt')),
                    content TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

    def _log_operation(self, user_id: str, mode: str, content: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                'INSERT INTO cipher_logs (user_id, mode, content) VALUES (?, ?, ?)',
                (user_id, mode, content)
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

    # BINARY_MAP = {'00': '我', '01': '要', '10': '吃', '11': '饭'}
    # TEXT_MAP = {v: k for k, v in BINARY_MAP.items()}

@register("cipher", "Yuki Soffd", "集合多种加解密功能的astrbot插件", "1.0.0", "https://github.com/Soffd/astrbot_plugin_encipherer")
class CipherPlugin(Star):
    server = CipherServer()
    
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
        if not re.fullmatch(r'^[A-Za-z0-9]{6}$', key):
            yield event.plain_result("❌ 密钥格式错误，必须为6位字母或数字组合")
            return
        
        user_id = event.get_sender_id()
        try:
            cipher = self.server.encrypt_text(plaintext, key)
            self.server._log_operation(user_id, 'encrypt', plaintext)
            yield event.plain_result(f"🔒 加密结果：\n{cipher}")
        except Exception as e:
            logger.error(f"加密失败: {str(e)}", exc_info=True)
            yield event.plain_result("❌ 加密失败，请检查输入内容")

    @filter.command("解密")
    async def decrypt_command(self, event: AstrMessageEvent):
        full_text = event.message_str.strip()
        args = full_text.split(maxsplit=2)
        
        if len(args) < 3:
            yield event.plain_result("❌ 格式错误，请使用：解密 密钥 密文内容")
            return
        
        _, key, ciphertext = args
        if not re.fullmatch(r'^[A-Za-z0-9]{6}$', key):
            yield event.plain_result("❌ 密钥格式错误，必须为6位字母或数字组合")
            return
        
        user_id = event.get_sender_id()
        try:
            plaintext_result = self.server.decrypt_text(ciphertext, key)
            self.server._log_operation(user_id, 'decrypt', ciphertext)
            yield event.plain_result(f"🔓 解密结果：\n{plaintext_result}")
        except ValueError as e:
            yield event.plain_result(f"❌ 解密失败：{str(e)}")
        except Exception as e:
            logger.error(f"解密失败: {str(e)}", exc_info=True)
            yield event.plain_result("❌ 解密失败，请检查密文格式或密钥是否正确")

    @filter.command("Base64编码")
    async def base64_encrypt(self, event: AstrMessageEvent):
        full_text = event.message_str.strip()
        args = full_text.split(maxsplit=1)
        
        if len(args) < 2:
            yield event.plain_result("❌ 格式错误，请使用：Base64加密 明文")
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
            yield event.plain_result("❌ 格式错误，请使用：Base解密 密文")
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
            yield event.plain_result("❌ 格式错误，请使用：URL加密 明文")
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
            yield event.plain_result("❌ 格式错误，请使用：URL解密 密文")
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
            yield event.plain_result("❌ 格式错误，请使用：Pun加密 明文")
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
            yield event.plain_result("❌ 格式错误，请使用：Pun解密 密文")
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
        "🔹 版本：1.0.0\n\n"
        "📌 使用指令：\n"
        "1. 加密 <6位密钥> <明文> - 使用指定密钥加密文字得到「我」「要」「吃」「饭」四个字符组成的密文\n"
        "  例：加密 ABC123 你好\n\n"
        "2. 解密 <6位密钥> <密文> - 使用密钥解密\n"
        "  例：解密 ABC123 我吃要饭\n\n"
        "3. Base64编码 <明文> - Base64编码\n"
        "4. Base64解码 <密文> - Base64解码\n"
        "5. URL编码 <明文> - URL百分号编码\n"
        "6. URL解码 <密文> - URL百分号解码\n"
        "7. Pun编码 <明文> - Punycode编码\n"  
        "8. Pun解码 <密文> - Punycode解码\n\n"  
        "⚠️ 注意：\n"
        "- 密钥必须为6位字母或数字组合\n"
        "- 二进制密文只能包含「我」「要」「吃」「饭」四个字符\n"
        "- Punycode编码适用于国际化域名处理，通常对中文域名进行编码，以便申请SSL证书或操作DNS设置。"
        )
        yield event.plain_result(help_text)

    