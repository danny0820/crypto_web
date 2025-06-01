"""
自定義加密算法實現
=====================

本模塊包含自定義實現的AES-256-GCM和RSA-2048加密算法，
用於替代cryptography庫的實現。

警告：此實現僅用於學習和演示目的，不建議在生產環境中使用。
生產環境應該使用經過充分測試和驗證的cryptography庫。

作者：自定義實現
版本：1.0
"""

import os
import secrets
import math
import hashlib
import struct
from typing import Tuple, List, Union

# ============================
# 數學工具函數
# ============================

def gcd(a: int, b: int) -> int:
    """計算最大公約數"""
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a: int, m: int) -> int:
    """計算模逆元"""
    if gcd(a, m) != 1:
        raise ValueError("模逆元不存在")
    
    # 擴展歐幾里得算法
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    _, x, _ = extended_gcd(a % m, m)
    return (x % m + m) % m

def miller_rabin(n: int, k: int = 5) -> bool:
    """Miller-Rabin素數測試"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # 將n-1寫成d * 2^r的形式
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # 進行k輪測試
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
            
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits: int) -> int:
    """生成指定位數的素數"""
    while True:
        # 生成隨機數
        candidate = secrets.randbits(bits)
        # 確保最高位為1（保證位數）
        candidate |= (1 << (bits - 1))
        # 確保最低位為1（保證奇數）
        candidate |= 1
        
        if miller_rabin(candidate):
            return candidate

# ============================
# AES-256 自定義實現
# ============================

class CustomAES:
    """自定義AES-256實現"""
    
    # S-box
    SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]
    
    # 逆S-box
    INV_SBOX = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]
    
    # Rcon常數
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
    
    def __init__(self, key: bytes):
        """初始化AES加密器
        
        Args:
            key: 32字節的AES-256密鑰
        """
        if len(key) != 32:
            raise ValueError("AES-256密鑰必須是32字節")
        
        self.key = key
        self.round_keys = self._key_expansion(key)
    
    def _key_expansion(self, key: bytes) -> List[List[int]]:
        """密鑰擴展"""
        # 將密鑰轉換為32位字
        w = []
        for i in range(8):  # AES-256有8個初始字
            word = struct.unpack('>I', key[i*4:(i+1)*4])[0]
            w.append(word)
        
        # 擴展到60個字（15輪 × 4字）
        for i in range(8, 60):
            temp = w[i-1]
            
            if i % 8 == 0:
                # RotWord + SubWord + Rcon
                temp = self._rot_word(temp)
                temp = self._sub_word(temp)
                temp ^= (self.RCON[(i//8)-1] << 24)
            elif i % 8 == 4:
                # SubWord
                temp = self._sub_word(temp)
            
            w.append(w[i-8] ^ temp)
        
        # 將字轉換為輪密鑰
        round_keys = []
        for i in range(15):  # AES-256有15輪
            round_key = []
            for j in range(4):
                word = w[i*4 + j]
                round_key.extend([
                    (word >> 24) & 0xff,
                    (word >> 16) & 0xff,
                    (word >> 8) & 0xff,
                    word & 0xff
                ])
            round_keys.append(round_key)
        
        return round_keys
    
    def _rot_word(self, word: int) -> int:
        """字循環左移"""
        return ((word << 8) | (word >> 24)) & 0xffffffff
    
    def _sub_word(self, word: int) -> int:
        """字節替換"""
        result = 0
        for i in range(4):
            byte = (word >> (8 * (3-i))) & 0xff
            result |= (self.SBOX[byte] << (8 * (3-i)))
        return result
    
    def _sub_bytes(self, state: List[List[int]]) -> None:
        """字節替換"""
        for i in range(4):
            for j in range(4):
                state[i][j] = self.SBOX[state[i][j]]
    
    def _inv_sub_bytes(self, state: List[List[int]]) -> None:
        """逆字節替換"""
        for i in range(4):
            for j in range(4):
                state[i][j] = self.INV_SBOX[state[i][j]]
    
    def _shift_rows(self, state: List[List[int]]) -> None:
        """行移位"""
        # 第一行不移位
        # 第二行左移1位
        temp = state[1][0]
        state[1][0] = state[1][1]
        state[1][1] = state[1][2]
        state[1][2] = state[1][3]
        state[1][3] = temp
        
        # 第三行左移2位
        temp1, temp2 = state[2][0], state[2][1]
        state[2][0] = state[2][2]
        state[2][1] = state[2][3]
        state[2][2] = temp1
        state[2][3] = temp2
        
        # 第四行左移3位
        temp = state[3][3]
        state[3][3] = state[3][2]
        state[3][2] = state[3][1]
        state[3][1] = state[3][0]
        state[3][0] = temp
    
    def _inv_shift_rows(self, state: List[List[int]]) -> None:
        """逆行移位"""
        # 第一行不移位
        # 第二行右移1位
        temp = state[1][3]
        state[1][3] = state[1][2]
        state[1][2] = state[1][1]
        state[1][1] = state[1][0]
        state[1][0] = temp
        
        # 第三行右移2位
        temp1, temp2 = state[2][2], state[2][3]
        state[2][2] = state[2][0]
        state[2][3] = state[2][1]
        state[2][0] = temp1
        state[2][1] = temp2
        
        # 第四行右移3位
        temp = state[3][0]
        state[3][0] = state[3][1]
        state[3][1] = state[3][2]
        state[3][2] = state[3][3]
        state[3][3] = temp
    
    def _gmul(self, a: int, b: int) -> int:
        """GF(2^8)中的乘法"""
        result = 0
        while b:
            if b & 1:
                result ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x11b  # AES的不可約多項式
            b >>= 1
        return result & 0xff
    
    def _mix_columns(self, state: List[List[int]]) -> None:
        """列混合"""
        for j in range(4):
            s0, s1, s2, s3 = state[0][j], state[1][j], state[2][j], state[3][j]
            state[0][j] = self._gmul(2, s0) ^ self._gmul(3, s1) ^ s2 ^ s3
            state[1][j] = s0 ^ self._gmul(2, s1) ^ self._gmul(3, s2) ^ s3
            state[2][j] = s0 ^ s1 ^ self._gmul(2, s2) ^ self._gmul(3, s3)
            state[3][j] = self._gmul(3, s0) ^ s1 ^ s2 ^ self._gmul(2, s3)
    
    def _inv_mix_columns(self, state: List[List[int]]) -> None:
        """逆列混合"""
        for j in range(4):
            s0, s1, s2, s3 = state[0][j], state[1][j], state[2][j], state[3][j]
            state[0][j] = self._gmul(14, s0) ^ self._gmul(11, s1) ^ self._gmul(13, s2) ^ self._gmul(9, s3)
            state[1][j] = self._gmul(9, s0) ^ self._gmul(14, s1) ^ self._gmul(11, s2) ^ self._gmul(13, s3)
            state[2][j] = self._gmul(13, s0) ^ self._gmul(9, s1) ^ self._gmul(14, s2) ^ self._gmul(11, s3)
            state[3][j] = self._gmul(11, s0) ^ self._gmul(13, s1) ^ self._gmul(9, s2) ^ self._gmul(14, s3)
    
    def _add_round_key(self, state: List[List[int]], round_key: List[int]) -> None:
        """輪密鑰加"""
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i*4 + j]
    
    def encrypt_block(self, plaintext: bytes) -> bytes:
        """加密一個16字節的塊"""
        if len(plaintext) != 16:
            raise ValueError("塊大小必須是16字節")
        
        # 將輸入轉換為4x4狀態矩陣
        state = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                state[i][j] = plaintext[i*4 + j]
        
        # 初始輪密鑰加
        self._add_round_key(state, self.round_keys[0])
        
        # 14輪加密
        for round_num in range(1, 14):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, self.round_keys[round_num])
        
        # 最後一輪（不包含列混合）
        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, self.round_keys[14])
        
        # 將狀態矩陣轉換為字節
        ciphertext = bytearray(16)
        for i in range(4):
            for j in range(4):
                ciphertext[i*4 + j] = state[i][j]
        
        return bytes(ciphertext)
    
    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """解密一個16字節的塊"""
        if len(ciphertext) != 16:
            raise ValueError("塊大小必須是16字節")
        
        # 將輸入轉換為4x4狀態矩陣
        state = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                state[i][j] = ciphertext[i*4 + j]
        
        # 初始輪密鑰加
        self._add_round_key(state, self.round_keys[14])
        
        # 14輪解密
        for round_num in range(13, 0, -1):
            self._inv_shift_rows(state)
            self._inv_sub_bytes(state)
            self._add_round_key(state, self.round_keys[round_num])
            self._inv_mix_columns(state)
        
        # 最後一輪（不包含列混合）
        self._inv_shift_rows(state)
        self._inv_sub_bytes(state)
        self._add_round_key(state, self.round_keys[0])
        
        # 將狀態矩陣轉換為字節
        plaintext = bytearray(16)
        for i in range(4):
            for j in range(4):
                plaintext[i*4 + j] = state[i][j]
        
        return bytes(plaintext)

class CustomAESGCM:
    """自定義AES-GCM實現（認證加密）"""
    
    def __init__(self, key: bytes):
        """初始化AES-GCM
        
        Args:
            key: 32字節的AES-256密鑰
        """
        self.aes = CustomAES(key)
        self.h = self._get_h()
    
    def _get_h(self) -> int:
        """獲取GCM的H值（加密全零塊）"""
        zero_block = b'\x00' * 16
        h_bytes = self.aes.encrypt_block(zero_block)
        # 將字節轉換為整數
        h = 0
        for byte in h_bytes:
            h = (h << 8) | byte
        return h
    
    def _gcm_multiply(self, x: int, y: int) -> int:
        """GCM中的乘法運算"""
        result = 0
        for i in range(128):
            if x & (1 << (127 - i)):
                result ^= y
            if y & 1:
                y = (y >> 1) ^ (0xE1 << 120)
            else:
                y >>= 1
        return result
    
    def _ghash(self, h: int, additional_data: bytes, ciphertext: bytes) -> bytes:
        """GHASH函數"""
        # 填充數據到16字節邊界
        def pad_to_16(data):
            padding_len = (16 - len(data) % 16) % 16
            return data + b'\x00' * padding_len
        
        padded_ad = pad_to_16(additional_data) if additional_data else b''
        padded_ct = pad_to_16(ciphertext)
        
        # 長度塊
        len_block = struct.pack('>QQ', len(additional_data) * 8, len(ciphertext) * 8)
        
        # 組合所有數據
        all_data = padded_ad + padded_ct + len_block
        
        # GHASH計算
        y = 0
        for i in range(0, len(all_data), 16):
            block = all_data[i:i+16]
            block_int = int.from_bytes(block, 'big')
            y = self._gcm_multiply(y ^ block_int, h)
        
        return y.to_bytes(16, 'big')
    
    def _inc32(self, block: bytes) -> bytes:
        """32位計數器遞增"""
        block_int = int.from_bytes(block, 'big')
        # 只對最後32位遞增
        low_32 = (block_int & 0xffffffff) + 1
        high_96 = block_int & ~0xffffffff
        return (high_96 | (low_32 & 0xffffffff)).to_bytes(16, 'big')
    
    @staticmethod
    def generate_key(bit_length: int = 256) -> bytes:
        """生成AES密鑰"""
        if bit_length != 256:
            raise ValueError("僅支援256位密鑰")
        return secrets.token_bytes(32)
    
    def encrypt(self, nonce: bytes, plaintext: bytes, additional_data: bytes = None) -> bytes:
        """GCM加密
        
        Args:
            nonce: 12字節的隨機數
            plaintext: 要加密的明文
            additional_data: 附加認證數據（可選）
            
        Returns:
            密文 + 16字節認證標籤
        """
        if len(nonce) != 12:
            raise ValueError("nonce必須是12字節")
        
        if additional_data is None:
            additional_data = b''
        
        # 初始計數器：nonce + 32位計數器（從1開始）
        initial_counter = nonce + b'\x00\x00\x00\x01'
        
        # 加密明文（CTR模式）
        ciphertext = bytearray()
        counter = initial_counter
        
        for i in range(0, len(plaintext), 16):
            # 加密計數器
            keystream = self.aes.encrypt_block(counter)
            
            # 與明文異或
            block = plaintext[i:i+16]
            for j in range(len(block)):
                ciphertext.append(block[j] ^ keystream[j])
            
            # 遞增計數器
            counter = self._inc32(counter)
        
        # 計算認證標籤
        auth_tag_mask = self.aes.encrypt_block(nonce + b'\x00\x00\x00\x00')
        ghash_result = self._ghash(self.h, additional_data, bytes(ciphertext))
        
        # 標籤 = GHASH ⊕ 加密後的J0
        auth_tag = bytearray()
        for i in range(16):
            auth_tag.append(ghash_result[i] ^ auth_tag_mask[i])
        
        return bytes(ciphertext) + bytes(auth_tag)
    
    def decrypt(self, nonce: bytes, ciphertext_with_tag: bytes, additional_data: bytes = None) -> bytes:
        """GCM解密
        
        Args:
            nonce: 12字節的隨機數
            ciphertext_with_tag: 密文 + 16字節認證標籤
            additional_data: 附加認證數據（可選）
            
        Returns:
            解密後的明文
            
        Raises:
            ValueError: 認證失敗
        """
        if len(nonce) != 12:
            raise ValueError("nonce必須是12字節")
        
        if len(ciphertext_with_tag) < 16:
            raise ValueError("密文過短，缺少認證標籤")
        
        if additional_data is None:
            additional_data = b''
        
        # 分離密文和標籤
        ciphertext = ciphertext_with_tag[:-16]
        received_tag = ciphertext_with_tag[-16:]
        
        # 驗證認證標籤
        auth_tag_mask = self.aes.encrypt_block(nonce + b'\x00\x00\x00\x00')
        ghash_result = self._ghash(self.h, additional_data, ciphertext)
        
        expected_tag = bytearray()
        for i in range(16):
            expected_tag.append(ghash_result[i] ^ auth_tag_mask[i])
        
        # 恆定時間比較標籤
        tag_match = True
        for i in range(16):
            if received_tag[i] != expected_tag[i]:
                tag_match = False
        
        if not tag_match:
            raise ValueError("認證標籤驗證失敗")
        
        # 解密密文（CTR模式）
        plaintext = bytearray()
        counter = nonce + b'\x00\x00\x00\x01'
        
        for i in range(0, len(ciphertext), 16):
            # 加密計數器
            keystream = self.aes.encrypt_block(counter)
            
            # 與密文異或
            block = ciphertext[i:i+16]
            for j in range(len(block)):
                plaintext.append(block[j] ^ keystream[j])
            
            # 遞增計數器
            counter = self._inc32(counter)
        
        return bytes(plaintext)

# ============================
# RSA-2048 自定義實現
# ============================

class CustomRSA:
    """自定義RSA-2048實現"""
    
    def __init__(self, public_key: Tuple[int, int] = None, private_key: Tuple[int, int, int, int, int] = None):
        """初始化RSA
        
        Args:
            public_key: (n, e) 公鑰
            private_key: (n, e, d, p, q) 私鑰
        """
        self.public_key = public_key
        self.private_key = private_key
    
    @staticmethod
    def generate_key_pair(key_size: int = 2048) -> Tuple['CustomRSA', 'CustomRSA']:
        """生成RSA密鑰對
        
        Args:
            key_size: 密鑰位數，默認2048
            
        Returns:
            (private_key_obj, public_key_obj)
        """
        # 生成兩個大素數
        p = generate_prime(key_size // 2)
        q = generate_prime(key_size // 2)
        
        # 計算n和φ(n)
        n = p * q
        phi_n = (p - 1) * (q - 1)
        
        # 選擇公鑰指數e（通常是65537）
        e = 65537
        if gcd(e, phi_n) != 1:
            # 如果65537與φ(n)不互質，選擇其他值
            e = 3
            while gcd(e, phi_n) != 1:
                e += 2
        
        # 計算私鑰指數d
        d = mod_inverse(e, phi_n)
        
        # 創建私鑰和公鑰對象
        private_key = CustomRSA(
            public_key=(n, e),
            private_key=(n, e, d, p, q)
        )
        
        public_key = CustomRSA(public_key=(n, e))
        
        return private_key, public_key
    
    def _mgf1(self, seed: bytes, length: int, hash_func=hashlib.sha256) -> bytes:
        """MGF1遮罩生成函數"""
        t = b''
        counter = 0
        while len(t) < length:
            c = struct.pack('>I', counter)
            t += hash_func(seed + c).digest()
            counter += 1
        return t[:length]
    
    def _oaep_encode(self, message: bytes, label: bytes = b'') -> bytes:
        """OAEP編碼"""
        # 計算參數
        k = 256  # RSA-2048的字節長度
        hash_func = hashlib.sha256
        h_len = hash_func().digest_size
        
        # 檢查消息長度
        if len(message) > k - 2 * h_len - 2:
            raise ValueError("消息過長")
        
        # 計算lHash
        l_hash = hash_func(label).digest()
        
        # 構造DB = lHash || PS || 0x01 || M
        ps_len = k - len(message) - 2 * h_len - 2
        db = l_hash + b'\x00' * ps_len + b'\x01' + message
        
        # 生成隨機種子
        seed = secrets.token_bytes(h_len)
        
        # 生成遮罩
        db_mask = self._mgf1(seed, k - h_len - 1)
        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
        
        seed_mask = self._mgf1(masked_db, h_len)
        masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
        
        # 構造編碼消息
        em = b'\x00' + masked_seed + masked_db
        
        return em
    
    def _oaep_decode(self, encoded_message: bytes, label: bytes = b'') -> bytes:
        """OAEP解碼"""
        k = 256  # RSA-2048的字節長度
        hash_func = hashlib.sha256
        h_len = hash_func().digest_size
        
        # 檢查編碼消息長度
        if len(encoded_message) != k:
            raise ValueError("編碼消息長度錯誤")
        
        # 分離組件
        y = encoded_message[0]
        masked_seed = encoded_message[1:h_len+1]
        masked_db = encoded_message[h_len+1:]
        
        # 恢復種子和DB
        seed_mask = self._mgf1(masked_db, h_len)
        seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
        
        db_mask = self._mgf1(seed, k - h_len - 1)
        db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
        
        # 驗證並提取消息
        l_hash = hash_func(label).digest()
        l_hash_prime = db[:h_len]
        
        # 檢查lHash
        if l_hash != l_hash_prime:
            raise ValueError("OAEP解碼失敗：標籤不匹配")
        
        # 查找0x01分隔符
        separator_index = -1
        for i in range(h_len, len(db)):
            if db[i] == 0x01:
                separator_index = i
                break
            elif db[i] != 0x00:
                raise ValueError("OAEP解碼失敗：格式錯誤")
        
        if separator_index == -1:
            raise ValueError("OAEP解碼失敗：找不到分隔符")
        
        # 提取消息
        message = db[separator_index + 1:]
        
        return message
    
    def encrypt(self, message: bytes) -> bytes:
        """RSA公鑰加密（使用OAEP填充）
        
        Args:
            message: 要加密的消息
            
        Returns:
            加密後的密文
        """
        if not self.public_key:
            raise ValueError("缺少公鑰")
        
        n, e = self.public_key
        
        # OAEP編碼
        encoded_message = self._oaep_encode(message)
        
        # 轉換為整數
        m = int.from_bytes(encoded_message, 'big')
        
        # RSA加密：c = m^e mod n
        c = pow(m, e, n)
        
        # 轉換為字節（256字節）
        return c.to_bytes(256, 'big')
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """RSA私鑰解密（使用OAEP填充）
        
        Args:
            ciphertext: 要解密的密文
            
        Returns:
            解密後的明文
        """
        if not self.private_key:
            raise ValueError("缺少私鑰")
        
        n, e, d, p, q = self.private_key
        
        # 轉換為整數
        c = int.from_bytes(ciphertext, 'big')
        
        # RSA解密：m = c^d mod n（使用中國剩餘定理優化）
        # m1 = c^(d mod (p-1)) mod p
        # m2 = c^(d mod (q-1)) mod q
        dp = d % (p - 1)
        dq = d % (q - 1)
        
        m1 = pow(c, dp, p)
        m2 = pow(c, dq, q)
        
        # 合併結果
        q_inv = mod_inverse(q, p)
        h = (q_inv * (m1 - m2)) % p
        m = m2 + h * q
        
        # 轉換為字節
        encoded_message = m.to_bytes(256, 'big')
        
        # OAEP解碼
        message = self._oaep_decode(encoded_message)
        
        return message
    
    def to_pem(self) -> Tuple[bytes, bytes]:
        """將密鑰導出為PEM格式
        
        Returns:
            (private_key_pem, public_key_pem)
        """
        if not self.private_key:
            raise ValueError("缺少私鑰")
        
        n, e, d, p, q = self.private_key
        
        # 計算額外參數
        dp = d % (p - 1)
        dq = d % (q - 1)
        qi = mod_inverse(q, p)
        
        # 私鑰PEM（簡化版本，實際應該使用ASN.1編碼）
        private_key_data = f"""-----BEGIN CUSTOM RSA PRIVATE KEY-----
n={n}
e={e}
d={d}
p={p}
q={q}
dp={dp}
dq={dq}
qi={qi}
-----END CUSTOM RSA PRIVATE KEY-----"""
        
        # 公鑰PEM
        public_key_data = f"""-----BEGIN CUSTOM RSA PUBLIC KEY-----
n={n}
e={e}
-----END CUSTOM RSA PUBLIC KEY-----"""
        
        return private_key_data.encode(), public_key_data.encode()
    
    @staticmethod
    def from_pem(private_key_pem: bytes = None, public_key_pem: bytes = None) -> 'CustomRSA':
        """從PEM格式加載密鑰
        
        Args:
            private_key_pem: 私鑰PEM數據
            public_key_pem: 公鑰PEM數據
            
        Returns:
            CustomRSA對象
        """
        rsa_obj = CustomRSA()
        
        if private_key_pem:
            # 解析私鑰PEM（簡化版本）
            pem_str = private_key_pem.decode()
            lines = pem_str.strip().split('\n')
            
            params = {}
            for line in lines:
                if '=' in line:
                    key, value = line.split('=', 1)
                    params[key] = int(value)
            
            if all(k in params for k in ['n', 'e', 'd', 'p', 'q']):
                rsa_obj.private_key = (params['n'], params['e'], params['d'], params['p'], params['q'])
                rsa_obj.public_key = (params['n'], params['e'])
        
        elif public_key_pem:
            # 解析公鑰PEM（簡化版本）
            pem_str = public_key_pem.decode()
            lines = pem_str.strip().split('\n')
            
            params = {}
            for line in lines:
                if '=' in line:
                    key, value = line.split('=', 1)
                    params[key] = int(value)
            
            if all(k in params for k in ['n', 'e']):
                rsa_obj.public_key = (params['n'], params['e'])
        
        return rsa_obj 