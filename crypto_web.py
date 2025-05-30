"""
資料夾加密/解密 Web 應用程序
=============================

這是一個基於Flask的Web應用程序，提供文件夾加密和解密功能。
使用混合加密技術：
- AES-GCM：用於實際數據加密（對稱加密，速度快）
- RSA：用於保護AES密鑰（非對稱加密，安全性高）

主要功能：
1. 文件夾/文件上傳和加密
2. 加密文件的解密和還原
3. 實時處理進度顯示
4. 文件下載功能

技術架構：
- 前端：HTML + Bootstrap + JavaScript
- 後端：Flask + Python
- 加密庫：cryptography
- 多線程處理：避免阻塞用戶界面
"""

import os
import sys
import zipfile  # 用於壓縮和解壓縮文件
import secrets  # 用於生成安全的隨機數據
import shutil   # 用於文件夾操作
import json     # 用於狀態持久化
from datetime import datetime
from flask import Flask, request, render_template, send_file, jsonify, flash, redirect, url_for
from werkzeug.utils import secure_filename  # 用於安全化文件名
import tempfile  # 用於創建臨時文件
import threading  # 用於後台處理
import time

# 加密相關庫
from cryptography.hazmat.primitives.asymmetric import rsa, padding  # RSA加密
from cryptography.hazmat.primitives import serialization, hashes     # 密鑰序列化和哈希
from cryptography.hazmat.primitives.ciphers.aead import AESGCM      # AES-GCM加密

# ============================
# Flask 應用程序配置
# ============================

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # 用於Flask會話加密，實際部署時請更改為更安全的密鑰

# 文件上傳配置
UPLOAD_FOLDER = 'uploads'      # 臨時文件存儲目錄
PROCESSED_FOLDER = 'processed' # 處理結果存儲目錄
ALLOWED_EXTENSIONS = {'zip', 'bin'}  # 允許上傳的文件類型

# 創建必要的目錄
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(PROCESSED_FOLDER):
    os.makedirs(PROCESSED_FOLDER)

# Flask配置
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PROCESSED_FOLDER'] = PROCESSED_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB 上傳限制

# ============================
# 狀態管理系統
# ============================

STATUS_FILE = 'processing_status.json'  # 狀態持久化文件

def load_status():
    """
    從文件載入處理狀態
    
    這個函數用於在應用程序重啟後恢復之前的處理狀態，
    確保用戶可以看到正確的進度信息。
    
    Returns:
        dict: 包含處理狀態的字典
    """
    try:
        if os.path.exists(STATUS_FILE):
            with open(STATUS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        print(f"載入狀態失敗: {e}")
    
    # 返回默認狀態
    return {
        'is_processing': False,    # 是否正在處理
        'status_message': '',      # 當前狀態消息
        'progress': 0,             # 處理進度 (0-100)
        'result_files': []         # 結果文件列表
    }

def save_status(status):
    """
    保存狀態到文件
    
    Args:
        status (dict): 要保存的狀態字典
    """
    try:
        with open(STATUS_FILE, 'w', encoding='utf-8') as f:
            json.dump(status, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"保存狀態失敗: {e}")

# 初始化全局狀態變量
processing_status = load_status()

# ============================
# 工具函數
# ============================

def allowed_file(filename):
    """
    檢查文件是否為允許的類型
    
    Args:
        filename (str): 文件名
        
    Returns:
        bool: 是否允許上傳
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def zip_folder_from_files(files, output_zip):
    """
    從上傳的文件列表創建ZIP檔案
    
    這個函數處理從網頁上傳的文件，保持原有的資料夾結構，
    並將所有文件打包成一個ZIP檔案。
    
    Args:
        files: Flask上傳的文件列表
        output_zip (str): 輸出ZIP文件路徑
    """
    with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file in files:
            if file.filename:
                # 使用webkitRelativePath來保持資料夾結構，如果沒有則使用filename
                file_path = getattr(file, 'filename', file.filename)
                
                # 檢查是否有相對路徑（資料夾上傳）
                if hasattr(file, 'headers') and 'content-disposition' in file.headers:
                    # 嘗試從headers獲取完整路徑
                    content_disp = file.headers['content-disposition']
                    if 'filename=' in content_disp:
                        # 提取文件名
                        import re
                        match = re.search(r'filename="([^"]*)"', content_disp)
                        if match:
                            file_path = match.group(1)
                
                # 安全化文件名但保持路徑結構
                if '/' in file_path or '\\' in file_path:
                    # 處理路徑中的每個部分
                    path_parts = file_path.replace('\\', '/').split('/')
                    safe_path_parts = [secure_filename(part) for part in path_parts if part]
                    safe_path = '/'.join(safe_path_parts)
                else:
                    safe_path = secure_filename(file_path)
                
                try:
                    # 檢查文件是否已關閉
                    if hasattr(file, 'closed') and file.closed:
                        print(f"警告：文件 {safe_path} 已經關閉，跳過")
                        continue
                        
                    # 嘗試重置文件指針到開頭（如果文件還開著）
                    if hasattr(file, 'seek'):
                        file.seek(0)
                    
                    # 讀取文件內容
                    file_content = file.read()
                    
                    # 確保有內容才寫入
                    if file_content:
                        zipf.writestr(safe_path, file_content)
                    else:
                        print(f"警告：文件 {safe_path} 內容為空")
                        
                except (ValueError, OSError) as e:
                    # 如果文件操作失敗，嘗試另一種方法
                    print(f"文件 {safe_path} 讀取失敗: {e}")
                    continue

def zip_folder(folder_path, output_zip):
    """
    壓縮本地資料夾
    
    這個函數用於壓縮已經保存到本地的文件夾，
    比zip_folder_from_files更簡單可靠。
    
    Args:
        folder_path (str): 要壓縮的資料夾路徑
        output_zip (str): 輸出ZIP文件路徑
    """
    with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                full_path = os.path.join(root, file)                    # 文件的完整路徑
                relative_path = os.path.relpath(full_path, folder_path) # 相對於根目錄的路徑
                zipf.write(full_path, relative_path)

# ============================
# 加密相關函數
# ============================

def generate_rsa_keys():
    """
    生成RSA金鑰對
    
    RSA用於保護AES密鑰，這是混合加密的重要組成部分。
    私鑰用於解密，公鑰用於加密。
    
    Returns:
        tuple: (private_key, public_key) RSA私鑰和公鑰對象
    """
    # 生成2048位RSA密鑰對
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # 將密鑰保存到文件以供下載
    private_key_path = os.path.join(app.config['PROCESSED_FOLDER'], 'private_key.pem')
    public_key_path = os.path.join(app.config['PROCESSED_FOLDER'], 'public_key.pem')
    
    # 保存私鑰（PEM格式，無密碼保護）
    with open(private_key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    
    # 保存公鑰（PEM格式）
    with open(public_key_path, 'wb') as f:
        f.write(public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
    
    return private_key, public_key

def rsa_encrypt(public_key, data: bytes) -> bytes:
    """
    RSA加密
    
    使用RSA公鑰加密數據。主要用於加密AES密鑰。
    
    Args:
        public_key: RSA公鑰對象
        data (bytes): 要加密的數據
        
    Returns:
        bytes: 加密後的數據
    """
    return public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def rsa_decrypt(private_key, data: bytes) -> bytes:
    """
    RSA解密
    
    使用RSA私鑰解密數據。主要用於解密AES密鑰。
    
    Args:
        private_key: RSA私鑰對象
        data (bytes): 要解密的數據
        
    Returns:
        bytes: 解密後的數據
    """
    return private_key.decrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def unzip_folder(zip_path, extract_to):
    """
    解壓縮ZIP文件
    
    Args:
        zip_path (str): ZIP文件路徑
        extract_to (str): 解壓縮目標目錄
    """
    with zipfile.ZipFile(zip_path, 'r') as zipf:
        zipf.extractall(extract_to)

def update_status(message, progress=None):
    """
    更新處理狀態
    
    這個函數用於更新處理進度和狀態消息，
    同時將狀態保存到文件以確保持久化。
    
    Args:
        message (str): 狀態消息
        progress (int, optional): 進度百分比 (0-100)
    """
    global processing_status
    processing_status['status_message'] = message
    if progress is not None:
        processing_status['progress'] = progress
    save_status(processing_status)  # 保存狀態到文件
    print(f"[{datetime.now()}] {message}")

# ============================
# 核心處理函數
# ============================

def encrypt_files_process(file_data_list):
    """
    文件加密處理的核心函數
    
    這個函數在後台線程中運行，執行完整的加密流程：
    1. 保存上傳的文件到臨時目錄
    2. 壓縮文件為ZIP
    3. 生成RSA密鑰對
    4. 生成AES密鑰
    5. 用AES加密ZIP文件
    6. 用RSA加密AES密鑰
    7. 清理臨時文件
    
    Args:
        file_data_list (list): 包含文件數據的列表，每個元素是字典格式：
                              {'filename': 文件名, 'content': 文件內容, 'size': 文件大小}
    """
    global processing_status
    temp_files = []  # 追踪臨時文件以便清理
    
    try:
        # 設置處理狀態為進行中
        processing_status['is_processing'] = True
        processing_status['result_files'] = []
        save_status(processing_status)  # 保存狀態
        
        # 生成時間戳作為文件名的一部分，避免文件名衝突
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # 定義各種文件路徑
        temp_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'temp_{timestamp}')           # 臨時文件夾
        zip_name = os.path.join(app.config['PROCESSED_FOLDER'], f'folder_{timestamp}.zip')     # 臨時ZIP文件
        encrypted_file = os.path.join(app.config['PROCESSED_FOLDER'], f'folder_encrypted_{timestamp}.bin')      # 加密後的數據文件
        encrypted_key_file = os.path.join(app.config['PROCESSED_FOLDER'], f'aes_key_encrypted_{timestamp}.bin') # 加密後的AES密鑰文件

        # 步驟1：創建臨時資料夾並保存文件
        os.makedirs(temp_folder, exist_ok=True)
        print(f"創建臨時資料夾: {temp_folder}")
        
        update_status("🔄 正在處理上傳的文件...", 5)
        
        # 將所有文件保存到臨時資料夾
        saved_count = 0
        total_size = 0
        
        for i, file_data in enumerate(file_data_list):
            try:
                # 從文件數據中提取信息
                filename = file_data['filename']
                content = file_data['content']
                file_size = file_data['size']
                
                print(f"處理文件 {i+1}: {filename} ({file_size} bytes)")
                
                # 處理文件路徑，確保安全性
                if '/' in filename or '\\' in filename:
                    # 如果是資料夾結構，處理每個路徑部分
                    path_parts = filename.replace('\\', '/').split('/')
                    safe_path_parts = [secure_filename(part) for part in path_parts if part]
                    relative_path = '/'.join(safe_path_parts)
                else:
                    # 單個文件，直接安全化
                    relative_path = secure_filename(filename)
                
                # 生成完整的臨時文件路徑
                temp_file_path = os.path.join(temp_folder, relative_path)
                print(f"保存到: {temp_file_path}")
                
                # 創建必要的子資料夾
                temp_file_dir = os.path.dirname(temp_file_path)
                if temp_file_dir and temp_file_dir != temp_folder:
                    os.makedirs(temp_file_dir, exist_ok=True)
                    print(f"創建子資料夾: {temp_file_dir}")
                
                # 將文件內容寫入到磁盤
                with open(temp_file_path, 'wb') as f:
                    f.write(content)
                
                # 驗證文件是否成功保存
                if os.path.exists(temp_file_path):
                    actual_size = os.path.getsize(temp_file_path)
                    temp_files.append(temp_file_path)
                    saved_count += 1
                    total_size += actual_size
                    print(f"✅ 文件保存成功: {relative_path} ({actual_size} bytes)")
                    
                    # 驗證內容完整性
                    if actual_size != file_size:
                        print(f"⚠️ 文件大小不匹配: 預期 {file_size}, 實際 {actual_size}")
                else:
                    print(f"❌ 文件保存失敗: {relative_path}")
                
                # 更新進度（5-10%用於文件保存）
                progress = 5 + (i + 1) * 5 / len(file_data_list)
                update_status(f"📁 已處理 {i+1}/{len(file_data_list)} 個文件", min(progress, 10))
                
            except Exception as e:
                print(f"❌ 保存文件 {file_data.get('filename', 'unknown')} 失敗: {e}")
                import traceback
                traceback.print_exc()
                continue
        
        # 檢查是否有文件成功保存
        update_status(f"✅ 已保存 {saved_count} 個文件 (總大小: {total_size} bytes)", 15)
        
        # 顯示臨時資料夾的內容結構
        print(f"臨時資料夾內容:")
        for root, dirs, files_in_dir in os.walk(temp_folder):
            level = root.replace(temp_folder, '').count(os.sep)
            indent = ' ' * 2 * level
            print(f"{indent}{os.path.basename(root)}/")
            subindent = ' ' * 2 * (level + 1)
            for file in files_in_dir:
                file_path = os.path.join(root, file)
                file_size = os.path.getsize(file_path)
                print(f"{subindent}{file} ({file_size} bytes)")
        
        if saved_count == 0:
            raise Exception("沒有成功保存任何文件")
        
        # 步驟2：壓縮文件
        update_status(f"📦 正在壓縮 {saved_count} 個文件...", 20)
        zip_folder(temp_folder, zip_name)
        
        # 驗證ZIP文件是否創建成功
        if not os.path.exists(zip_name):
            raise Exception("壓縮文件創建失敗")
        
        zip_size = os.path.getsize(zip_name)
        update_status(f"✅ 壓縮完成 (ZIP文件: {zip_size} bytes)", 30)
        print(f"ZIP文件創建成功: {zip_name} ({zip_size} bytes)")

        # 步驟3：生成RSA金鑰對
        update_status("🔑 正在產生RSA金鑰...", 40)
        private_key, public_key = generate_rsa_keys()
        print("RSA金鑰對生成完成")

        # 步驟4：生成AES金鑰和隨機數
        update_status("🔐 正在產生AES金鑰...", 50)
        aes_key = AESGCM.generate_key(bit_length=256)  # 生成256位AES密鑰
        aesgcm = AESGCM(aes_key)                       # 創建AES-GCM加密對象
        nonce = secrets.token_bytes(12)                # 生成12字節的隨機數（nonce）
        print("AES金鑰生成完成")

        # 步驟5：讀取ZIP文件準備加密
        update_status("📖 讀取壓縮檔進行加密...", 60)
        with open(zip_name, 'rb') as f:
            plaintext = f.read()
        
        if len(plaintext) == 0:
            raise Exception("壓縮文件為空")
        
        update_status(f"📊 讀取了 {len(plaintext)} bytes 的數據", 65)
        print(f"讀取壓縮文件: {len(plaintext)} bytes")

        # 步驟6：使用AES-GCM加密ZIP文件
        update_status("🔒 用AES-GCM加密壓縮檔...", 70)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        print(f"AES加密完成: {len(ciphertext)} bytes")

        # 步驟7：保存加密後的文件（nonce + 密文）
        update_status("💾 儲存加密後的檔案...", 80)
        with open(encrypted_file, 'wb') as f:
            f.write(nonce + ciphertext)  # nonce在前，密文在後
        print(f"加密文件保存: {encrypted_file}")

        # 步驟8：使用RSA加密AES密鑰
        update_status("🔑 用RSA公鑰加密AES金鑰...", 90)
        encrypted_key = rsa_encrypt(public_key, aes_key)
        with open(encrypted_key_file, 'wb') as f:
            f.write(encrypted_key)
        print(f"AES金鑰加密保存: {encrypted_key_file}")

        # 步驟9：設置結果文件列表供下載
        processing_status['result_files'] = [
            {'name': f'folder_encrypted_{timestamp}.bin', 'path': encrypted_file, 'type': 'encrypted'},
            {'name': f'aes_key_encrypted_{timestamp}.bin', 'path': encrypted_key_file, 'type': 'key'},
            {'name': 'private_key.pem', 'path': os.path.join(app.config['PROCESSED_FOLDER'], 'private_key.pem'), 'type': 'private_key'},
            {'name': 'public_key.pem', 'path': os.path.join(app.config['PROCESSED_FOLDER'], 'public_key.pem'), 'type': 'public_key'}
        ]
        save_status(processing_status)  # 保存狀態

        update_status("🎉 加密完成！所有文件已準備下載", 100)
        print("✅ 加密過程完全完成!")
        
    except Exception as e:
        # 處理任何錯誤
        import traceback
        error_details = traceback.format_exc()
        print(f"❌ 加密錯誤詳情: {error_details}")
        update_status(f"❌ 加密過程發生錯誤：{str(e)}", 0)
    finally:
        # 清理臨時文件和資料夾
        try:
            if 'zip_name' in locals() and os.path.exists(zip_name):
                os.remove(zip_name)
                print(f"清理臨時ZIP文件: {zip_name}")
            if 'temp_folder' in locals() and os.path.exists(temp_folder):
                shutil.rmtree(temp_folder)
                print(f"清理臨時資料夾: {temp_folder}")
        except Exception as e:
            print(f"清理臨時文件失敗: {e}")
            
        # 標記處理完成
        processing_status['is_processing'] = False
        save_status(processing_status)  # 保存狀態

def decrypt_files_process(encrypted_file_path, key_file_path):
    """
    文件解密處理的核心函數
    
    這個函數執行完整的解密流程：
    1. 載入RSA私鑰
    2. 解密AES密鑰
    3. 解密數據文件
    4. 還原ZIP文件
    5. 解壓縮到目標目錄
    
    Args:
        encrypted_file_path (str): 加密文件的路徑
        key_file_path (str): 加密密鑰文件的路徑
    """
    global processing_status
    try:
        # 設置處理狀態
        processing_status['is_processing'] = True
        processing_status['result_files'] = []
        save_status(processing_status)  # 保存狀態
        
        # 生成時間戳用於輸出文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        decrypted_zip = os.path.join(app.config['PROCESSED_FOLDER'], f'decrypted_folder_{timestamp}.zip')
        output_folder = os.path.join(app.config['PROCESSED_FOLDER'], f'decrypted_{timestamp}')

        # 步驟1：讀取RSA私鑰
        update_status("讀取RSA私鑰...", 10)
        private_key_path = os.path.join(app.config['PROCESSED_FOLDER'], 'private_key.pem')
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        # 步驟2：讀取加密的AES密鑰
        update_status("讀取加密後的AES金鑰...", 20)
        with open(key_file_path, 'rb') as f:
            encrypted_key = f.read()

        # 步驟3：使用RSA私鑰解密AES密鑰
        update_status("用RSA私鑰解密AES金鑰...", 30)
        aes_key = rsa_decrypt(private_key, encrypted_key)

        # 步驟4：讀取加密的數據文件
        update_status("讀取加密檔案...", 40)
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()

        # 分離nonce和密文（前12字節是nonce，其餘是密文）
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        # 創建AES-GCM解密對象
        aesgcm = AESGCM(aes_key)

        # 步驟5：使用AES-GCM解密數據
        update_status("用AES-GCM解密資料...", 60)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        # 步驟6：寫入解密後的ZIP文件
        update_status("寫入解密後的zip檔案...", 80)
        with open(decrypted_zip, 'wb') as f:
            f.write(plaintext)

        # 步驟7：解壓縮ZIP文件到目標目錄
        update_status("解壓縮還原資料夾...", 90)
        os.makedirs(output_folder, exist_ok=True)
        unzip_folder(decrypted_zip, output_folder)

        # 設置結果文件列表
        processing_status['result_files'] = [
            {'name': f'decrypted_folder_{timestamp}.zip', 'path': decrypted_zip, 'type': 'decrypted_zip'},
            {'name': f'decrypted_folder_{timestamp}', 'path': output_folder, 'type': 'decrypted_folder'}
        ]
        save_status(processing_status)  # 保存狀態

        update_status("解密與還原完成！", 100)
        
    except Exception as e:
        # 處理解密過程中的錯誤
        update_status(f"解密過程發生錯誤：{str(e)}", 0)
    finally:
        # 標記處理完成
        processing_status['is_processing'] = False
        save_status(processing_status)  # 保存狀態

# ============================
# Flask 路由定義
# ============================

@app.route('/')
def index():
    """
    主頁路由
    渲染主要的用戶界面
    """
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_files():
    """
    文件加密路由
    
    處理文件上傳請求，立即讀取所有文件內容到內存，
    然後啟動後台線程進行加密處理。
    """
    # 檢查是否有文件上傳
    if 'files' not in request.files:
        flash('沒有選擇文件')
        return redirect(request.url)
    
    files = request.files.getlist('files')
    
    if not files or all(file.filename == '' for file in files):
        flash('沒有選擇文件')
        return redirect(url_for('index'))
    
    # 立即在主線程中讀取所有文件內容
    # 這樣可以避免在後台線程中使用已失效的FileStorage對象
    file_data_list = []
    
    for file in files:
        if file.filename:
            try:
                print(f"正在讀取文件: {file.filename}")
                
                # 重置文件指針並讀取內容
                file.seek(0)
                content = file.read()
                
                # 創建文件數據字典
                file_data = {
                    'filename': file.filename,
                    'content': content,
                    'size': len(content)
                }
                
                file_data_list.append(file_data)
                print(f"✅ 已讀取: {file.filename} ({len(content)} bytes)")
                
            except Exception as e:
                print(f"❌ 讀取文件失敗 {file.filename}: {e}")
                continue
    
    if not file_data_list:
        flash('沒有成功讀取任何文件')
        return redirect(url_for('index'))
    
    print(f"總共讀取了 {len(file_data_list)} 個文件")
    
    # 在新線程中處理加密，傳遞文件數據而不是FileStorage對象
    threading.Thread(target=encrypt_files_process, args=(file_data_list,), daemon=True).start()
    
    return jsonify({'status': 'started', 'message': '開始加密處理...'})

@app.route('/decrypt', methods=['POST'])
def decrypt_files():
    """
    文件解密路由
    
    處理解密請求，需要上傳加密文件和密鑰文件。
    """
    # 檢查必要的文件是否都已上傳
    if 'encrypted_file' not in request.files or 'key_file' not in request.files:
        flash('請選擇加密檔案和金鑰檔案')
        return redirect(url_for('index'))
    
    encrypted_file = request.files['encrypted_file']
    key_file = request.files['key_file']
    
    if encrypted_file.filename == '' or key_file.filename == '':
        flash('請選擇加密檔案和金鑰檔案')
        return redirect(url_for('index'))
    
    # 保存上傳的文件到臨時目錄
    encrypted_filename = secure_filename(encrypted_file.filename)
    key_filename = secure_filename(key_file.filename)
    
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
    key_path = os.path.join(app.config['UPLOAD_FOLDER'], key_filename)
    
    encrypted_file.save(encrypted_path)
    key_file.save(key_path)
    
    # 在新線程中處理解密
    threading.Thread(target=decrypt_files_process, args=(encrypted_path, key_path), daemon=True).start()
    
    return jsonify({'status': 'started', 'message': '開始解密處理...'})

@app.route('/status')
def get_status():
    """
    狀態查詢路由
    
    返回當前處理狀態的JSON數據，供前端JavaScript輪詢使用。
    """
    return jsonify(processing_status)

@app.route('/download/<filename>')
def download_file(filename):
    """
    文件下載路由
    
    Args:
        filename (str): 要下載的文件名
    """
    file_path = os.path.join(app.config['PROCESSED_FOLDER'], filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return "文件不存在", 404

@app.route('/clear')
def clear_files():
    """
    清理文件路由
    
    清理所有上傳和處理過的文件，重置狀態。
    """
    try:
        # 清理上傳文件夾
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.isfile(file_path):
                os.remove(file_path)
        
        # 清理處理文件夾
        for filename in os.listdir(app.config['PROCESSED_FOLDER']):
            file_path = os.path.join(app.config['PROCESSED_FOLDER'], filename)
            if os.path.isfile(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
                
        # 重置狀態
        global processing_status
        processing_status = load_status()
        
        flash('所有文件已清理')
    except Exception as e:
        flash(f'清理文件時發生錯誤：{str(e)}')
    
    return redirect(url_for('index'))

# ============================
# 應用程序啟動
# ============================

if __name__ == '__main__':
    # 啟動Flask開發伺服器
    # debug=True: 啟用調試模式，顯示詳細錯誤信息
    # host='0.0.0.0': 允許所有IP訪問
    # port=5000: 使用5000端口
    # use_reloader=False: 禁用自動重載，避免狀態丟失
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False) 