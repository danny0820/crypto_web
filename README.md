# 資料加密/解密 Web 應用程序

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)](https://flask.palletsprojects.com/)
[![OpenCV](https://img.shields.io/badge/OpenCV-4.8.1-red.svg)](https://opencv.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

一個基於Flask的Web應用程序，提供安全的文件加密和解密功能，使用AES-GCM和RSA混合加密技術，並具備圖片、視頻預覽和加密視覺化功能。

## 🚀 功能特點

### 🔐 核心加密功能
- **混合加密技術**：AES-GCM（對稱加密）+ RSA（非對稱加密）
- **文件夾加密**：支持整個資料夾的批量加密
- **安全密鑰管理**：自動生成RSA密鑰對和AES密鑰
- **文件完整性**：GCM模式提供認證加密，確保數據完整性

### 🎬 媒體預覽功能
- **圖片預覽**：支持常見圖片格式的縮略圖預覽
- **視頻預覽**：自動生成視頻縮略圖，顯示視頻信息（時長、解析度、幀率）
- **加密視覺化**：將加密後的二進制文件轉換為視覺雜訊圖像
- **前後對比**：並排顯示加密前後的效果對比
- **解密預覽**：解密完成後可預覽還原的媒體文件

### 🎨 用戶體驗
- **響應式設計**：支持桌面和移動設備
- **實時進度**：顯示處理進度和狀態信息
- **拖拽上傳**：支持文件拖拽上傳
- **直觀界面**：現代化的用戶界面設計
- **統一媒體預覽**：圖片和視頻統一展示界面

## 🛠️ 技術架構

### 前端技術
- **HTML5 + CSS3**：現代Web標準
- **Bootstrap 5**：響應式UI框架
- **JavaScript ES6**：動態交互邏輯
- **Font Awesome**：圖標庫

### 後端技術
- **Flask**：輕量級Web框架
- **Cryptography**：現代加密庫
- **Pillow**：圖片處理庫
- **OpenCV**：視頻處理和縮略圖生成
- **imageio & imageio-ffmpeg**：視頻編解碼支持
- **NumPy**：數值計算庫

### 加密算法
- **AES-GCM**：256位密鑰，認證加密
- **RSA**：2048位密鑰，OAEP填充
- **SHA-256**：哈希算法

## 📋 系統要求

### 軟件要求
- Python 3.8 或更高版本
- pip 包管理器

### 硬件要求
- **內存**：最少 1GB，推薦 2GB+（處理視頻文件需要更多內存）
- **磁盤空間**：最少 200MB 用於臨時文件存儲
- **網絡**：運行時需要訪問CDN資源（Bootstrap、Font Awesome）

### 支持的文件格式
- **加密**：任意文件和資料夾
- **圖片預覽**：.jpg, .jpeg, .png, .gif, .bmp, .webp, .tiff, .svg
- **視頻預覽**：.mp4, .avi, .mov, .mkv, .webm, .flv, .wmv, .m4v, .3gp, .ogv, .ts, .mts, .m2ts

## 🚀 快速開始

### 1. 下載和安裝

```bash
# 克隆倉庫
git clone <repository-url>
cd 加解密

# 創建虛擬環境（推薦）
python -m venv venv

# 激活虛擬環境
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# 安裝依賴
pip install -r requirements.txt
```

### 2. 運行應用

```bash
# 啟動Web服務器
python crypto_web.py

# 或使用Flask命令
flask --app crypto_web run --host=0.0.0.0 --port=5000
```

### 3. 訪問應用

打開瀏覽器，訪問：`http://localhost:5000`

## 📖 使用指南

### 🔒 文件加密流程

1. **選擇文件**
   - 點擊「選擇文件」或「選擇資料夾」
   - 或直接拖拽文件到上傳區域

2. **媒體預覽**（可選）
   - 如果包含圖片或視頻文件，會自動顯示預覽選項
   - 點擊「顯示預覽」查看縮略圖和媒體信息
   - 視頻會顯示時長、解析度、幀率等詳細信息

3. **開始加密**
   - 點擊「開始加密」按鈕
   - 觀察實時進度條

4. **下載結果**
   - 加密完成後下載以下文件：
     - `folder_encrypted_[時間戳].bin`：加密後的數據
     - `aes_key_encrypted_[時間戳].bin`：加密的AES密鑰
     - `private_key.pem`：RSA私鑰（用於解密）
     - `public_key.pem`：RSA公鑰（用於驗證）

### 🔓 文件解密流程

1. **上傳文件**
   - 選擇加密檔案（`.bin`）
   - 選擇AES金鑰檔案（`.bin`）

2. **加密文件預覽**（可選）
   - 點擊「預覽加密視覺化」查看加密效果

3. **開始解密**
   - 點擊「開始解密」按鈕
   - 等待處理完成

4. **下載結果**
   - 下載解密後的ZIP文件
   - 如果包含圖片或視頻，會顯示解密前後對比

## 🔧 配置選項

### 環境變量
```bash
# Flask配置
FLASK_ENV=development          # 開發模式
FLASK_DEBUG=True              # 調試模式

# 應用配置
MAX_CONTENT_LENGTH=500MB      # 最大上傳文件大小
UPLOAD_FOLDER=uploads         # 上傳文件夾
PROCESSED_FOLDER=processed    # 處理結果文件夾
```

### 安全設置
- 修改 `app.secret_key` 為安全的隨機值
- 在生產環境中禁用調試模式
- 配置適當的文件權限

## 📁 項目結構

```
加解密/
├── crypto_web.py              # 主應用程序
├── requirements.txt           # 依賴清單
├── README.md                 # 系統說明文檔
├── processing_status.json    # 處理狀態文件
├── templates/
│   └── index.html            # 前端模板（包含CSS和JavaScript）
├── uploads/                  # 上傳臨時目錄
├── processed/               # 處理結果目錄
├── __pycache__/             # Python字節碼緩存
└── .git/                   # Git版本控制
```

## 🔍 安全考慮

### 加密強度
- **AES-256-GCM**：軍用級對稱加密算法
- **RSA-2048**：符合當前安全標準的非對稱加密
- **隨機密鑰**：每次加密都生成新的密鑰和隨機數

### 安全最佳實踐
- 私鑰文件應安全保存，丟失無法恢復數據
- 加密文件和密鑰文件應分別保存
- 定期清理臨時文件
- 在生產環境中使用HTTPS

## 🚀 生產部署

### 使用Gunicorn部署
```bash
# 安裝Gunicorn
pip install gunicorn

# 啟動生產服務器
gunicorn -w 4 -b 0.0.0.0:8000 crypto_web:app
```

### 使用Docker部署
```dockerfile
FROM python:3.9-slim

# 安裝系統依賴（OpenCV需要）
RUN apt-get update && apt-get install -y \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgomp1 \
    libglib2.0-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["python", "crypto_web.py"]
```

## 🛠️ 開發指南

### 開發依賴
```bash
pip install pytest pytest-flask flask-cors
```

### 運行測試
```bash
pytest tests/
```

### 代碼結構說明
- **加密模塊**：RSA和AES加密實現
- **文件處理**：ZIP壓縮和解壓縮
- **媒體處理**：圖片和視頻預覽功能
- **視頻處理**：使用OpenCV進行縮略圖生成和信息提取
- **Web接口**：Flask路由和API
- **前端交互**：JavaScript和CSS（內聯在HTML中）

## 🐛 問題排除

### 常見問題

**Q: 上傳大文件時出現錯誤**
A: 檢查 `MAX_CONTENT_LENGTH` 設置，並確保有足夠的磁盤空間

**Q: 圖片/視頻預覽不顯示**
A: 確保安裝了Pillow和OpenCV庫，並檢查媒體文件格式是否支持

**Q: 視頻縮略圖生成失敗**
A: 檢查視頻文件是否損壞，確保imageio-ffmpeg正常安裝

**Q: 解密失敗**
A: 確保使用正確的密鑰文件，並檢查文件是否損壞

**Q: 頁面載入緩慢**
A: 檢查網絡連接，確保可以訪問CDN資源

### 日誌查看
- 應用程序會在控制台輸出詳細的處理日誌
- 檢查 `processing_status.json` 文件了解處理狀態

## 📄 許可證

本項目採用 MIT 許可證 - 查看 [LICENSE](LICENSE) 文件了解詳情

## 🤝 貢獻

歡迎提交問題報告和功能請求！

1. Fork 本倉庫
2. 創建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 創建 Pull Request

## 📞 支持

如有問題或建議，請：
- 創建 GitHub Issue
- 發送郵件至：[your-email@example.com]

## 🔄 更新日誌

### v2.1.0 (最新)
- ✨ 新增視頻預覽功能
- ✨ 視頻縮略圖自動生成
- ✨ 視頻信息提取（時長、解析度、幀率）
- ✨ 統一媒體預覽界面（圖片+視頻）
- ✨ 視頻加密前後對比功能
- 🔧 優化色彩轉換（BGR到RGB）
- 🔧 更新依賴項（添加OpenCV、imageio等）

### v2.0.0
- ✨ 新增圖片預覽功能
- ✨ 新增加密視覺化功能
- ✨ 新增解密前後對比
- ✨ 響應式設計優化
- 🐛 修復下載功能問題
- 🔧 簡化解密文件下載流程

### v1.0.0
- 🎉 初始版本發布
- 🔐 基本加密/解密功能
- 🌐 Web用戶界面
- 📁 文件夾支持

---

**⚠️ 重要提醒：請務必妥善保管私鑰文件，丟失私鑰將無法恢復加密數據！** 