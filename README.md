# AiSafeguard Control Center

AI Agent 安全防護雷達控制台 — Python Flask 後端 + 即時 WebSocket UI

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![SocketIO](https://img.shields.io/badge/SocketIO-5.x-yellow)

## 快速開始

```bash
# 安裝依賴
pip install -r requirements.txt

# 啟動伺服器
python app.py
```

開啟瀏覽器訪問 `http://localhost:5000`

## 架構

```
aisafeguard-app/
├── app.py                    # Flask 主程式 + REST API + SocketIO
├── requirements.txt          # Python 依賴
├── templates/
│   └── index.html            # 完整 UI (HTML/CSS/JS + SocketIO client)
└── static/
    └── images/
        ├── aisafeguard-logo.png   # AiSafeguard Logo
        ├── asrock-logo.png        # ASRock Industrial Logo
        ├── exein-logo.png         # Exein Logo
        └── openclaw.png           # Open Claw 龍蝦
```

## REST API

| Method | Endpoint | 說明 |
|--------|----------|------|
| `GET` | `/api/state` | 取得目前狀態（stats, events, pending, chat） |
| `POST` | `/api/feed` | 提交新的 feed item |
| `POST` | `/api/prompt` | 送出使用者指令 |
| `POST` | `/api/review/<id>` | 批准或拒絕 pending item |
| `POST` | `/api/classify` | 分類指令（dry-run，不執行） |

### 範例

```bash
# 提交指令（自動分類威脅等級）
curl -X POST http://localhost:5000/api/prompt \
  -H "Content-Type: application/json" \
  -d '{"command": "rm -rf /"}'

# 提交 feed item（手動指定威脅等級）
curl -X POST http://localhost:5000/api/feed \
  -H "Content-Type: application/json" \
  -d '{"type": "blocked", "label": "DROP TABLE", "source": "External API", "source_type": "external"}'

# 分類指令（dry-run）
curl -X POST http://localhost:5000/api/classify \
  -H "Content-Type: application/json" \
  -d '{"command": "sudo apt install malware"}'

# 批准 pending item
curl -X POST http://localhost:5000/api/review/ITEM_UUID \
  -H "Content-Type: application/json" \
  -d '{"action": "approve"}'
```

## SocketIO 即時事件

### 從伺服器接收

| 事件名稱 | 說明 |
|----------|------|
| `init_state` | 連線時推送完整狀態 |
| `new_blip` | 新的雷達 blip（動畫觸發） |
| `stats_update` | 統計數據更新 |
| `new_event` | 新的事件日誌 |
| `net_flash` | 防護網閃爍 (outer/inner) |
| `eating_task` | Open Claw 吃任務動畫 |
| `pending_update` | Pending 佇列更新 |
| `chat_message` | 聊天訊息 |
| `review_complete` | 審查完成 |

### 發送至伺服器

| 事件名稱 | 說明 |
|----------|------|
| `manual_feed` | 手動投餵 `{type: "blocked"}` |
| `auto_feed_tick` | 自動投餵 tick |

## 後端整合

### 替換威脅分類引擎

在 `app.py` 中找到 `classify_threat()` 函數，替換為你的實際安全分析邏輯：

```python
def classify_threat(command: str) -> ThreatLevel:
    """
    替換此函數為你的安全分析引擎
    例如：LLM 分類、規則引擎、ML 模型
    """
    # 呼叫你的安全 API
    result = your_security_api.analyze(command)
    return ThreatLevel(result.level)
```

### 與 Open Claw Agent 整合

```python
# 在 app.py 中新增 endpoint
@app.route("/api/agent/action", methods=["POST"])
def agent_action():
    """Open Claw Agent 回報其行為"""
    data = request.get_json()
    action = data["action"]  # e.g. "subprocess.run('ls')"
    
    threat = classify_threat(action)
    item = FeedItem(
        type=threat.value,
        label=action[:30],
        source="Code Execution",
        source_type="internal",  # Agent 自身行為
        detail=f"Agent executed: {action}",
    ).to_dict()
    
    socketio.emit("new_blip", item)
    # ... 處理結果
    
    return jsonify({"allowed": threat in (ThreatLevel.TRUSTED, ThreatLevel.NORMAL)})
```

## 功能

- **雷達掃描動畫** — Canvas 繪製的即時掃描線
- **雙向防護** — 內部威脅從中心向外，外部威脅從邊緣向內
- **Open Claw 龍蝦** — 中心區漫遊、眨眼、吃任務動畫
- **即時監控面板** — Passed / Blocked / Pending 統計
- **使用者對話** — 聊天介面輸入指令，自動分類威脅等級
- **事件日誌** — 底部即時記錄所有事件
- **Pending 審查** — 側邊滑出面板，逐一批准/拒絕
- **WebSocket 即時更新** — 所有連線客戶端同步更新
