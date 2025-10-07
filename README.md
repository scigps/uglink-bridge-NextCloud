# UGLINK Cloudflare Worker

这个 Cloudflare Worker 通过自动登录和处理认证来反向代理 uglink 服务。

## 功能特性

- 自动登录 uglink 获取会话令牌和代理 Cookie
- 将代理 Cookie 和目标域名缓存 1 小时
- 反向代理所有请求到目标服务，自动附加认证 Cookie

## 配置

1. **KV 命名空间**：在您的 Cloudflare 账户中创建一个 KV 命名空间并记录 ID。

2. **密钥**：
   - `PASSWORD`：登录绿联云的原始密码（Worker 会自动用 RSA 加密）
   - 使用以下命令设置原始密码：
     ```
     echo "your_raw_password_here" | wrangler secret put PASSWORD
     ```

3. **环境变量**（已在 wrangler.toml 中设置）：
   - `BASE_URL`：uglink API 的基础 URL
   - `PORT`：端口号
   - `USERNAME`：绿联云登录用户名

## 设置步骤

1. 安装 Wrangler：`npm install -g wrangler`

2. 登录 Cloudflare：`wrangler auth login`

3. 更新 `wrangler.toml`：
   - 将 `your_kv_namespace_id_here` 替换为您的实际 KV 命名空间 ID
   - 将 `your_preview_kv_namespace_id_here` 替换为您的实际预览 KV 命名空间 ID

4. 设置 PASSWORD 密钥：使用上述命令设置密码

5. 部署：`wrangler deploy`

## 使用方法

部署完成后，访问您的 Worker URL。它将自动处理登录、令牌获取和反向代理所有请求到目标服务。

## 查看日志

Worker 中的 `console.log` 输出可以在 Cloudflare Workers 控制台的 "Logs" 标签页中查看。日志包含详细的 API 调用状态信息，帮助监控和调试。