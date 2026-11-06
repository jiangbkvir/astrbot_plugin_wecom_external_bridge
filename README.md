# astrbot_plugin_wecom_external_bridge

在 AstrBot 插件进程内，把 macOS 企业微信外部客户群接入 AstrBot。  
目标群内明确 `@数字员工` 的文本消息会进入 AstrBot 默认 LLM / 人格 / 插件，并把纯文本回复通过企业微信原生接口发回原群。

这是非官方实现，不使用个人微信、不截屏、不模拟鼠标键盘、不抢企业微信前台。

配套工具仓库：[jiangbkvir/WeComExternalBridge](https://github.com/jiangbkvir/WeComExternalBridge)

## 运行链路

```text
外部客户群 @数字员工
  -> 企业微信 macOS 进程（WEWMessageService）
  -> 宿主机 frida-server（仅作 Docker→macOS 传输）
  -> 本插件（AstrBot 容器内）
       -> 白名单外部群过滤
       -> @ 目标校验 / 文本类型校验 / 自身消息过滤
       -> SQLite 事件和发送去重
       -> AstrBot 默认 LLM / 人格 / 插件
       -> 原生文本发送接口
  -> 回写同一外部客户群
```

不再启动 HTTP 桥接服务，不再监听 `8770`，不再使用长轮询。

## 特性

- 只附加企业微信 `com.tencent.WeWorkMac`，不操作个人微信。
- 支持外部客户群白名单，仅处理明确 `@数字员工` 的文本消息。
- 机器人自己发送的消息不会再次触发回复。
- 已发送文本回环抑制，避免“自言自语”。
- 事件、消息、发送请求均持久化去重。
- 纯文本回复按分段聚合后串行发送。
- 默认关闭发送，先监听验证再切换正式回复。

## 前提

- macOS 已安装并登录企业微信，账号可被拉入目标外部客户群。
- AstrBot 可访问宿主机 Frida 服务（Docker 使用 `host.docker.internal`）。
- 宿主机运行官方 `frida-server`，只做传输层，不承载业务。
- AstrBot 环境已安装 `frida==17.26.0`。

## 安装

1. 将本目录放入 AstrBot 插件目录：

```text
<AstrBot>/data/plugins/astrbot_plugin_wecom_external_bridge
```

2. 安装依赖：

```bash
pip install -r requirements.txt
```

3. 在 AstrBot 平台设置中启用 `wecom_external_bridge`，并填写下方配置。

## 配置

| 字段 | 说明 | 示例 |
|---|---|---|
| `frida_host` | 宿主机 Frida 地址 | `host.docker.internal` |
| `frida_port` | 宿主机 Frida 端口 | `27042` |
| `frida_token` | Frida 服务 Token | 随机字符串 |
| `process_name` | 企业微信进程名 | `企业微信` |
| `wecom_pid` | 固定进程 PID，留 `0` 自动查找 | `0` |
| `allowed_group_ids` | 外部客户群白名单 | `["R:..."]` |
| `bot_user_id` | 数字员工的企业微信用户 ID | `1688...` |
| `bot_display_name` | 群内显示名 | `数字员工` |
| `capture_only` | 只记录事件，不触发 LLM | `true` |
| `send_enabled` | 是否允许原生发送 | `false` |
| `require_outer_group` | 必须为外部客户群 | `true` |
| `require_mention_id_match` | 必须通过 user ID 匹配 @ | `true` |
| `poll_interval_seconds` | 轮询间隔 | `0.75` |
| `poll_message_count` | 每次拉取消息数 | `50` |

建议验收顺序：

1. `capture_only=true`，不发送，确认能收到目标群事件。
2. 验证不 `@`、图片、语音、自身消息均被过滤。
3. 确认群和账号无误后再打开 `capture_only=false` 和 `send_enabled=true`。

## 过滤规则

- 仅白名单外部客户群。
- 仅 `contentType==1` 的文本消息。
- 仅 `mention_ids` 包含 `bot_user_id` 的 @ 消息。
- 排除发送者等于 `bot_user_id` 的自身消息。
- 排除空文本、超长文本和已发送文本回声。
- 同一消息事件不会重复进入 AstrBot。

## 数据与日志

- SQLite 数据库位于 `data/plugin_data/astrbot_plugin_wecom_external_bridge/`。
- 日志不会打印 token 和聊天正文。
- 启动后周期性输出 `attached`、`poll_ms`、`accepted`、`filters` 等状态。

## 局限与风险

- 依赖企业微信客户端私有接口，企业微信升级后可能失效。
- 存在账号风控风险，建议使用公司授权的数字员工账号。
- 当前仅支持文本消息与单个/少量白名单外部群。
- 只支持 AstrBot 纯文本回复，不发送图片、语音和文件。

## License

[MIT](LICENSE)
