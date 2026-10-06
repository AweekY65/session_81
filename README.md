# 本地 MIME 邮件解析器（mime_parser）

一个纯本地、纯 Python 标准库实现的 `.eml`（RFC 5322 / MIME）解析器。
**不连接任何网络或外部服务**：没有 SMTP、IMAP、POP3、Gmail API 或任何
远程调用。所有邮件、附件、解析状态只存在于本地文件或内存中。

## 快速开始

```python
from mime_parser import MimeParser, save_attachments

msg = MimeParser().parse_file("sample.eml")   # 只读本地文件
print(msg.subject, msg.from_, msg.to, msg.date)
print(msg.text_body)                           # text/plain 正文
print(msg.html_body)                           # text/html 正文（如有）
paths = save_attachments(msg, "attachments/")  # 安全落盘
```

## 支持的 MIME 范围

- **Header**：`From`、`To`、`Subject`、`Date`、`Content-Type`、
  `Content-Disposition` 等常见 RFC 风格头部；支持 folded header
  （以空格/制表符续行的折叠头）。
- **Encoded-word**：RFC 2047 `=?charset?B?...?=` / `=?charset?Q?...?=`
  编码词解码，支持 UTF-8、GBK/GB2312、ISO-8859-1 等 Python 标准编解码器
  可识别的字符集；相邻编码词自动合并。无法解码时保留原文并继续。
- **Multipart**：`multipart/mixed`、`multipart/alternative`（及其他
  `multipart/*`）递归解析；`message/rfc822` 内嵌邮件按嵌套部件处理。
  自动识别文本正文（`text/plain` → `text_body`，`text/html` →
  `html_body`）与附件。
- **Content-Transfer-Encoding**：`7bit` / `8bit` / `binary` 直通；
  `base64` 与 `quoted-printable` 严格解码，可检测非法字符、错误填充、
  截断数据（长度非 4 的倍数、末尾悬空的 `=`、非法 `=XX` 转义）。
  默认将损坏内容记录到 `msg.warnings` 并保留原始数据；
  `MimeParser(strict=True)` 时直接抛出 `TransferEncodingError`。

## 安全限制

通过 `Limits` 配置，防止恶意邮件造成资源耗尽或无限递归：

| 限制 | 默认值 | 说明 |
| --- | --- | --- |
| `max_depth` | 20 | MIME 最大嵌套深度，超限抛 `LimitExceededError` |
| `max_attachments` | 100 | 单封邮件最大附件数 |
| `max_total_bytes` | 50 MiB | 全部解码后负载的总字节数上限 |
| `max_header_bytes` | 256 KiB | 单个头部块大小上限 |

```python
from mime_parser import Limits, MimeParser
parser = MimeParser(Limits(max_depth=10, max_attachments=20))
```

## 附件文件名策略

附件文件名来自不可信输入，保存前一律经过 `sanitize_filename` 处理：

- 同时按 `/` 和 `\` 切分，只保留最后一段，`../`、绝对路径
  （`/etc/passwd`、`C:\...`）等目录穿越尝试会被剥离；
- 去除控制字符与 `<>:"|?*` 等危险字符，去掉前导点（防 `..` 与隐藏文件）；
- 名称为空时回退为 `attachment-N`，长度截断到 255 字符；
- `save_attachments` 落盘前再次校验解析后的绝对路径必须位于输出目录内，
  否则抛出 `UnsafeFilenameError` 拒绝写入；重名附件自动追加序号。

## 运行测试

测试样本全部由代码生成，仅写入本地临时目录，不访问任何真实邮箱：

```bash
cd /mnt2/zjh/code/Goleta/session_81/a
python3 -m unittest discover -s tests -v
```

覆盖场景：纯文本邮件、multipart/alternative 多段正文、multipart/mixed
附件、UTF-8/GBK encoded-word Unicode 标题、折叠 header、附件文件名
路径穿越、非法与截断 Base64、非法 quoted-printable、嵌套深度限制、
附件数量限制、总解码大小限制、本地 `.eml` 文件解析与安全落盘。

## 目录结构

```
mime_parser/
  __init__.py    # 包导出
  errors.py      # 异常类型
  headers.py     # 头部展开、encoded-word、参数解析
  transfer.py    # Base64 / quoted-printable 严格解码
  security.py    # Limits 与文件名清洗
  parser.py      # 递归 MIME 解析核心
  storage.py     # 附件安全落盘
tests/
  test_parser.py # 自动化测试（样本由代码生成）
```
