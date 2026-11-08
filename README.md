# bkcrack-py

`bkcrack-py` 是 [bkcrack](https://github.com/kimci86/bkcrack) 的**纯 Python 重实现**，
复刻其在 ZIP 传统加密（ZipCrypto）上执行 Biham–Kocher 已知明文攻击的全部功能。

- 与上游 C++ 版本 **1.8.1**（2025-10-25）逐行对齐：算法、边界处理、错误文案、退出码一致。
- **零运行时依赖**；可选安装 `numpy` 获得向量化加速（无 numpy 时自动回退到纯 Python 路径）。
- 既可作为命令使用（`bkcrack ...` 或 `python -m bkcrack ...`），也可作为库导入。
- 已通过 **37 项与官方二进制的交叉验证** 和 **183 项测试**。

---

## 安装

```bash
# 从仓库安装（可编辑模式）
python -m pip install -e .

# 带向量化加速
python -m pip install -e ".[fast]"

# 带测试依赖
python -m pip install -e ".[test]"
```

安装后即可使用 `bkcrack` 命令：

```bash
bkcrack --version
python -m bkcrack --version
```

要求 Python >= 3.9。

---

## 用法

命令行的每一个选项都与原版一致，包括 `-h` 帮助文本。完整帮助见 `bkcrack -h`。

### 1. 列出 ZIP 条目

```bash
bkcrack -L archive.zip
```

输出与官方实现逐字节相同：条目序号、压缩方式、加密方式、CRC-32、压缩前后大小、文件名。

### 2. 已知明文攻击

需要至少 12 字节已知明文，其中至少 8 字节在密文中连续，并且知道它们对应的密文：

```bash
bkcrack -C encrypted.zip -c cipher.bin -p plain.bin
bkcrack -C encrypted.zip -c doc.txt -p plain.txt -o 12 -x 0 504b0304
```

- `-p` 给出已知明文文件；`-x offset hexdata` 可再追加不连续的额外明文（可重复使用），
  `-o` 指定明文在（解密后）条目中的偏移。
- 已知明文可以来自 STORED 条目里的可预测文件头，也可以来自同格式文档的固定片段。
- 攻击成功后输出内部密钥：

```
Keys: c4490e28 b414a23d 91404b31
```

### 3. 使用密钥

```bash
# 解密单个条目
bkcrack -C encrypted.zip -c secret.txt -k c4490e28 b414a23d 91404b31 -d secret.txt

# 保留加密头（12 字节）一起解密
bkcrack -C encrypted.zip -c secret.txt -k ... -d secret.enc --keep-header

# 整包去密码，生成无保护的副本
bkcrack -C encrypted.zip -k ... -D decrypted.zip

# 整包改密码
bkcrack -C encrypted.zip -k ... -U new.zip newpassword

# 整包改成指定的内部密钥
bkcrack -C encrypted.zip -k ... --change-keys copy.zip 0a0b0c0d 0e0f1011 12131415
```

### 4. 恢复密码

已知密钥后，可以尝试恢复原始密码：

```bash
# 暴力搜索（字符集用 ?l ?u ?d ?a ?p ?s ?b 等表示）
bkcrack -k c4490e28 b414a23d 91404b31 -b ?l?l?l?l?l?l?l?l

# 限定长度区间 + 掩码
bkcrack -k ... -l 8..12 -m ?u?l?l?l?l-?d?d?d?d
```

`-b`、`-l`、`-m`、`-r`、`-j`、`-s`、`-e` 的语义与参数语法完全沿用原版，参见 `-h`。

### 5. 中断与续跑

```bash
bkcrack ... --continue-attack 183750     # 从攻击的指定候选位置继续
bkcrack ... --continue-recovery "pass"   # 从密码恢复的指定前缀继续
```

---

## 作为库使用

```python
from bkcrack import Data, Zreduction, attack
from bkcrack.console_progress import ConsoleProgress

ciphertext = open("entry.bin", "rb").read()   # 含 12 字节加密头
plaintext = b'<?xml version="1.0" '           # 至少 12 字节

data = Data(ciphertext, plaintext=plaintext)  # 归一化偏移、检查字节、额外明文

zr = Zreduction(data.keystream)
with ConsoleProgress() as progress:           # 进度条，可换成自定实现
    zr.reduce(progress)                       # 逐字节反向归约 Zi[10,32)
zr.generate()                                 # 扩展成 Zi[2,32)

with ConsoleProgress() as progress:
    solutions, restart = attack(
        data, zr.candidates, 0, zr.index, jobs=4, progress=progress
    )

for keys in solutions:
    print(keys)                               # Keys: c4490e28 b414a23d 91404b31
```

`attack()` 返回 `(solutions, restart)`；`restart` 即 `--continue-attack` 可用的续跑位置。

常用模块：

| 模块 | 职责 |
| --- | --- |
| `bkcrack.constants` | 全局常量（乘法常量、初始状态、块大小等） |
| `bkcrack.tables` | CRC32 正反查表、KeystreamTab、MultTab、`mask` / `maxdiff` 等位工具 |
| `bkcrack.keys` | 三字状态 `Keys(X, Y, Z)`，含前向/后向更新与密码派生 |
| `bkcrack.data` | 已知明文 / 密文归一化与额外明文校验 |
| `bkcrack.zreduction` | `Zi[10,32)` 的生成与归约 |
| `bkcrack.attack` | Biham–Kocher 攻击本体（`exploreZlists` → `exploreYlists` → `testXlist`） |
| `bkcrack.password` | `SixCharactersRecovery` / `BruteforceRecovery` / `MaskRecovery` |
| `bkcrack.ziparchive` | ZIP 解析与重写（Zip64、AES、Unicode 额外字段），`decipher` / `decrypt` / `change_keys` |
| `bkcrack.arguments` | 命令行解析，与 C++ `Arguments` 一一对应 |
| `bkcrack.progress` | 进度与状态机（`NORMAL` / `CANCELED` / `EARLY_EXIT`） |
| `bkcrack.cli` | 命令行界面与输出格式 |

---

## 项目结构

```
bkcrack-py/
├── pyproject.toml            # 构建配置、console script、可选依赖
├── LICENSE
├── README.md
├── src/bkcrack/              # 可安装包（src 布局）
│   ├── __init__.py           # 公开 API 与版本号
│   ├── __main__.py           # python -m bkcrack
│   ├── cli.py                # 命令行界面
│   ├── arguments.py          # 参数解析与约束检查
│   ├── constants.py tables.py keys.py
│   ├── data.py zreduction.py attack.py password.py
│   ├── _fastroots.py         # NumPy 向量化内核（可选）
│   ├── _attack_parallel.py   # 多进程攻击
│   ├── ziparchive.py         # ZIP 解析与改写
│   ├── progress.py console_progress.py errors.py file.py
│   └── py.typed
├── tests/                    # pytest 用例与样例压缩包
│   └── data/                 # 上游测试用 zip 文件
├── scripts/cross_validate.py # 与官方二进制对拍
├── reference/                # 上游 C++ 源码（仅对照用，不随包分发）
└── _refbin/                  # 官方 bkcrack 可执行文件（仅对照用）
```

---

## 测试

```bash
python -m pytest                 # 全部测试
python -m pytest -m "not slow"   # 跳过耗时较长的攻击 / 密码恢复用例
```

当前状态：

```
183 passed in 63.98s
```

测试分两类：

1. **官方向量移植**：`tests/test_tables.py`、`test_keys.py`、`test_data.py`、
   `test_zreduction.py`、`test_attack.py`、`test_password.py`、`test_ziparchive.py`、
   `test_arguments.py` 直接移植自上游 `tests/`，覆盖 CRC32 表、KeystreamTab 向量、
   `Data` 的 13 个构造用例与 8 个错误用例、Zreduction 的 `generate` / `reduce` 结果、
   Attack 的 5 个向量、密码恢复与 ZIP 解析细节。
2. **端到端 CLI 测试**：`tests/test_cli.py` 用 `tests/data/` 中的样例压缩包跑完整流程，
   逐字节比对输出文件；`tests/test_files.py` 覆盖输入输出文件的打开失败文案。

---

## 交叉验证

`scripts/cross_validate.py` 会同时调用**官方 `bkcrack.exe`** 与本实现，比较标准输出、
标准错误、退出码以及生成文件的哈希：

```bash
# 需要官方二进制，默认在 _refbin/bkcrack-1.8.1-win64/bkcrack.exe
python scripts/cross_validate.py

# 指定二进制路径 / 只跑部分检查 / 追加攻击分支
python scripts/cross_validate.py --binary /path/to/bkcrack --attack --verbose
```

最近一次完整运行（`--attack`，含完整攻击）结果：

```
[ok] attack on example archive
       official 61.5 s, python 1632.2 s

37/37 checks passed
all checks passed
```

覆盖范围：

| 类别 | 检查项 |
| --- | --- |
| 版本与帮助 | `--version`、`-h` 全文 |
| 列表 | 7 个测试压缩包的 `-L` 输出逐字节一致 |
| 密码校验 | 4 组 `--password`（含空密码与 UTF-8 密码） |
| 错误处理 | 7 类错误消息与退出码 |
| 解密 | `-d`（STORED、DEFLATE、`--keep-header`、JPEG、SVG）输出逐字节相同 |
| 去密码 | `-D`（zipcrypto、zip64-zipcrypto、aes256）逐字节相同 |
| 改密钥 | `-U`、`--change-keys` |
| 密码恢复 | 6 组（暴力、掩码、越界字节、自定义字符集） |
| 完整攻击 | 教程压缩包上找到同一组密钥 `c4490e28 b414a23d 91404b31` |

比较前会归一化时间戳、终端转义序列（官方 Windows 二进制在进度行尾会输出 `ESC[1K`）
和进度行本身，其余输出逐行比对。

此外教程 `example/tutorial.md` 中的攻击也在本实现上完整复现，
得到与官方一致的密钥 `c4490e28 b414a23d 91404b31`。

---

## 性能

纯 Python 比 C++ 慢，但通过 NumPy 向量化内核（默认启用）与多进程并行，
实际耗时仍在可接受范围内。教程中的完整攻击（542303 个候选，同一台机器实测）：

| 实现 | 耗时 |
| --- | --- |
| 官方 C++ 二进制（单线程） | 61.5 s |
| 本实现（NumPy + 多进程） | 1632.2 s（约 27 分钟） |

设置环境变量 `BKCRACK_NO_NUMPY=1` 可强制走纯 Python 路径（用于对照调试，
速度会显著下降）。`-j` 控制并行进程数，默认为 CPU 核数。

密码恢复等短任务几乎感觉不到差异，主要差距都集中在完整攻击这一步。

---

## 与原实现的已知差异

以下差异都不影响结果正确性：

1. **并行粒度**。C++ 用线程池按候选逐个抢占，`--continue-attack` 的值精确到单个候选；
   本实现用进程池，单批 64 个候选，因此中断时记录的位置可能比官方**略靠前**。
   由于保底重启点只会更早，不会漏掉任何候选，只是可能重复计算少量已排除的候选。
2. **进度行清屏方式**。两者都是 200 ms 刷新、`\r` 覆盖、`"%.1f %% (%d / %d)"` 格式；
   官方 Windows 发行版在进度行尾追加 `ESC[1K`（清到行尾），本实现沿用参考源码的写法
   用空格覆盖，终端观感一致。交叉验证时这类终端控制序列会被归一化。
3. **并行实现方式**。C++ 使用 `std::thread`，Python 受 GIL 限制改用
   `multiprocessing` 的 `spawn` 上下文，首次启动有额外开销，代价是完整攻击慢约 26 倍
   （见上一节）。
4. **标准输出编码**。官方按字节直接写出，本实现也走 `sys.stdout.buffer`，
   因此非 ASCII 密码（例如 `passwörd`、含 emoji 的密码）输出的原始字节一致。

---

## 许可证

沿用上游的 zlib/libpng 许可证，见 [LICENSE](LICENSE)。

原始项目版权：Copyright (c) 2016-2026 Joachim Hotonnier。
本仓库是独立的 Python 改写版本，与原作者无关，也未获其背书。
