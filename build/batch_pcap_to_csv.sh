#!/usr/bin/env bash
# 批量将 final 目录中的 pcap/pcapng 转为同名 csv
# 用法：
#   1) 直接用默认目录与默认可执行文件路径：
#        ./batch_pcap_to_csv.sh
#   2) 指定数据目录：
#        ./batch_pcap_to_csv.sh "/Users/lizeyi/OneDrive/Documents/work_code/FlowRhythm/final"
#   3) 指定 FlowRhythm 可执行文件（环境变量）：
#        FLOWRHYTHM_BIN="/path/to/FlowRhythm" ./batch_pcap_to_csv.sh

set -euo pipefail

# —— 配置 —— #
# FlowRhythm 可执行文件路径（默认当前目录下的 ./FlowRhythm）
FLOWRHYTHM_BIN="${FLOWRHYTHM_BIN:-./FlowRhythm}"

# pcap 所在目录（默认你的 final 目录）
PCAP_DIR="${1:-/Users/lizeyi/OneDrive/Documents/work_code/FlowRhythm/final}"

# 已存在 csv 是否跳过（1=跳过，0=覆盖）
SKIP_EXISTING="${SKIP_EXISTING:-1}"

# —— 检查 —— #
if [[ ! -d "$PCAP_DIR" ]]; then
  echo "❌ 目录不存在：$PCAP_DIR"
  exit 1
fi

# 允许两种形式：1) 明确在 PATH 里；2) 以相对/绝对路径存在并可执行
if ! command -v "$FLOWRHYTHM_BIN" >/dev/null 2>&1; then
  if [[ ! -x "$FLOWRHYTHM_BIN" ]]; then
    echo "❌ 找不到 FlowRhythm 可执行文件：$FLOWRHYTHM_BIN"
    echo "   请将 FLOWRHYTHM_BIN 指向正确的可执行文件，或把它加入 PATH。"
    exit 1
  fi
fi

echo "📁 数据目录：$PCAP_DIR"
echo "⚙️  提取程序：$FLOWRHYTHM_BIN"
echo "🔁 已有 CSV 处理策略：$([[ $SKIP_EXISTING -eq 1 ]] && echo '跳过' || echo '覆盖')"
echo

# —— 遍历并处理 —— #
# 用 find -print0 + 读取以安全处理空格/中文
found_any=0
while IFS= read -r -d '' pcap; do
  found_any=1
  # 输出文件名与 pcap 同名（去掉扩展名）+ .csv
  csv="${pcap%.*}.csv"

  if [[ -f "$csv" && "$SKIP_EXISTING" -eq 1 ]]; then
    echo "⏩ 已存在，跳过：$(basename "$csv")"
    continue
  fi

  echo "▶️  处理：$(basename "$pcap")"
  # 运行命令：FlowRhythm <输入pcap> <输出csv>
  "$FLOWRHYTHM_BIN" "$pcap" "$csv"
  echo "✅  生成：$(basename "$csv")"
  echo
done < <(find "$PCAP_DIR" -maxdepth 1 -type f \( -iname '*.pcap' -o -iname '*.pcapng' \) -print0)

if [[ $found_any -eq 0 ]]; then
  echo "ℹ️  目录中未发现 .pcap / .pcapng 文件。"
fi

echo "🎉 全部完成。"
