#!/bin/bash
# 跨平台打包脚本（在各平台上分别运行）

set -e

OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
  Darwin)
    PLATFORM="macos"
    EXT=""
    ;;
  Linux)
    PLATFORM="linux"
    EXT=""
    ;;
  MINGW*|CYGWIN*|MSYS*)
    PLATFORM="windows"
    EXT=".exe"
    ;;
  *)
    PLATFORM="$OS"
    EXT=""
    ;;
esac

OUTPUT_NAME="codex-manager-webui-${PLATFORM}-${ARCH}${EXT}"

echo "=== 构建平台: ${PLATFORM} (${ARCH}) ==="
echo "=== 输出文件: dist/${OUTPUT_NAME} ==="

# 安装打包依赖
pip install pyinstaller --quiet 2>/dev/null || \
  uv run --with pyinstaller pyinstaller --version > /dev/null 2>&1

# 执行打包（优先用 uv，回退到直接调用）
if command -v uv &>/dev/null; then
  uv run --with pyinstaller pyinstaller codex_manager_webui.spec --clean --noconfirm
else
  pyinstaller codex_manager_webui.spec --clean --noconfirm
fi

# 重命名输出文件
mv dist/codex-manager-webui${EXT} dist/${OUTPUT_NAME} 2>/dev/null || \
  mv "dist/codex-manager-webui" "dist/${OUTPUT_NAME}" 2>/dev/null || true

echo "=== 构建完成: dist/${OUTPUT_NAME} ==="
ls -lh dist/${OUTPUT_NAME}
