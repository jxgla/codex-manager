@echo off
REM Windows 打包脚本

echo === 构建平台: Windows ===

REM 安装打包依赖
pip install pyinstaller --quiet

REM 执行打包
pyinstaller codex_manager_webui.spec --clean --noconfirm

IF EXIST dist\codex-manager-webui.exe (
    FOR /F "tokens=*" %%i IN ('powershell -Command "[System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture"') DO SET ARCH=%%i
    SET OUTPUT=dist\codex-manager-webui-windows-%ARCH%.exe
    MOVE dist\codex-manager-webui.exe "%OUTPUT%"
    echo === 构建完成: %OUTPUT% ===
) ELSE (
    echo === 构建失败，未找到输出文件 ===
    exit /b 1
)
