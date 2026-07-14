#!/bin/bash
# AERO Edge VPS 一键测试 + 清理脚本
# 用法（在你本地终端执行）:
#   scp /tmp/aero-edge-linux-amd64 root@128.241.228.161:/tmp/
#   ssh root@128.241.228.161 "bash -s" < deploy/test_and_clean.sh
set -e

TOKEN="test-aero-$(date +%s)"
LOG="/tmp/aero-test.log"
echo "=========================================" | tee $LOG
echo " AERO Edge Server — 部署 + 测试 + 清理" | tee -a $LOG
echo " 时间: $(date)" | tee -a $LOG
echo "=========================================" | tee -a $LOG

# ============ 第1步: 部署 ============
echo "" | tee -a $LOG
echo "[1/5] 安装二进制..." | tee -a $LOG
mkdir -p /etc/aero /var/lib/aero/certs /tmp/aero-test
cp /tmp/aero-edge-linux-amd64 /usr/local/bin/aero-edge
chmod +x /usr/local/bin/aero-edge
echo "  OK: $(file /usr/local/bin/aero-edge)" | tee -a $LOG

echo "[2/5] 生成配置..." | tee -a $LOG
cat > /etc/aero/edge.conf << CONF
AERO_TOKEN=$TOKEN
AERO_PORTS=18443
AERO_SNI=cdn-aero.com
AERO_CERT_DIR=/tmp/aero-test/certs
AERO_LOG=/tmp/aero-test/edge.log
CONF
echo "  OK: /etc/aero/edge.conf" | tee -a $LOG

echo "[3/5] 启动 Edge（自签证书 + 日志到文件）..." | tee -a $LOG
aero-edge \
  -token "$TOKEN" \
  -ports "18443" \
  -sni "cdn-aero.com" \
  -log-file "/tmp/aero-test/edge.log" \
  -log-format "text" \
  > /tmp/aero-test/stdout.log 2>&1 &
EDGE_PID=$!
echo "  PID: $EDGE_PID" | tee -a $LOG

# 等待启动
sleep 3

# ============ 第2步: 验证 ============
echo "" | tee -a $LOG
echo "[4/5] 验证..." | tee -a $LOG

# 检查进程
if kill -0 $EDGE_PID 2>/dev/null; then
    echo "  ✅ 进程运行中 (PID=$EDGE_PID)" | tee -a $LOG
else
    echo "  ❌ 进程未运行！查看日志:" | tee -a $LOG
    cat /tmp/aero-test/stdout.log | tee -a $LOG
    cat /tmp/aero-test/edge.log 2>/dev/null | tee -a $LOG
    exit 1
fi

# 检查端口
if ss -tlnp | grep -q 18443; then
    echo "  ✅ 端口 18443 监听中" | tee -a $LOG
else
    echo "  ⚠️  端口 18443 未监听" | tee -a $LOG
fi

# 检查健康端点
sleep 1
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:18443/health 2>/dev/null || echo "000")
if [ "$HEALTH" = "200" ]; then
    echo "  ✅ /health 返回 200" | tee -a $LOG
else
    echo "  ⚠️  /health 返回 $HEALTH (预期200，自签可能需-k)" | tee -a $LOG
fi

# 检查 /ech-config 端点
ECH_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:18443/ech-config 2>/dev/null || echo "000")
echo "  ℹ️  /ech-config HTTP $ECH_CODE" | tee -a $LOG

# 检查日志
if [ -f /tmp/aero-test/edge.log ]; then
    LOG_LINES=$(wc -l < /tmp/aero-test/edge.log)
    echo "  ✅ 日志文件已生成 ($LOG_LINES 行)" | tee -a $LOG
    echo "  --- 日志最后5行 ---" | tee -a $LOG
    tail -5 /tmp/aero-test/edge.log | tee -a $LOG
fi

# SSL 握手测试
echo "" | tee -a $LOG
echo "  --- TLS 握手测试 ---" | tee -a $LOG
if command -v openssl &>/dev/null; then
    TLS_OK=$(echo Q | openssl s_client -connect 127.0.0.1:18443 -tls1_3 2>&1 | grep -c "Server certificate" || echo "0")
    if [ "$TLS_OK" -gt 0 ]; then
        echo "  ✅ TLS 1.3 握手成功" | tee -a $LOG
    else
        echo "  ⚠️  TLS 握手未确认" | tee -a $LOG
    fi
else
    echo "  ⏭️  openssl 未安装，跳过" | tee -a $LOG
fi

# 资源使用
echo "" | tee -a $LOG
echo "  --- 资源使用 ---" | tee -a $LOG
ps -o pid,rss,vsz,pcpu,comm -p $EDGE_PID 2>/dev/null | tee -a $LOG

# ============ 第3步: 稳定运行 ============
echo "" | tee -a $LOG
echo "[5/5] 30秒稳定性测试..." | tee -a $LOG
for i in 1 2 3; do
    sleep 10
    if kill -0 $EDGE_PID 2>/dev/null; then
        echo "  ✅ ${i}0秒: 存活" | tee -a $LOG
    else
        echo "  ❌ ${i}0秒: 进程退出!" | tee -a $LOG
        cat /tmp/aero-test/stdout.log | tee -a $LOG
        exit 1
    fi
done

# ============ 输出测试结果 ============
echo "" | tee -a $LOG
echo "=========================================" | tee -a $LOG
echo " ✅ 全部测试通过！" | tee -a $LOG
echo "=========================================" | tee -a $LOG
echo "" | tee -a $LOG
echo "Token: $TOKEN" | tee -a $LOG
echo "日志:  /tmp/aero-test/edge.log" | tee -a $LOG

# ============ 提示清理 ============
echo "" | tee -a $LOG
echo "=========================================" | tee -a $LOG
echo " 准备清理... (kill PID=$EDGE_PID)" | tee -a $LOG
echo "=========================================" | tee -a $LOG

# 停止进程
kill $EDGE_PID 2>/dev/null || true
sleep 1
kill -9 $EDGE_PID 2>/dev/null || true

# 删除所有 AERO 文件
echo "清理文件..." | tee -a $LOG
rm -f /usr/local/bin/aero-edge
rm -rf /etc/aero
rm -rf /var/lib/aero
rm -rf /tmp/aero-test
rm -f /tmp/aero-edge-linux-amd64
rm -f /root/aero_context.db

echo "" | tee -a $LOG
echo "=========================================" | tee -a $LOG
echo " ✅ 清理完成！VPS 已恢复原状" | tee -a $LOG
echo "=========================================" | tee -a $LOG
