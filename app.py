"""Rule-based IDS over synthetic/offline flow records."""
COMMON_PORTS = {22, 53, 80, 123, 443, 445, 3389}
def detect(flow: dict) -> list[dict]:
    alerts = []
    src = str(flow.get("src_ip", "unknown"))
    if int(flow.get("connections_last_minute", 0)) >= 100:
        alerts.append({"rule":"NET-001", "severity":"high", "src_ip":src, "reason":"High connection rate"})
    port = int(flow.get("dst_port", 0))
    if port not in COMMON_PORTS and port > 0:
        alerts.append({"rule":"NET-002", "severity":"low", "src_ip":src, "reason":f"Unusual destination port {port}"})
    if int(flow.get("failed_connections", 0)) >= 20:
        alerts.append({"rule":"NET-003", "severity":"medium", "src_ip":src, "reason":"Repeated failed connections"})
    return alerts

if __name__ == "__main__":
    samples = [{"src_ip":"192.0.2.10","dst_port":4444,"connections_last_minute":130,"failed_connections":28}]
    for item in samples:
        print(detect(item))
