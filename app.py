"""Rule-based detection over offline JSON network-flow records."""
from __future__ import annotations
COMMON_PORTS={22,53,80,123,443,445,3389}
def detect(flow: dict) -> list[dict]:
    if not isinstance(flow,dict): raise ValueError("Flow must be an object")
    alerts=[]; src=str(flow.get("src_ip","unknown"))
    try:
        rate=int(flow.get("connections_last_minute",0)); failed=int(flow.get("failed_connections",0)); port=int(flow.get("dst_port",0))
    except (TypeError,ValueError) as exc: raise ValueError("Flow counters and port must be integers") from exc
    if min(rate,failed,port)<0 or port>65535: raise ValueError("Counters must be non-negative and port <= 65535")
    if rate>=100: alerts.append({"rule":"NET-001","severity":"high","src_ip":src,"reason":"High connection rate"})
    if port and port not in COMMON_PORTS: alerts.append({"rule":"NET-002","severity":"low","src_ip":src,"reason":f"Unusual destination port {port}"})
    if failed>=20: alerts.append({"rule":"NET-003","severity":"medium","src_ip":src,"reason":"Repeated failed connections"})
    return alerts
if __name__=="__main__":
    print(detect({"src_ip":"192.0.2.10","dst_port":4444,"connections_last_minute":130,"failed_connections":28}))
