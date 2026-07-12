import sys
import json
import socket

def main():
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
            method = req.get("method")
            req_id = req.get("id")
            
            if method == "tools/list":
                res = {
                    "jsonrpc": "2.0",
                    "result": {
                        "tools": [
                            {
                                "name": "check_port",
                                "description": "Checks if a local port is open",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "host_ip": {"type": "string"},
                                        "port": {"type": "integer"}
                                    },
                                    "required": ["host_ip", "port"]
                                }
                            }
                        ]
                    },
                    "id": req_id
                }
            elif method == "tools/call":
                params = req.get("params", {})
                name = params.get("name")
                arguments = params.get("arguments", {})
                
                if name == "check_port":
                    host_ip = arguments.get("host_ip", "host.docker.internal")
                    port = int(arguments.get("port", 80))
                    
                    # Establish TCP connection to specified host IP
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    try:
                        result = sock.connect_ex((host_ip, port))
                        is_open = (result == 0)
                    except Exception:
                        is_open = False
                    finally:
                        sock.close()
                        
                    res = {
                        "jsonrpc": "2.0",
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps({"port": port, "open": is_open})
                                }
                            ]
                        },
                        "id": req_id
                    }
                else:
                    res = {
                        "jsonrpc": "2.0",
                        "error": {"code": -32601, "message": f"Method not found: {name}"},
                        "id": req_id
                    }
            else:
                res = {
                    "jsonrpc": "2.0",
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                    "id": req_id
                }
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "error": {"code": -32603, "message": str(e)}}) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
