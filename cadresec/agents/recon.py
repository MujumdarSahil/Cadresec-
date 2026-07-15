from typing import Dict, Any
from langgraph.graph import StateGraph, END
from langchain_core.runnables import RunnableConfig

from cadresec.agents.state import AgentState
from cadresec.tools.recon_stub import ReconStubTool, ReconInput
from cadresec.tools.dns_lookup import DNSLookupToolSpec, DNSInput
from cadresec.tools.nmap import NmapToolSpec, NmapInput
from cadresec.tools.banner_grab import BannerGrabToolSpec, BannerGrabInput


def recon_node(state: AgentState, config: RunnableConfig) -> Dict[str, Any]:
    """Recon agent node: runs DNS lookup, port discovery, and banner grabbing."""
    session = config.get("configurable", {}).get("session")
    if not session:
        raise ValueError("An active EngagementSession must be configured in 'configurable.session'.")

    # Assert session is not killed
    session.assert_not_killed()

    target = state.get("current_target")
    messages = []
    open_ports = []

    # 1. Run Recon Stub (always run for backward compatibility/tests)
    try:
        recon_stub = ReconStubTool()
        recon_res = recon_stub.run(session, ReconInput(target=target))
        messages.append({
            "sender": "recon_agent",
            "text": f"Passive recon stub completed. Resolved IPs: {recon_res.detected_ips}."
        })
    except Exception as e:
        messages.append({
            "sender": "recon_agent",
            "text": f"Passive recon stub failed: {str(e)}."
        })

    # 2. Run DNS Lookup if target is a domain name
    is_ip = True
    try:
        import ipaddress
        ipaddress.ip_address(target)
    except ValueError:
        is_ip = False

    if not is_ip:
        try:
            dns_tool = DNSLookupToolSpec()
            dns_res = dns_tool.run(session, DNSInput(target=target, record_types=["A", "NS", "MX"]))
            if dns_res.success:
                messages.append({
                    "sender": "recon_agent",
                    "text": f"DNS lookup resolved: {dns_res.records}."
                })
        except Exception as e:
            messages.append({
                "sender": "recon_agent",
                "text": f"DNS lookup skipped: {str(e)}."
            })

    # 3. Run Nmap discovery scan
    try:
        nmap_tool = NmapToolSpec()
        nmap_res = nmap_tool.run(session, NmapInput(target=target))
        if nmap_res.success:
            messages.append({
                "sender": "recon_agent",
                "text": f"Nmap discovery scan completed successfully."
            })
            for host in nmap_res.parsed_hosts:
                for p in host.get("ports", []):
                    if p.get("state") == "open":
                        open_ports.append(p.get("port"))
    except Exception as e:
        messages.append({
            "sender": "recon_agent",
            "text": f"Nmap discovery scan skipped: {str(e)}."
        })

    # 4. Grab banners for open ports
    banner_info = []
    for port in open_ports[:3]:  # Limit to top 3 ports to keep it fast
        try:
            banner_tool = BannerGrabToolSpec()
            banner_res = banner_tool.run(session, BannerGrabInput(target=target, port=port))
            if banner_res.success and banner_res.banner:
                banner_info.append(f"Port {port}: {banner_res.service_guess} ({banner_res.banner})")
        except Exception:
            pass

    if banner_info:
        messages.append({
            "sender": "recon_agent",
            "text": f"Banner grabbing results:\n" + "\n".join(banner_info)
        })

    return {
        "messages": messages,
        "completed_steps": ["recon"]
    }


def build_recon_graph():
    """Compiles the Recon Agent subgraph."""
    builder = StateGraph(AgentState)
    builder.add_node("recon_node", recon_node)
    builder.set_entry_point("recon_node")
    builder.add_edge("recon_node", END)
    return builder.compile()
