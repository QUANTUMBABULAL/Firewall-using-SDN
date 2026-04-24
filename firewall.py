from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

# ==============================
# 🔥 RULE SET (EDITABLE)
# ==============================
RULES = [
    {"type": "ip", "value": "10.0.0.2", "action": "block"},          # h2
    {"type": "mac", "value": "00:00:00:00:00:01", "action": "block"},# h1
    {"type": "port", "value": 80, "action": "block"}                 # HTTP
]

# ==============================
# 🔍 RULE CHECK FUNCTION
# ==============================
def check_rules(packet):
    eth = packet.find('ethernet')
    ip_packet = packet.find('ipv4')
    tcp_packet = packet.find('tcp')

    for rule in RULES:

        # 🔴 IP RULE
        if rule["type"] == "ip" and ip_packet:
            if str(ip_packet.srcip) == rule["value"]:
                return "block", "IP"

        # 🔴 MAC RULE
        if rule["type"] == "mac" and eth:
            if str(eth.src) == rule["value"]:
                return "block", "MAC"

        # 🔴 PORT RULE
        if rule["type"] == "port" and tcp_packet:
            if tcp_packet.dstport == rule["value"]:
                return "block", "PORT"

    return "allow", None


# ==============================
# 📦 PACKET HANDLER
# ==============================
def _handle_PacketIn(event):
    packet = event.parsed

    if not packet:
        return

    eth = packet.find('ethernet')
    ip_packet = packet.find('ipv4')
    tcp_packet = packet.find('tcp')

    action, rule_type = check_rules(packet)

    # 🔴 BLOCK TRAFFIC
    if action == "block":
        log.info("🚫 BLOCKED (%s RULE)", rule_type)

        msg = of.ofp_flow_mod()

        # MAC RULE
        if rule_type == "MAC" and eth:
            msg.match = of.ofp_match(dl_src=eth.src)

        # IP RULE
        elif rule_type == "IP" and ip_packet:
            msg.match = of.ofp_match(
                dl_type=0x0800,
                nw_src=ip_packet.srcip
            )

        # PORT RULE
        elif rule_type == "PORT" and tcp_packet:
            msg.match = of.ofp_match(
                dl_type=0x0800,
                nw_proto=6,
                tp_dst=tcp_packet.dstport
            )

        else:
            return

        msg.actions = []  # DROP
        event.connection.send(msg)
        return

    # ✅ ALLOW TRAFFIC
    msg = of.ofp_packet_out()
    msg.data = event.ofp
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    event.connection.send(msg)


# ==============================
# 🚀 START CONTROLLER
# ==============================
def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("🔥 SDN Firewall Running (IP + MAC + PORT Filtering)")