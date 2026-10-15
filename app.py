import streamlit as st
import pandas as pd
from io import BytesIO
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw

st.set_page_config(
    page_title="Wireshark Network Detective",
    page_icon="🔎",
    layout="wide"
)
# ==========================================
# SECURITY ALERTS
# ==========================================

st.header("🚨 Security Alerts")

if "packets" in locals() and packets:
    alerts = []

    for packet_number, packet in enumerate(packets, start=1):
        if IP in packet and TCP in packet:
            destination_port = packet[TCP].dport
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

            # Flag traffic to selected administrative ports.
            if destination_port in [23, 3389, 5900]:
                alerts.append({
                    "Packet Number": packet_number,
                    "Severity": "Review",
                    "Source IP": source_ip,
                    "Destination IP": destination_ip,
                    "Alert": f"Traffic to monitored port {destination_port}"
                })

            # Flag TCP packets with SYN and no ACK as connection attempts.
            if packet[TCP].flags & 0x02 and not packet[TCP].flags & 0x10:
                alerts.append({
                    "Packet Number": packet_number,
                    "Severity": "Information",
                    "Source IP": source_ip,
                    "Destination IP": destination_ip,
                    "Alert": "TCP connection attempt"
                })

    if alerts:
        st.warning(f"{len(alerts)} potential event(s) to review.")

        st.dataframe(
            pd.DataFrame(alerts),
            use_container_width=True
        )

        alert_csv = pd.DataFrame(alerts).to_csv(index=False).encode("utf-8")

        st.download_button(
            label="⬇️ Download Security Alerts Report",
            data=alert_csv,
            file_name="security_alerts.csv",
            mime="text/csv"
        )
    else:
        st.success("No events matched the current alert rules.")

else:
    st.info("Upload a packet capture to generate security alerts.")
st.title("🔎 Wireshark Network Detective")
st.subheader("Network Packet Analysis and Troubleshooting")
st.write(
    "Upload a packet capture exported from Wireshark to analyze "
    "ARP, DNS, TCP, ICMP, HTTP, and other traffic."
)

uploaded_file = st.file_uploader(
    "Upload a Wireshark capture file",
    type=["pcap", "pcapng"]
)


def get_protocol(packet):
    if ARP in packet:
        return "ARP"
    if DNS in packet:
        return "DNS"
    if ICMP in packet:
        return "ICMP"
    if TCP in packet:
        if packet[TCP].sport == 80 or packet[TCP].dport == 80:
            return "HTTP"
        return "TCP"
    if UDP in packet:
        return "UDP"
    if IPv6 in packet:
        return "IPv6"
    if IP in packet:
        return "IP"
    return "Other"


def get_addresses(packet):
    source = "Unknown"
    destination = "Unknown"

    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst
    elif IPv6 in packet:
        source = packet[IPv6].src
        destination = packet[IPv6].dst
    elif ARP in packet:
        source = packet[ARP].psrc
        destination = packet[ARP].pdst

    return source, destination


if uploaded_file is not None:
    try:
        packets = rdpcap(BytesIO(uploaded_file.getvalue()))

        if len(packets) == 0:
            st.warning("This capture contains no packets.")
        else:
            rows = []

            for number, packet in enumerate(packets, start=1):
                source, destination = get_addresses(packet)

                rows.append({
                    "Packet Number": number,
                    "Protocol": get_protocol(packet),
                    "Source": source,
                    "Destination": destination,
                    "Length (bytes)": len(packet),
                    "Summary": packet.summary()
                })

            df = pd.DataFrame(rows)

            st.success("Capture loaded successfully!")

            st.header("1. Capture Overview")

            col1, col2, col3 = st.columns(3)

            col1.metric("Total Packets", len(df))
            col2.metric("Protocols Found", df["Protocol"].nunique())
            col3.metric("Unique Sources", df["Source"].nunique())

            st.header("2. Protocol Distribution")

            counts = df["Protocol"].value_counts()
            st.bar_chart(counts)

            st.header("3. Packet Explorer")

            choices = sorted(df["Protocol"].unique())

            selected = st.multiselect(
                "Filter by protocol",
                choices,
                default=choices
            )

            filtered = df[df["Protocol"].isin(selected)]

            st.dataframe(filtered, use_container_width=True)

            csv_data = filtered.to_csv(index=False).encode("utf-8")

            st.download_button(
                "Download packet report as CSV",
                data=csv_data,
                file_name="packet_analysis.csv",
                mime="text/csv"
            )

            st.header("4. DNS Analysis")

            dns_packets = [
                p for p in packets
                if DNS in p
            ]

            if dns_packets:
                dns_rows = []

                for p in dns_packets:
                    source, destination = get_addresses(p)
                    query_name = ""

                    if DNSQR in p:
                        query_name = p[DNSQR].qname.decode(
                            "utf-8", errors="replace"
                        ).rstrip(".")

                    dns_rows.append({
                        "Source": source,
                        "Destination": destination,
                        "Query Name": query_name,
                        "Message Type": (
                            "Response" if p[DNS].qr else "Query"
                        )
                    })

                st.dataframe(
                    pd.DataFrame(dns_rows),
                    use_container_width=True
                )
            else:
                st.info(
                    "No DNS packets were found in this capture. "
                    "Try capturing traffic while visiting a new website."
                )

            st.header("5. ARP Analysis")

            arp_packets = [
                p for p in packets
                if ARP in p
            ]

            if arp_packets:
                arp_rows = []

                for p in arp_packets:
                    arp_rows.append({
                        "Type": (
                            "Request"
                            if p[ARP].op == 1
                            else "Reply"
                        ),
                        "Sender IP": p[ARP].psrc,
                        "Sender MAC": p[ARP].hwsrc,
                        "Target IP": p[ARP].pdst,
                        "Target MAC": p[ARP].hwdst
                    })

                st.dataframe(
                    pd.DataFrame(arp_rows),
                    use_container_width=True
                )
            else:
                st.info(
                    "No ARP packets were found in this capture."
                )

            st.header("6. TCP Analysis")

            tcp_packets = [
                p for p in packets
                if TCP in p
            ]

            if tcp_packets:
                tcp_rows = []

                for p in tcp_packets:
                    source, destination = get_addresses(p)

                    tcp_rows.append({
                        "Source": source,
                        "Destination": destination,
                        "Source Port": p[TCP].sport,
                        "Destination Port": p[TCP].dport,
                        "Flags": str(p[TCP].flags)
                    })

                st.dataframe(
                    pd.DataFrame(tcp_rows),
                    use_container_width=True
                )
            else:
                st.info("No TCP packets were found.")

            st.header("7. ICMP Analysis")

            icmp_packets = [
                p for p in packets
                if ICMP in p
            ]

            if icmp_packets:
                icmp_rows = []

                for p in icmp_packets:
                    source, destination = get_addresses(p)

                    icmp_rows.append({
                        "Source": source,
                        "Destination": destination,
                        "Type": p[ICMP].type,
                        "Code": p[ICMP].code
                    })

                st.dataframe(
                    pd.DataFrame(icmp_rows),
                    use_container_width=True
                )
            else:
                st.info(
                    "No ICMP packets were found. "
                    "A ping test may help generate ICMP traffic."
                )

            st.header("8. Basic HTTP Inspection")

            http_rows = []

            for p in packets:
                if TCP in p and Raw in p:
                    if p[TCP].sport == 80 or p[TCP].dport == 80:
                        payload = bytes(p[Raw].load)
                        text_payload = payload.decode(
                            "utf-8", errors="replace"
                        )

                        if any(
                            marker in text_payload
                            for marker in [
                                "GET ", "POST ", "HEAD ",
                                "HTTP/1."
                            ]
                        ):
                            source, destination = get_addresses(p)

                            http_rows.append({
                                "Source": source,
                                "Destination": destination,
                                "HTTP Data": text_payload[:300]
                            })

            if http_rows:
                st.dataframe(
                    pd.DataFrame(http_rows),
                    use_container_width=True
                )
            else:
                st.info(
                    "No recognizable HTTP text was found on TCP port 80. "
                    "HTTPS traffic is encrypted and will not show "
                    "readable webpage contents here."
                )

            st.header("9. Basic Troubleshooting Notes")

            st.write(
                "- DNS packets can help identify name-resolution activity."
            )
            st.write(
                "- ARP requests without visible replies may need investigation."
            )
            st.write(
                "- TCP flags help inspect connection setup and termination."
            )
            st.write(
                "- ICMP packets can help investigate ping and reachability."
            )
            st.write(
                "- These observations are clues, not automatic proof "
                "of a network fault."
            )

    except Exception as error:
        st.error("Unable to analyze this capture.")
        st.exception(error)

else:
    st.info(
        "Start by uploading a .pcap or .pcapng file exported from Wireshark."
    )

    st.markdown(
        """
        **How to use this dashboard**

        1. Capture traffic in Wireshark.
        2. Save the capture as a `.pcapng` or `.pcap` file.
        3. Upload the saved file above.
        4. Explore the protocol distribution and packet details.
        5. Download the filtered report as CSV.
        """
    )

    # Security Analysis
st.header("🛡️ Suspicious Traffic Detection")

if "packets" in locals() and packets:
    suspicious_results = []

    for packet_number, packet in enumerate(packets, start=1):
        reasons = []

        if IP in packet:
            if len(packet) > 1500:
                reasons.append("Large packet")

            if TCP in packet and TCP.dport in [22, 23, 3389, 5900]:
                reasons.append(
                    f"Traffic to monitored port {packet[TCP].dport}"
                )

            if reasons:
                suspicious_results.append({
                    "Packet Number": packet_number,
                    "Source IP": packet[IP].src,
                    "Destination IP": packet[IP].dst,
                    "Reason": ", ".join(reasons)
                })

    if suspicious_results:
        st.dataframe(
            pd.DataFrame(suspicious_results),
            use_container_width=True
        )
    else:
        st.info("No packets matched the investigation rules.")
else:
    st.info("Upload a packet capture to analyze traffic.")


    # ==========================================
# IP ADDRESS ANALYSIS
# ==========================================

st.header("🌐 IP Address Analysis")

if "packets" in locals() and packets:
    source_ips = []
    destination_ips = []

    for packet in packets:
        if IP in packet:
            source_ips.append(packet[IP].src)
            destination_ips.append(packet[IP].dst)
        elif IPv6 in packet:
            source_ips.append(packet[IPv6].src)
            destination_ips.append(packet[IPv6].dst)

    if source_ips:
        source_counts = (
            pd.Series(source_ips)
            .value_counts()
            .head(10)
            .rename_axis("Source IP")
            .reset_index(name="Packet Count")
        )

        destination_counts = (
            pd.Series(destination_ips)
            .value_counts()
            .head(10)
            .rename_axis("Destination IP")
            .reset_index(name="Packet Count")
        )

        st.subheader("Top 10 Source IP Addresses")
        st.bar_chart(source_counts.set_index("Source IP"))
        st.dataframe(source_counts, use_container_width=True)

        st.subheader("Top 10 Destination IP Addresses")
        st.bar_chart(destination_counts.set_index("Destination IP"))
        st.dataframe(destination_counts, use_container_width=True)
    else:
        st.info("No IPv4 or IPv6 packets were found.")
else:
    st.info("Upload a packet capture to analyze IP addresses.")


    # ==========================================
# SECURITY ALERTS
# ==========================================

st.header("🚨 Security Alerts")

if "packets" in locals() and packets:
    alerts = []

    for packet_number, packet in enumerate(packets, start=1):
        if IP in packet and TCP in packet:
            destination_port = packet[TCP].dport
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

            # Flag traffic to selected administrative ports.
            if destination_port in [23, 3389, 5900]:
                alerts.append({
                    "Packet Number": packet_number,
                    "Severity": "Review",
                    "Source IP": source_ip,
                    "Destination IP": destination_ip,
                    "Alert": f"Traffic to monitored port {destination_port}"
                })

            # Flag TCP packets with SYN and no ACK as connection attempts.
            if packet[TCP].flags & 0x02 and not packet[TCP].flags & 0x10:
                alerts.append({
                    "Packet Number": packet_number,
                    "Severity": "Information",
                    "Source IP": source_ip,
                    "Destination IP": destination_ip,
                    "Alert": "TCP connection attempt"
                })

    if alerts:
        st.warning(f"{len(alerts)} potential event(s) to review.")

        st.dataframe(
            pd.DataFrame(alerts),
            use_container_width=True
        )

        alert_csv = pd.DataFrame(alerts).to_csv(index=False).encode("utf-8")

        st.download_button(
            label="⬇️ Download Security Alerts Report",
            data=alert_csv,
            file_name="security_alerts.csv",
            mime="text/csv"
        )
    else:
        st.success("No events matched the current alert rules.")

else:
    st.info("Upload a packet capture to generate security alerts.")

