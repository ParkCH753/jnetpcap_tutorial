package com.example.jnetpcap;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class JPacketCapture {

    private Pcap pcap;

    public JPacketCapture() {
        // 네트워크 인터페이스 목록 조회
        List<PcapIf> allDevs = new ArrayList<>();
        StringBuilder errbuf = new StringBuilder();
        if (Pcap.findAllDevs(allDevs, errbuf) != Pcap.OK) {
            System.err.printf("Pcap Error: %s", errbuf);
            return;
        }
        if (allDevs.isEmpty()) {
            System.out.println("No interfaces found! Make sure WinPcap or libpcap is installed.");
            return;
        }

        // 캡처할 인터페이스 선택
        PcapIf pcapIf = allDevs.get(1);

        // 패킷 캡처 시작
        pcap = Pcap.openLive(pcapIf.getName(), 65536, Pcap.MODE_PROMISCUOUS, 1000, errbuf);
        if (pcap == null) {
            System.err.printf("Pcap Error: %s", errbuf);
        }
    }

    public void captureNaverPacket() {


        String filter = "tcp port 443";
        PcapBpfProgram program = new PcapBpfProgram();
        int mask = 0xffffff;
        if (pcap.compile(program, filter, 1, mask) != Pcap.OK) {
            System.err.println(pcap.getErr());
        }
        if (pcap.setFilter(program) != Pcap.OK) {
            System.err.println(pcap.getErr());
        }

        String addrNaver = null;

        try {
            InetAddress address = InetAddress.getByName("www.naver.com");
            addrNaver = address.getHostAddress();

            System.out.println("네이버의 IP 주소: " + addrNaver);
        } catch (Exception e) {
            System.out.println("IP 주소를 얻는 중 오류가 발생하였습니다.");
            e.printStackTrace();
        }

        // 도메인 IP 고정된 부분 추출하기
        String regex = "^(\\d{1,3}\\.\\d{1,3})\\..*";
        String extractedAddr = null;

        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(addrNaver);

        if (matcher.matches()) { extractedAddr = matcher.group(1); }
        System.out.println();

        // 캡처된 패킷 처리
        String finalExtractedAddr = extractedAddr;
        JPacketHandler<String> packetHandler = new JPacketHandler<>() {
            private final Tcp tcp = new Tcp();
            private final Ip4 ip = new Ip4();

            @Override
            public void nextPacket(JPacket packet, String user) {
                if (packet.hasHeader(tcp) && packet.hasHeader(ip)) {

                    String srcIp = org.jnetpcap.packet.format.FormatUtils.ip(ip.source());
                    String dstIp = org.jnetpcap.packet.format.FormatUtils.ip(ip.destination());
//                    System.out.println("Source IP: " + srcIp);
//                    System.out.println("Destination IP: " + dstIp);

                    if (srcIp.startsWith(finalExtractedAddr) || dstIp.startsWith(finalExtractedAddr)) {

                        byte[] data = packet.getByteArray(tcp.getOffset(), tcp.getHeaderLength() + tcp.getPayloadLength());

//                    System.out.println(packet);
                        if (tcp.destination() == 443) {
                            // SSL/TLS 핸드셰이크 패킷 처리
                            String hex = bytesToHex(data);
                            System.out.println("SSL/TLS Handshake: " + hex);
                        } else {
                            // HTTPS 패킷 처리
                            System.out.println("HTTPS Packet: " + new String(data));
                            // System.out.println(packet);
                        }
                    }
                }
            }

            private String bytesToHex(byte[] bytes) {
                StringBuilder sb = new StringBuilder();
                for (byte b : bytes) {
                    sb.append(String.format("%02X ", b));
                }
                return sb.toString();
            }
        };
        pcap.loop(Pcap.LOOP_INFINITE, packetHandler, "");


    }
    public void captureHttpsPacket() {

        String filter = "tcp port 443";
        PcapBpfProgram program = new PcapBpfProgram();
        int mask = 0xffffff;
        if (pcap.compile(program, filter, 1, mask) != Pcap.OK) {
            System.err.println(pcap.getErr());
        }
        if (pcap.setFilter(program) != Pcap.OK) {
            System.err.println(pcap.getErr());
        }

        // 캡처된 패킷 처리
        JPacketHandler<String> packetHandler = new JPacketHandler<>() {
            private final Tcp tcp = new Tcp();
            private final Ip4 ip = new Ip4();

            @Override
            public void nextPacket(JPacket packet, String user) {
                if (packet.hasHeader(tcp) && packet.hasHeader(ip)) {

                    byte[] data = packet.getByteArray(tcp.getOffset(), tcp.getHeaderLength() + tcp.getPayloadLength());

//                    System.out.println(packet);
                    if (tcp.destination() == 443) {
                        // SSL/TLS 핸드셰이크 패킷 처리
                        String hex = bytesToHex(data);
                        System.out.println("SSL/TLS Handshake: " + hex);
                    } else {
                        // HTTPS 패킷 처리
                        System.out.println("HTTPS Packet: " + new String(data));
                    }
                }
            }

            private String bytesToHex(byte[] bytes) {
                StringBuilder sb = new StringBuilder();
                for (byte b : bytes) {
                    sb.append(String.format("%02X ", b));
                }
                return sb.toString();
            }
        };
        pcap.loop(Pcap.LOOP_INFINITE, packetHandler, "");

    }

    public void captureHttpPacket() {

        String filter = "tcp port 80";
        PcapBpfProgram program = new PcapBpfProgram();
        int mask = 0xffffff;
        if (pcap.compile(program, filter, 1, mask) != Pcap.OK) {
            System.err.println(pcap.getErr());
        }
        if (pcap.setFilter(program) != Pcap.OK) {
            System.err.println(pcap.getErr());
        }

        // 캡처된 패킷 처리
        JPacketHandler<String> packetHandler = new JPacketHandler<>() {
            private final Tcp tcp = new Tcp();
            private final Ip4 ip = new Ip4();

            @Override
            public void nextPacket(JPacket packet, String user) {
                if (packet.hasHeader(tcp) && packet.hasHeader(ip)) {

                    byte[] data = packet.getByteArray(tcp.getOffset(), tcp.getHeaderLength() + tcp.getPayloadLength());


                    if (tcp.destination() == 80) {
                        // SSL/TLS 핸드셰이크 패킷 처리
                        String hex = bytesToHex(data);
                        System.out.println("SSL/TLS Handshake: " + hex);
                    } else {
                        // HTTPS 패킷 처리
                        System.out.println(packet);
                        System.out.println("HTTPS Packet: " + new String(data));
                    }
                }
            }

            private String bytesToHex(byte[] bytes) {
                StringBuilder sb = new StringBuilder();
                for (byte b : bytes) {
                    sb.append(String.format("%02X ", b));
                }
                return sb.toString();
            }
        };
        pcap.loop(Pcap.LOOP_INFINITE, packetHandler, "");

    }

    public void close() {
        pcap.close();
    }
}