package com.example.jnetpcap;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.*;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;



public class PacketCapture {

    private final ArrayList<PcapIf> allDevs;
    private Pcap pcap;

    public PacketCapture() {
        allDevs = new ArrayList<>();
        // 네트워크 어댑터들을 저장할 수 있는 배열생성
        StringBuilder errBuf = new StringBuilder();
        // 오류 메시지를 담을 수 있는 변수 생성
        // 오류 발생시 errBuf안에 오류들을 담게 된다.

        int r = Pcap.findAllDevs(allDevs, errBuf);
        // Pcap이 -1이거나 비어있으면 오류 발생 메시지 출력
        if (r == Pcap.NEXT_EX_NOT_OK || allDevs.isEmpty()) {
            System.out.println("네트워크 장치를 찾을 수 없습니다." + errBuf);
            return;
        }

        System.out.println("네트워크 장비 탐색 성공!!");
        int i = 0;
        // 장치에 존재하는 네트워크들을 모두 탐색하여 null이 아니면 현재장치 설명담는 변수
        for (PcapIf device : allDevs) {
            String description = (device.getDescription() != null) ? device.getDescription() : "장비에 대한 설명이 없습니다.";
            System.out.printf("[%d]번 : %s [%s]n\n", i++, device.getName(), description);
        }

        // 실제 사용할 네트워크를 지정하기
        PcapIf device1 = allDevs.get(1);
        System.out.printf("선택한 장치 : %s\n", (device1.getDescription() != null) ? device1.getDescription() : device1.getName());

        int snapLen = 64 * 1024; // 패킷을 얼마나 캡쳐할 것인지에 대한 옵션
        int flags = Pcap.MODE_NON_PROMISCUOUS; // 패킷검열 없이 받아들이는 옵션
        int timeout = 10 * 1000; // 10000ms 만큼 timeout 설정

        pcap = Pcap.openLive(device1.getName(), snapLen, flags, timeout, errBuf);
        // 에러 발생시 에러메시지 출력
        if (pcap == null) {
            System.out.printf("패킷 캡처를 위해 네트워크 장치를 여는 데 실패했습니다. 오류 : " + errBuf);
        }

//        String filterExpression = "host www.example.com";
//        JPacketHandler<String> packetHandler = new JPacketHandler<String>() {
//            public void nextPacket(JPacket packet, String user) {
//                System.out.printf("Received packet at %s%n", new Date(packet.getCaptureHeader().timestampInMillis()));
//                System.out.println(packet);
//            }
//        };
//        // BPF 필터 설정
//        PcapBpfProgram bpf = new PcapBpfProgram();
//        String expression = "tcp port 443";
//        int optimize = 0;
//        int netmask = 0xFFFFFF00;
//        if (pcap.compile(bpf, expression, optimize, netmask) != Pcap.OK) {
//            System.err.println(pcap.getErr());
//            return;
//        }
//        if (pcap.setFilter(bpf) != Pcap.OK) {
//            System.err.println(pcap.getErr());
//        }
//
//        // 패킷 처리 핸들러 등록
//        JPacketHandler<String> handler = new JPacketHandler<String>() {
//            public void nextPacket(JPacket packet, String user) {
//                Ip4 ip = new Ip4();
//                if (packet.hasHeader(ip)) {
//                    // 패킷에 IP 헤더가 있는 경우 처리
//                    byte[] data = packet.getByteArray(ip.size(), packet.size() - ip.size());
//                    if (data.length > 0 && (data[0] == 22)) {
//                        // 패킷 데이터의 첫 바이트가 22인 경우 처리 (SSL 핸드셰이크 메시지)
//                        System.out.printf("Found HTTPS packet:\n%s\n", packet.toHexdump(packet.size(), false, true, true));
//                    }
//                }
//            }
//        };
    }

    protected void finalize() {
        pcap.close();
    }

    public void capturePacket() {

        System.out.println("[PACKET CAPTURE]\n");

        // pcap에서 제공하는 함수임으로 Override를 해야하고 형식도 맞춰야한다.
        PcapPacketHandler<String> jPacketHandler = new PcapPacketHandler<>() {
            @Override
            public void nextPacket(PcapPacket packet, String user) {
                System.out.printf("캡처 시작: %s\n 패킷의 길이: %-4d\n",
                        new Date(packet.getCaptureHeader().timestampInMillis()),
                        packet.getCaptureHeader().caplen()
                );
                System.out.println(packet);
                System.out.println(user);
            }
        };

        // loop를 통해 10개만 출력하게 했다.
        pcap.loop(10, jPacketHandler, "jnetjNetPcap");

        System.out.println("\n");
    }

    public void showMac() {

        System.out.println("[SHOW MAC]\n");

        try {
            for (final PcapIf i : allDevs) {
                final byte[] mac = i.getHardwareAddress();
                if (mac == null) {
                    continue;
                }
                System.out.printf("장치 주소 : %s\n맥주소 : %s\n", i.getName(), asString(mac));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("\n");
    }

    // mac주소를 문자열형태로 나타내기 위함
    public static String asString(final byte[] mac) {
        final StringBuilder buf = new StringBuilder();
        for (byte b : mac) {
            if (buf.length() != 0) {
                buf.append(":");
            }
            if (b >= 0 && b < 16) {
                buf.append('0');
            }
            buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
        }
        return buf.toString();
    }
    public void sniffPacket() {

        System.out.println("[SNIFF PACKET]\n");

        // 네트워크 2계층 정보를 담는다
        Ethernet eth = new Ethernet();
        // 네트워크 3계층 정보를 담는다
        Ip4 ip = new Ip4();
        // 네트워크 4계층 정보를 담는다
        Tcp tcp = new Tcp();
        // 서버와 통신해서 데이터를 주고 받을 때 데이터가 들어가는 공간(ex. 로그인)
        Payload payload = new Payload();
        // 패킷 헤더
        PcapHeader header = new PcapHeader(JMemory.POINTER);
        // 패킷 버퍼
        JBuffer buf = new JBuffer(JMemory.POINTER);
        // 패킷 캡처시 필요한 id값
        int id = JRegistry.mapDLTToId(pcap.datalink());

        // 오류가 발생하지 않는 한 계속해서 패킷을 캡처할 수 있도록 하는 While 구문
        while (pcap.nextEx(header, buf) != Pcap.NEXT_EX_NOT_OK) {
            PcapPacket packet = new PcapPacket(header, buf);
            packet.scan(id);
            System.out.printf("[ #%d ]\n", packet.getFrameNumber());
            if (packet.hasHeader(eth)) {
                System.out.printf("출발지 MAC 주소 = %s\n도착지 MAC 주소 = %s\n", FormatUtils.mac(eth.source()),
                        FormatUtils.mac(eth.destination()));
            }
            if (packet.hasHeader(ip)) {
                System.out.printf("출발지 IP 주소 = %s\n도착지 IP 주소 = %s\n",
                        FormatUtils.ip(ip.source()), FormatUtils.ip(ip.destination()));
            }
            if (packet.hasHeader(tcp)) {
                System.out.printf("출발지 TCP 주소 = %d\n도착지 TCP 주소 = %d\n",
                        tcp.source(), tcp.destination());
            }
            if (packet.hasHeader(payload)) {
                System.out.printf("페이로드의 길이 = %d\n", payload.getLength());
                //System.out.print(payload.toHexdump());
            }
        }
    }

    public void sendPacket() {

        System.out.println("[SEND PACKET]\n");
        byte[] bytes = new byte[14];
        Arrays.fill(bytes, (byte) 0xff);
        // 전송을 하기 위한 기본 변수 설정
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        // 전송 실패시
        if (pcap.sendPacket(buffer) != Pcap.OK) {
            System.out.println(pcap.getErr());
        }
        // 어떠한 메시지를 실질적으로 보냈는지 확인하는 부분
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            // 0xff 와 AND연산해서 1인 부분만 true 연산
            sb.append(String.format("%02x ", b & 0xff));
        }
        System.out.println("전송한 패킷 : " + sb);
    }

}
