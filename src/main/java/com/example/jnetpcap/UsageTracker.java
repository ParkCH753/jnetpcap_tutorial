package com.example.jnetpcap;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class UsageTracker {
    private static final String HTTPS_SYN_FIN_FILTER = "dst port 443 and (tcp-syn|tcp-fin) != 0";
    private static final long SECONDS_IN_MINUTE = 60;
    private static final long MILLIS_IN_SECOND = 1000;

    public void trackTime(String url) {
        // 네트워크 장치 목록 가져오기
        StringBuilder errbuf = new StringBuilder();
        List<PcapIf> devices = new ArrayList<>();
        int result = Pcap.findAllDevs( devices, errbuf);
        if (result != Pcap.OK) {
            System.err.println("네트워크 장치를 찾을 수 없습니다: " + errbuf);
            return;
        }

        // 캡처 장치 열기
        int snaplen = 64 * 1024; // 패킷 캡처 크기
        int flags = Pcap.MODE_PROMISCUOUS; // 모든 패킷 캡처
        int timeout = 10 * 1000; // 타임아웃(ms)
        PcapIf pcapIf = devices.get(1);
        Pcap pcap = Pcap.openLive(pcapIf.getName(), snaplen, flags, timeout, errbuf);
        if (pcap == null) {
            System.err.println("캡처 장치를 열 수 없습니다: " + errbuf);
            return;
        }

        String FILTER = "host " + url + " and " + HTTPS_SYN_FIN_FILTER;

        System.out.println("filter : " + FILTER);
        // 패킷 필터 설정
        PcapBpfProgram filter = new PcapBpfProgram();
        result = pcap.compile(filter, FILTER, 0, 0);
        if (result != Pcap.OK) {
            System.err.println("패킷 필터를 설정할 수 없습니다: " + pcap.getErr());
            return;
        }
        result = pcap.setFilter(filter);
        if (result != Pcap.OK) {
            System.err.println("패킷 필터를 적용할 수 없습니다: " + pcap.getErr());
            return;
        }

        // YouTube 사용 시간 추적
        long startTime = 0;
        long totalTime = 0;

        System.out.println("식별 시작!");

        while (true) {
            PcapPacket packet = new PcapPacket(0);
            if (pcap.nextEx(packet) != Pcap.NEXT_EX_OK) {
                continue;
            }

            // YouTube 패킷 식별
            Ip4 ip = packet.getHeader(new Ip4());
            String destinationIp = FormatUtils.ip(ip.destination());
            System.out.println(destinationIp);

            long currentTime = packet.getCaptureHeader().timestampInMillis();

                if (startTime == 0) {
                    startTime = currentTime;
                } else {
                    long endTime = currentTime;
                    totalTime += (endTime - startTime);
                    startTime = endTime;
                }

            // 결과 표시 (예: 매분마다)
            long elapsedSeconds = totalTime / MILLIS_IN_SECOND;
            long minutes = elapsedSeconds / SECONDS_IN_MINUTE;
            long seconds = elapsedSeconds % SECONDS_IN_MINUTE;
            System.out.println("사용자의 "+url+" 사용 시간: " + minutes + "분 " + seconds + "초");
        }

        // 캡처 장치 닫기
    }
}
