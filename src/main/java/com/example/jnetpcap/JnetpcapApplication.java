package com.example.jnetpcap;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;

@SpringBootApplication
public class JnetpcapApplication {

    public static void main(String[] args) throws ClassNotFoundException {

        ApplicationContext context = SpringApplication.run(JnetpcapApplication.class, args);
        //JPacketCapture jPacketCapture = context.getBean(JPacketCapture.class);
        UsageTracker usageTracker = context.getBean(UsageTracker.class);

//        String url = "www.youtube.com";
        // 유튜브는 접속하고만 있어도, 동영상 틀어놔도 계속 syn/fin이 오간다.
        // 실시간으로 접속시간을 체크할 수 있다.

//        String url = "naver.com";
        // youtube로 할 경우엔 빠른데, naver의 경우는 5~7초는 있다가 packet capture가 된다.
        // 그래도 매번 되긴 한다!
        // 이 경우의 문제는, 정말 naver의 주소만 받아진다.

//        String url = "comic.naver.com";
        // 웹툰을 보고있는 동안에는 syn,fin flag가 오가진 않고, 페이지가 넘어갈 때마다 패킷이 오간다.
        // comic.naver.com을 쓰는 도메인은 모두 추적할 수 있다.
        // naver.com과 같은 경우에도, naver.com을 등록하면 안되고, 부수적인 페이지를 등록해줘야 할 듯 하다.

//        String url = "www.dcinside.com";
        // 메인 화면 주소랑 게시판에 들어갔을 때의 주소가 달라진다.
        // 게시판에 들어가면 시간이 잡히지 않는다.
        String url = "gall.dcinside.com";
        // 이렇게하면 게시판에서 글을 볼 때 시간 측정이 된다.
        // 반응속도 아주 빨라서 좋다!
        // 그냥 홈페이지로 들어가도 이 주소로 패킷이 오간다. 디시인사이드를 추적하고 싶으면 이 주소를 쓰자.

        usageTracker.trackTime(url);



        //        jPacketCapture.captureNaverPacket();
        //
        //PacketCapture packetCapture = context.getBean(PacketCapture.class);
//
//        jPacketCapture.captureHttpsPacket();
//        jPacketCapture.findIP();
//
//        packetCapture.showMac();
        //jPacketCapture.sniffPacket();
//
//        packetCapture.sendPacket();
    }

}
