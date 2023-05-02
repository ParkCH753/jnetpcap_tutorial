package com.example.jnetpcap;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;

@SpringBootApplication
public class JnetpcapApplication {

    public static void main(String[] args) throws ClassNotFoundException {
        ApplicationContext context = SpringApplication.run(JnetpcapApplication.class, args);
        //PacketCapture packetCapture = context.getBean(PacketCapture.class);
        PacketCapture packetCapture = new PacketCapture();

        packetCapture.capturePacket();

        packetCapture.showMac();

        packetCapture.sniffPacket();
    }

}
