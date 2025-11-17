# dragonfuzz
DragonFuzz

## Introduction

This is an attempt to get the `dragonfuzz` working on the latest OS and build of OpenSSL/Aircrack

Based heavily on https://gitlab.com/NikolaiT/dragonfuzz

## Basic Usage

Use the following configuration for the access point:

```
interface=wlanAP
ssid=WPA3-Network
hw_mode=g
channel=1
wpa=2
wpa_passphrase=abcdefgh
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
#ieee80211w=2
```

Then start the access point using the command `sudo hostapd/hostapd wpa3.conf -K`


Start the dragonfuzz tool using the command:

`sudo ./dragonfuzz -a 9c:ef:d5:fc:0e:a8 -d wlanSTA -c 1 -v0`

where `-a` specifies the MAC address of the AP (the one that belongs to wlanAP) and `-c` sets the channel.

This is a example run without fuzzing anything:

```
nikolai@nikolai:~/Master/Masterarbeit/dragondrain-and-time/src$ sudo ./dragonfuzz -a 9c:ef:d5:fc:0e:a8 -d wlan0 -c 1 -v0
[i] Using password=abcdefgh
[i] Using ECC groupid = 19
[i] Opening card wlan0
[i] Setting to channel 1
[i] c8:f7:33:d4:5a:e9 sent SAE AUTH-COMMIT frame
[i] Processing commit frame from 9c:ef:d5:fc:0e:a8!
[i] Sent ACK frame from c8:f7:33:d4:5a:e9 to 9c:ef:d5:fc:0e:a8
[i] c8:f7:33:d4:5a:e9 sent SAE AUTH-CONFIRM frame
[i] c8:f7:33:d4:5a:e9 sent SAE AUTH-CONFIRM frame
[i] Received a SAE CONFIRM frame from 9c:ef:d5:fc:0e:a8
[+] Successfully verified peer confirm token!
[i] c8:f7:33:d4:5a:e9 sent ASSOCIATION request frame
[i] Received a ASSOC RESPONSE frame from 9c:ef:d5:fc:0e:a8
```


## Fuzzing setup

For ease of development I use two Wifi devices on my Ubuntu 18.04 laptop. My laptop integrated NIC and a
USB Wifi Dongle PAU07. The AP uses the laptop integrated NIC and the client makes use of the USB Dongle.

The advantage in this setup is the complete control over both processes. It is immediately obvious when the
fuzzed AP crashes.

### How can we check if the targeted access point had a failure?

1. it does not send beacons in the same interval as before
2. we can monitor the process if the AP process is on the same system


## What is dragonfuzz doing exactly?

On the one side, dragonfuzz is only a simple program that implements the complete WPA3 dragonfly handshake.

The tool implements the following process/state machine when no fuzzing happens.

See here for reference of the [802.11 state machine](https://netbeez.net/blog/station-authentication-association/)

0. Sending a probe request frame and waiting for probe response frames.
1. Listening for Beacon Frames from the access point of interest.
2. Sending a SAE Auth-Commit frame to the access point
3. Waiting for the SAE Auth-Commit and SAE Auth-Confirm frame from the access point.
4. (optional because hard to implement in userland) Ack the received Auth-Commit and Auth-Confirm frames.
5. Sending an association request frame to the access point.
6. Waiting for an association response.
7. Begin the 4-way handshake by waiting for Msg1 from the AP
8. Reply with Msg2 of 4 way handshake
9. Wait for Msg3 of the AP
10. Reply with Msg4

Additionally, dragonfuzz has the capability to fuzz each frame in each state of the above handshake process.

When no specific frame to fuzz is specified, dragonfuzz implements the following automatic fuzzing strategy:

Fuzz the frame of step 0. If the access point replies in a valid way according to the 802.11 specification, mark this
step as handled and go further one step. This means we will send a deauthentication frame and begin freshly by sending frame 0
 (unfuzzed) and then fuzz the subsequent frame 1.

By following this algorithm, we will only **fuzz one frame at the time** and guarantee to dive into the full depth of the handshake by
resetting the state machine with sending a deauth frame. This also means that we need to define a **correct behavior** of the AP for
each state in the handshake.

### What means fuzzing a frame?

It depends on the frame. For example in the auth commit frame we can fuzz the lengths of the scalars or elements or the group id.
We can populate the auth-commit frame with crypto variables from FFC with multiplicative groups instead of ECC. We can send two
frames at the same time, one with a anti-clogging token set, the other without anti-clogging token.

We need to define in the state machine for each frame what defines a correct handling of a fuzzed frame.

### What is security critical behavior of an AP?

For example when the AP crashes. This can easily be spotted by monitoring the process while fuzzing.

Another critical behavior is when the AP process suddenly consumes more resources.

## The Dragonfly SAE state machine



## Debugging and troubleshooting

Monitoring the traffic while testing my fuzzer is a very important part. But it's not really easy, since both wireless devices
are in monitor mode


### Wireshark filters

```
Probe Request: wlan.fc.type_subtype == 0x0004
Probe Response: wlan.fc.type_subtype == 0x0005
Authentication frame: wlan.fc.type_subtype == 0x000b
Association Request: wlan.fc.type_subtype == 0x0000
Association Response: wlan.fc.type_subtype == 0x0001
```
