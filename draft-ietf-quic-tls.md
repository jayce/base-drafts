---
title: Using TLS to Secure QUIC
docname: draft-ietf-quic-tls-latest
date: {DATE}
category: std
ipr: trust200902
area: Transport
workgroup: QUIC

stand_alone: yes
pi: [toc, sortrefs, symrefs, docmapping]

author:
  -
    ins: M. Thomson
    name: Martin Thomson
    org: Mozilla
    email: mt@lowentropy.net
    role: editor
  -
    ins: S. Turner
    name: Sean Turner
    org: sn3rd
    email: sean@sn3rd.com
    role: editor

normative:

  QUIC-TRANSPORT:
    title: "QUIC: A UDP-Based Multiplexed and Secure Transport"
    date: {DATE}
    seriesinfo:
      Internet-Draft: draft-ietf-quic-transport-latest
    author:
      -
        ins: J. Iyengar
        name: Jana Iyengar
        org: Fastly
        role: editor
      -
        ins: M. Thomson
        name: Martin Thomson
        org: Mozilla
        role: editor

  QUIC-RECOVERY:
    title: "QUIC Loss Detection and Congestion Control"
    date: {DATE}
    seriesinfo:
      Internet-Draft: draft-ietf-quic-recovery-latest
    author:
      -
        ins: J. Iyengar
        name: Jana Iyengar
        org: Fastly
        role: editor
      -
        ins: I. Swett
        name: Ian Swett
        org: Google
        role: editor

  HKDF: RFC5869

informative:

  AEBounds:
    title: "Limits on Authenticated Encryption Use in TLS"
    author:
      - ins: A. Luykx
      - ins: K. Paterson
    date: 2016-03-08
    target: "http://www.isg.rhul.ac.uk/~kp/TLS-AEbounds.pdf"

  IMC:
    title: "Introduction to Modern Cryptography, Second Edition"
    author:
      - ins: J. Katz
      - ins: Y. Lindell
    date: 2014-11-06
    seriesinfo:
      ISBN: 978-1466570269

  QUIC-HTTP:
    title: "Hypertext Transfer Protocol Version 3 (HTTP/3)"
    date: {DATE}
    seriesinfo:
      Internet-Draft: draft-ietf-quic-http-latest
    author:
      -
        ins: M. Bishop
        name: Mike Bishop
        org: Akamai Technologies
        role: editor

  ROBUST:
    title: "Robust Channels: Handling Unreliable Networks in the Record Layers of QUIC and DTLS 1.3"
    author:
      - ins: M. Fischlin
      - ins: F. Günther
      - ins: C. Janson
    date: 2020-05-16
    target: "https://eprint.iacr.org/2020/718"


--- abstract

This document describes how Transport Layer Security (TLS) is used to secure
QUIC.

本文档介绍了如何使用传输层安全性协议（TLS）来保护 QUIC。

--- note_Note_to_Readers

Discussion of this draft takes place on the QUIC working group mailing list
(quic@ietf.org), which is archived at
[](https://mailarchive.ietf.org/arch/search/?email_list=quic).

Working Group information can be found at [](https://github.com/quicwg); source
code and issues list for this draft can be found at
[](https://github.com/quicwg/base-drafts/labels/-tls).

--- middle

# Introduction - 介绍

This document describes how QUIC {{QUIC-TRANSPORT}} is secured using TLS
{{!TLS13=RFC8446}}.

本文档介绍了如何使用 TLS {{!TLS13=RFC8446}} 保护 QUIC {{QUIC-TRANSPORT}}。

TLS 1.3 provides critical latency improvements for connection establishment over
previous versions.  Absent packet loss, most new connections can be established
and secured within a single round trip; on subsequent connections between the
same client and server, the client can often send application data immediately,
that is, using a zero round trip setup.

TLS 1.3 为先前版本提供了连接建立的关键延迟改进。在没有数据包丢失的情况下，
大多数新连接可以在一次往返中建立和保护; 在同一客户端和服务器之间的后续连接上，
客户端通常可以立即发送应用程序数据，即使用零往返机制。

This document describes how TLS acts as a security component of QUIC.

本文档描述 TLS 如何作为 QUIC 的安全组件。

# Notational Conventions - 符号约定

{::boilerplate bcp14}

This document uses the terminology established in {{QUIC-TRANSPORT}}.

文档使用 {{QUIC-TRANSPORT}} 中建立的术语。

For brevity, the acronym TLS is used to refer to TLS 1.3, though a newer version
could be used; see {{tls-version}}.

为简单起见，缩写 TLS 用来表示 TLS 1.3，不过可以使用更新的版本（见 {{tls-version}}）。

## TLS Overview - TLS 概述

TLS provides two endpoints with a way to establish a means of communication over
an untrusted medium (for example, the Internet). TLS enables authentication of
peers and provides confidentiality and integrity protection for messages that
endpoints exchange.

TLS 为两个端点提供了一种在不受信任的媒体（例如，Internet）上建立通信的方法。
TLS 启用两端的身份验证，并为两端交换的消息提供机密性和完整性保护。

Internally, TLS is a layered protocol, with the structure shown in
{{tls-layers}}.

TLS 内部是一种分层协议，其结构如 {{tls-layers}}。

~~~~
          +-------------+------------+--------------+---------+
Content   |             |            |  Application |         |
Layer     |  Handshake  |   Alerts   |     Data     |   ...   |
          |             |            |              |         |
          +-------------+------------+--------------+---------+
Record    |                                                   |
Layer     |                      Records                      |
          |                                                   |
          +---------------------------------------------------+
~~~~
{: #tls-layers title="TLS Layers"}

Each Content layer message (e.g., Handshake, Alerts, and Application Data) is
carried as a series of typed TLS records by the Record layer.  Records are
individually cryptographically protected and then transmitted over a reliable
transport (typically TCP), which provides sequencing and guaranteed delivery.

记录层将每个内容层消息（例如，握手、警告、应用层数据）作为一系列类型的 TLS 记录
进行传输。记录被单独地加密保护，然后通过可靠的传输方法（通常是 TCP ）传输，
该传输提供排序和有保证的传输。

The TLS authenticated key exchange occurs between two endpoints: client and
server.  The client initiates the exchange and the server responds.  If the key
exchange completes successfully, both client and server will agree on a secret.
TLS supports both pre-shared key (PSK) and Diffie-Hellman over either finite
fields or elliptic curves ((EC)DHE) key exchanges.  PSK is the basis for Early
Data (0-RTT); the latter provides forward secrecy (FS) when the (EC)DHE
keys are destroyed.  The two modes can also be combined, to provide forward
secrecy while using the PSK for authentication.

TLS 认证密钥交换发生在两个端点之间：客户端和服务器。客户端启动交换，服务器响应。
如果密钥交换成功完成，客户端和服务器都将同意一个秘密。TLS 支持有限域或椭圆曲线
上的预共享密钥（PSK）和 Diffie-Hellman 密钥交换。PSK 是早期数据（0-RTT）的基础；
后者在（EC）DHE 密钥被破坏时提供前向保密（FS）。这两种模式也可以结合使用，
以便在使用 PSK 进行身份验证时提供前向保密性。

After completing the TLS handshake, the client will have learned and
authenticated an identity for the server and the server is optionally able to
learn and authenticate an identity for the client.  TLS supports X.509
{{?RFC5280}} certificate-based authentication for both server and client.
When PSK key exchange is used (as in resumption), knowledge of the PSK
serves to authenticate the peer.

在完成 TLS 握手之后，客户机将学习并验证服务器的身份，并且服务器可选地能够学习并验
证客户机的身份。TLS 支持 X.509 {{?RFC5280}} 服务器和客户端的基于证书的身份验证。
当使用 PSK 密钥交换时（如在恢复中），PSK 的知识用于对对等方进行身份验证。

The TLS key exchange is resistant to tampering by attackers and it produces
shared secrets that cannot be controlled by either participating peer.

TLS 密钥交换能够抵抗攻击者的篡改，并且它产生的共享秘密不能由任何参与的对等方控制。

TLS provides two basic handshake modes of interest to QUIC:

TLS 提供了两种 QUIC 感兴趣的握手模式：

 * A full 1-RTT handshake, in which the client is able to send Application Data
   after one round trip and the server immediately responds after receiving the
   first handshake message from the client.

 * 完整的 1-RTT 握手，客户端能够在一次往返之后发送应用程序数据，服务器在接收到
   客户端的第一个握手消息后立即作出响应。

 * A 0-RTT handshake, in which the client uses information it has previously
   learned about the server to send Application Data immediately.  This
   Application Data can be replayed by an attacker so 0-RTT is not suitable for
   carrying instructions that might initiate any action that could cause
   unwanted effects if replayed.

 * 0-RTT 握手，客户端使用先前从服务端学到的信息立即发送应用程序数据。攻击者可以
   重放此应用程序数据，因此 0-RTT 不适合携带可能启动任何操作的指令，这些操作在
   重放时可能会造成不必要的影响。

A simplified TLS handshake with 0-RTT application data is shown in {{tls-full}}.

{{tls-full}} 显示了使用 0-RTT 应用程序数据的简化版 TLS 握手。

~~~
    Client                                             Server

    ClientHello
   (0-RTT Application Data)  -------->
                                                  ServerHello
                                         {EncryptedExtensions}
                                                    {Finished}
                             <--------      [Application Data]
   {Finished}                -------->

   [Application Data]        <------->      [Application Data]

    () Indicates messages protected by Early Data (0-RTT) Keys
    {} Indicates messages protected using Handshake Keys
    [] Indicates messages protected using Application Data
       (1-RTT) Keys

    () 表示使用 Early Data (0-RTT) 密钥保护的消息
    {} 表示使用握手密钥保护的消息
    [] 表示使用应用数据 (1-RTT) 密钥保护的消息
~~~
{: #tls-full title="TLS Handshake with 0-RTT"}

{{tls-full}} omits the EndOfEarlyData message, which is not used in QUIC; see
{{remove-eoed}}. Likewise, neither ChangeCipherSpec nor KeyUpdate messages are
used by QUIC. ChangeCipherSpec is redundant in TLS 1.3; see {{compat-mode}}.
QUIC has its own key update mechanism; see {{key-update}}.

{{tls-full}} 省略了 EndOfEarlyData 消息， QUIC 没有使用它（见 {{remove-eoed}}）。
同样，QUIC 也不使用 ChangeCipherSpec 和 KeyUpdate 消息。 ChangeCipherSpec 在 TLS 1.3
中是冗余的（见 {{compat-mode}}）。 QUIC 有自己的密钥更新机制（见 {{key-update}}）。

Data is protected using a number of encryption levels:

使用多种加密级别来保护数据：

- Initial Keys
- Early Data (0-RTT) Keys
- Handshake Keys
- Application Data (1-RTT) Keys

- 初始密钥
- Early Data (0-RTT) 密钥
- 握手密钥
- 应用数据 (1-RTT) 密钥

Application Data may appear only in the Early Data and Application Data
levels. Handshake and Alert messages may appear in any level.

应用数据可能只出现在 Early Data 和应用数据级别。握手和警告消息可以出现在任意级别。

The 0-RTT handshake can be used if the client and server have previously
communicated.  In the 1-RTT handshake, the client is unable to send protected
Application Data until it has received all of the Handshake messages sent by the
server.

如果客户端和服务器之前进行过通信，则可以使用 0-RTT 握手。在 1-RTT 握手过程中，
客户端在接收到服务器发送的所有握手消息之前，不能发送受保护的应用数据。

# Protocol Overview - 协议概述

QUIC {{QUIC-TRANSPORT}} assumes responsibility for the confidentiality and
integrity protection of packets.  For this it uses keys derived from a TLS
handshake {{!TLS13}}, but instead of carrying TLS records over QUIC (as with
TCP), TLS Handshake and Alert messages are carried directly over the QUIC
transport, which takes over the responsibilities of the TLS record layer, as
shown in {{quic-layers}}.

QUIC {{QUIC-TRANSPORT}} 负责数据包的机密性和完整性保护。为此，QUIC 只使用
从 TLS 握手过程中 {{!TLS13}} 派生的密钥，且不通过 QUIC 本身传输 TLS 记录
（同 TCP 一样），而是直接通过 QUIC 传输 TLS 握手和警告消息，等于 QUIC 接管
了 TLS 记录层的职责，如下 {{quic-layers}}。

~~~~
+--------------+--------------+ +-------------+
|     TLS      |     TLS      | |    QUIC     |
|  Handshake   |    Alerts    | | Applications|
|              |              | |  (h3, etc.) |
+--------------+--------------+-+-------------+
|                                             |
|                QUIC Transport               |
|   (streams, reliability, congestion, etc.)  |
|                                             |
+---------------------------------------------+
|                                             |
|            QUIC Packet Protection           |
|                                             |
+---------------------------------------------+
~~~~
{: #quic-layers title="QUIC Layers"}

QUIC also relies on TLS for authentication and negotiation of parameters that
are critical to security and performance.

QUIC 还依赖 TLS 来验证和协商对安全和性能至关重要的参数。

Rather than a strict layering, these two protocols cooperate: QUIC uses the TLS
handshake; TLS uses the reliability, ordered delivery, and record layer provided
by QUIC.

这两个协议不是严格分层的，而是相互协作：QUIC 使用 TLS 握手；TLS 使用 QUIC 提供的
可靠性、有序交付和记录层。

At a high level, there are two main interactions between the TLS and QUIC
components:

在高层次上，TLS 和 QUIC 组件之间有两种主要的相互作用：

* The TLS component sends and receives messages via the QUIC component, with
  QUIC providing a reliable stream abstraction to TLS.

* TLS 通过 QUIC 发送和接受消息，QUIC 为 TLS 提供了可靠的流抽象。

* The TLS component provides a series of updates to the QUIC component,
  including (a) new packet protection keys to install (b) state changes such as
  handshake completion, the server certificate, etc.

* TLS 为 QUIC 提供了一系列更新，包括 (a) 设置新的数据包保护密钥 (b) 状态变更，例如
  握手完成、服务端证书等。

{{schematic}} shows these interactions in more detail, with the QUIC packet
protection being called out specially.

{{schematic}} 更详细地展示了这些交互，特意展示了 QUIC 数据包保护。

~~~
+------------+                               +------------+
|            |<---- Handshake Messages ----->|            |
|            |<- Validate 0-RTT parameters ->|            |
|            |<--------- 0-RTT Keys ---------|            |
|    QUIC    |<------- Handshake Keys -------|    TLS     |
|            |<--------- 1-RTT Keys ---------|            |
|            |<------- Handshake Done -------|            |
+------------+                               +------------+
 |         ^
 | Protect | Protected
 v         | Packet
+------------+
|   QUIC     |
|  Packet    |
| Protection |
+------------+
~~~
{: #schematic title="QUIC and TLS Interactions"}

Unlike TLS over TCP, QUIC applications that want to send data do not send it
through TLS "application_data" records. Rather, they send it as QUIC STREAM
frames or other frame types, which are then carried in QUIC packets.

与 TLS over TCP 不同，想要发送数据的 QUIC 应用程序不通过 TLS "application_data" 记录。
相反，它们将其作为 QUIC 的 STREAM 帧或其他帧类型发送，然后封装在 QUIC 数据包中。

# Carrying TLS Messages - 传输 TLS 消息 {#carrying-tls}

QUIC carries TLS handshake data in CRYPTO frames, each of which consists of a
contiguous block of handshake data identified by an offset and length. Those
frames are packaged into QUIC packets and encrypted under the current
encryption level.  As with TLS over TCP, once TLS handshake data has been
delivered to QUIC, it is QUIC's responsibility to deliver it reliably. Each
chunk of data that is produced by TLS is associated with the set of keys that
TLS is currently using.  If QUIC needs to retransmit that data, it MUST use the
same keys even if TLS has already updated to newer keys.

QUIC 在 CRYPTO 帧中携带 TLS 握手数据，每个帧由一个偏移量和长度标识的连续握手数据块
组成。这些帧被打包成 QUIC 数据包，并在当前加密级别下进行加密。与 TCP over TLS 一样，
一旦 TLS 握手数据被传递到 QUIC，QUIC 就有责任可靠地传递它。TLS 生成的每个数据块都
与 TLS 当前使用的密钥集相关联。如果 QUIC 需要重新传输该数据，则必须使用相同的密钥，
即使 TLS 已经更新为较新的密钥。

Each encryption level corresponds to a packet number space. The packet number
space that is used determines the semantics of frames. Some frames are
prohibited in different packet number spaces; see {{Section 12.5 of
QUIC-TRANSPORT}}.

每个加密级别对应一个数据包编号空间。所使用的包编号空间决定帧的语义。
某些帧在不同的包编号空间中被禁止（见 {{Section 12.5 of QUIC-TRANSPORT}}）。

Because packets could be reordered on the wire, QUIC uses the packet type to
indicate which keys were used to protect a given packet, as shown in
{{packet-types-keys}}. When packets of different types need to be sent,
endpoints SHOULD use coalesced packets to send them in the same UDP datagram.

因为数据包在链路上可能被重新排序，所以 QUIC 使用数据包类型来区分哪种密钥保护哪种数据，
如 {{packet-types-keys}} 。当需要发送不同类型的数据包时，端点应使用聚合的数据包
在同一个 UDP 数据报中发送它们。

| Packet Type         | Encryption Keys | PN Space         |
| :------------------ | :-------------- | :--------------- |
| Initial             | Initial secrets | Initial          |
| 0-RTT Protected     | 0-RTT           | Application data |
| Handshake           | Handshake       | Handshake        |
| Retry               | Retry           | N/A              |
| Version Negotiation | N/A             | N/A              |
| Short Header        | 1-RTT           | Application data |
{: #packet-types-keys title="Encryption Keys by Packet Type"}

{{Section 17 of QUIC-TRANSPORT}} shows how packets at the various encryption
levels fit into the handshake process.

{{Section 17 of QUIC-TRANSPORT}} 展示各种加密级别的数据包如何适配握手过程。

## Interface to TLS - TLS 接口

As shown in {{schematic}}, the interface from QUIC to TLS consists of four
primary functions:

如 {{schematic}} ，QUIC 到 TLS 的接口由四个主要的函数组成：

- Sending and receiving handshake messages
- Processing stored transport and application state from a resumed session
  and determining if it is valid to generate or accept early data
- Rekeying (both transmit and receive)
- Handshake state updates

- 发送和接受握手消息
- 处理从恢复会话中保存的传输和应用状态，并确定生成或接受早期数据是否有效
- 更新密钥（包括发送和接受）
- 握手状态更新

Additional functions might be needed to configure TLS.  In particular, QUIC and
TLS need to agree on which is responsible for validation of peer credentials,
such as certificate validation ({{?RFC5280}}).

配置 TLS 可能需要额外的函数。特别是，QUIC 和 TLS 需要就谁负责对等凭据的验证达成一致，
比如证书验证 ({{?RFC5280}}) 。

### Handshake Complete - 握手完成 {#handshake-complete}

In this document, the TLS handshake is considered complete when the TLS stack
has reported that the handshake is complete.  This happens when the TLS stack
has both sent a Finished message and verified the peer's Finished message.
Verifying the peer's Finished provides the endpoints with an assurance that
previous handshake messages have not been modified.  Note that the handshake
does not complete at both endpoints simultaneously.  Consequently, any
requirement that is based on the completion of the handshake depends on the
perspective of the endpoint in question.

在本文中，当 TLS 堆栈报告握手已完成时，TLS 握手被认为已完成。当 TLS 堆栈既发送了
已完成的消息，又验证了对等方的已完成消息时，就会发生这种情况。验证对等方的完成为
端点提供了一个保证，即先前的握手消息没有被修改。请注意，握手不会在两个端点同时完成。
因此，基于握手完成的任何需求都取决于所讨论的端点的视角。

### Handshake Confirmed - 握手确认 {#handshake-confirmed}

In this document, the TLS handshake is considered confirmed at the server when
the handshake completes.  The server MUST send a HANDSHAKE_DONE frame as soon as
the handshake is complete.  At the client, the handshake is considered confirmed
when a HANDSHAKE_DONE frame is received.

在本文中，TLS 握手被认为是在握手完成时在服务器上确认的。一旦握手完成，服务器必须
发送 HANDSHAKE_DONE 帧。在客户端，当收到 HANDSHAKE_DONE帧 时，认为握手已确认。

Additionally, a client MAY consider the handshake to be confirmed when it
receives an acknowledgment for a 1-RTT packet.  This can be implemented by
recording the lowest packet number sent with 1-RTT keys, and comparing it to the
Largest Acknowledged field in any received 1-RTT ACK frame: once the latter is
greater than or equal to the former, the handshake is confirmed.

另外，客户端可以认为握手已经被确认，当客户端收到 1-RTT 数据包的确认时。这可以通过
记录用 1-RTT 密钥发送的最小数据包号来实现，并将其与任何接收到的 1-RTT ACK 帧中的
最大确认字段进行比较：一旦后者大于或等于前者，则确认握手。

### Sending and Receiving Handshake Messages - 发送和接收握手消息

In order to drive the handshake, TLS depends on being able to send and receive
handshake messages. There are two basic functions on this interface: one where
QUIC requests handshake messages and one where QUIC provides bytes that comprise
handshake messages.

TLS 依赖发送和接收握手消息来驱动握手。该接口上有两个基本功能：一个在 QUIC 请求
握手消息，另一个在 QUIC 提供构成握手消息的字节。

Before starting the handshake QUIC provides TLS with the transport parameters
(see {{quic_parameters}}) that it wishes to carry.

在握手开始之前，QUIC 向 TLS 提供它希望携带的传输参数（见 {{quic_parameters}}）。

A QUIC client starts TLS by requesting TLS handshake bytes from TLS.  The client
acquires handshake bytes before sending its first packet.  A QUIC server starts
the process by providing TLS with the client's handshake bytes.

QUIC 客户端通过 TLS 请求 TLS 握手字节来启动 TLS。客户端在发送第一个数据包之前
获取握手字节。QUIC 服务器通过向 TLS 提供客户端的握手字节来启动这个过程。

At any time, the TLS stack at an endpoint will have a current sending
encryption level and receiving encryption level. TLS encryption levels determine
the QUIC packet type and keys that are used for protecting data.

在任何时候，任意端点的 TLS 堆栈都将具有当前的发送加密级别和接收加密级别。 TLS 加密级
别确定 QUIC 数据包类型和用于保护数据的密钥。

Each encryption level is associated with a different sequence of bytes, which is
reliably transmitted to the peer in CRYPTO frames. When TLS provides handshake
bytes to be sent, they are appended to the handshake bytes for the current
encryption level. The encryption level then determines the type of packet that
the resulting CRYPTO frame is carried in; see {{packet-types-keys}}.

每个加密级别与不同的字节序列关联，并在 CRYPTO 帧中可靠的传输到对端。当 TLS 提供要发送的
握手字节时，会将它们附加到当前加密级别的握手字节中。然后，加密级别决定携带 CRYPTO 帧的
数据包类型（见 {{packet-types-keys}}）。

Four encryption levels are used, producing keys for Initial, 0-RTT, Handshake,
and 1-RTT packets. CRYPTO frames are carried in just three of these levels,
omitting the 0-RTT level. These four levels correspond to three packet number
spaces: Initial and Handshake encrypted packets use their own separate spaces;
0-RTT and 1-RTT packets use the application data packet number space.

使用四种加密级别，为 Initial、0-RTT、Handshake、1-RTT 数据包生成密钥。 CRYPTO 帧只出现
在三个级别，省略了 0-RTT 级别。这四个级别对应于三个数据包编号空间：Initial 和 Handshake 加
密的数据包使用各自独立的空间；0-RTT 和 1-RTT 数据包使用应用程序数据包编号空间。

QUIC takes the unprotected content of TLS handshake records as the content of
CRYPTO frames. TLS record protection is not used by QUIC. QUIC assembles
CRYPTO frames into QUIC packets, which are protected using QUIC packet
protection.

QUIC 把 TLS 握手记录中不受保护的内容作为 CRYPTO 帧的内容。QUIC 没有使用 TLS 记录保护。
QUIC 将 CRYPTO 帧封装到 QUIC 数据包中，使用 QUIC 包保护来保护。

QUIC CRYPTO frames only carry TLS handshake messages.  TLS
alerts are turned into QUIC CONNECTION_CLOSE error codes; see {{tls-errors}}.
TLS application data and other content types cannot be carried by QUIC at any
encryption level; it is an error if they are received from the TLS stack.

QUIC CRYPTO 帧只用于传输 TLS 握手消息。TLS 警告被转换成了 QUIC CONNECTION_CLOSE 帧的
错误代码（见 {{tls-errors}}）。TLS 应用数据以及其他内容不能传输，在 QUIC 任意加密级别；
如果它们是从 TLS 堆栈接收到的，则是错误的。

When an endpoint receives a QUIC packet containing a CRYPTO frame from the
network, it proceeds as follows:

当端点从网络上接收到一个包含 CRYPTO 帧的 QUIC 数据包时，处理过程如下：

- If the packet uses the current TLS receiving encryption level, sequence the
  data into the input flow as usual. As with STREAM frames, the offset is used
  to find the proper location in the data sequence.  If the result of this
  process is that new data is available, then it is delivered to TLS in order.

- 如果数据包使用当前的 TLS 接收加密级别，请照常将数据排序到输入流中。与 STREAM 帧
  一样，偏移量用于在数据序列中找到合适的位置。如果此过程的结果是有新数据可用，则
  将按顺序传送到 TLS。

- If the packet is from a previously installed encryption level, it MUST NOT
  contain data that extends past the end of previously received data in that
  flow. Implementations MUST treat any violations of this requirement as a
  connection error of type PROTOCOL_VIOLATION.

- 如果数据包来自先前安装的加密级别，则它不得包含超出该流中先前接收数据结尾的数据。
  实现必须将任何违反此要求的行为视为违反协议类型的连接错误。

- If the packet is from a new encryption level, it is saved for later processing
  by TLS.  Once TLS moves to receiving from this encryption level, saved data
  can be provided to TLS.  When TLS provides keys for a higher encryption level,
  if there is data from a previous encryption level that TLS has not consumed,
  this MUST be treated as a connection error of type PROTOCOL_VIOLATION.

- 如果数据包来自新的加密级别，它会被保存起由 TLS 延迟处理。一旦 TLS 从加密级别
  转移到接收状态，便可以将保存的数据提供给 TLS。当 TLS 为更高的加密级别提供密钥时，
  如果有来自 TLS 尚未使用的先前加密级别的数据，则必须将其视为 PROTOCOL_VIOLATION 类型
  的连接错误。

Each time that TLS is provided with new data, new handshake bytes are requested
from TLS.  TLS might not provide any bytes if the handshake messages it has
received are incomplete or it has no data to send.

每次为 TLS 提供新数据时，都会从 TLS 请求新的握手字节。如果已收到的握手消息不完整
或没有要发送的数据，则 TLS 可能不会提供任何字节。

The content of CRYPTO frames might either be processed incrementally by TLS or
buffered until complete messages or flights are available.  TLS is responsible
for buffering handshake bytes that have arrived in order.  QUIC is responsible
for buffering handshake bytes that arrive out of order or for encryption levels
that are not yet ready.  QUIC does not provide any means of flow control for
CRYPTO frames; see {{Section 7.5 of QUIC-TRANSPORT}}.

CRYPTO 帧的内容可以通过 TLS 进行增量处理，也可以进行缓冲，直到获得完整的消息或
传输为止。TLS 负责缓冲按顺序到达的握手字节。 QUIC 负责缓冲乱序到达的握手字节或尚未准备好的加密级别。
QUIC 不提供任何用于 CRYPTO 帧的流控制的方法（{{Section 7.5 of QUIC-TRANSPORT}}）。

Once the TLS handshake is complete, this is indicated to QUIC along with any
final handshake bytes that TLS needs to send.  At this stage, the transport
parameters that the peer advertised during the handshake are authenticated;
see {{quic_parameters}}.

一旦 TLS 握手完成，会将其与 TLS 需要发送的所有最终握手字节一起指示给 QUIC。
在此阶段，对端在握手期间通告的传输参数得到认证。

Once the handshake is complete, TLS becomes passive.  TLS can still receive data
from its peer and respond in kind, but it will not need to send more data unless
specifically requested - either by an application or QUIC.  One reason to send
data is that the server might wish to provide additional or updated session
tickets to a client.

只要握手完成，TLS 就会变成被动状态。TLS 依然可以从对端接收数据并响应，除非应用程序
或 QUIC 明确要求，否则它无需发送更多数据。发送数据的一个原因是服务器可能希望向客户端
提供其他或更新 session tickets 。

When the handshake is complete, QUIC only needs to provide TLS with any data
that arrives in CRYPTO streams.  In the same manner that is used during the
handshake, new data is requested from TLS after providing received data.

当握手完成的时候，QUIC 只需要向 TLS 提供 CYPTO 流中的任意数据。与握手期间相同的方式，
在提供接收到的数据之后，从 TLS 请求新的数据。

### Encryption Level Changes - 加密级别改变

As keys at a given encryption level become available to TLS, TLS indicates to
QUIC that reading or writing keys at that encryption level are available.

当给定加密级别的密钥可供 TLS 使用时，TLS 向 QUIC 指示可在该加密级别读取或写入密钥。

The availability of new keys is always a result of providing inputs to TLS.  TLS
only provides new keys after being initialized (by a client) or when provided
with new handshake data.

新密钥的可用性始终是向 TLS 提供输入的结果。TLS 仅在初始化（由客户端）或提供新的握手
数据后提供新密钥。

However, a TLS implementation could perform some of its processing
asynchronously. In particular, the process of validating a certificate can take
some time. While waiting for TLS processing to complete, an endpoint SHOULD
buffer received packets if they might be processed using keys that aren't yet
available. These packets can be processed once keys are provided by TLS. An
endpoint SHOULD continue to respond to packets that can be processed during this
time.

但是，TLS 实现可以异步执行其某些处理。特别是，验证证书的过程可能需要一些时间。
在等待 TLS 处理完成时，如果可能使用尚不可用的密钥来处理它们，则端点应该缓冲接收
到的数据包。 TLS 提供密钥后即可处理这些数据包。端点应该继续响应在这段时间内可以
处理的数据包。

After processing inputs, TLS might produce handshake bytes, keys for new
encryption levels, or both.

在处理输入之后， TLS 可能会生成握手字节，或是用于新加密级别的密钥，或者两者都生成。

TLS provides QUIC with three items as a new encryption level becomes available:

随着新的加密级别变得可用，TLS 向 QUIC 提供了三项：

* A secret

* An Authenticated Encryption with Associated Data (AEAD) function

* A Key Derivation Function (KDF)

* 一个秘密

* 一个具有关联数据的身份验证加密 (AEAD) 函数

* 一个密钥派生函数

These values are based on the values that TLS negotiates and are used by QUIC to
generate packet and header protection keys; see {{packet-protection}} and
{{header-protect}}.

这些值是基于 TLS 协商出来的值，被 QUIC 用来生成数据包和包头保护密钥
（见 {{packet-protection}} 和 {{header-protect}}）。

If 0-RTT is possible, it is ready after the client sends a TLS ClientHello
message or the server receives that message.  After providing a QUIC client with
the first handshake bytes, the TLS stack might signal the change to 0-RTT
keys. On the server, after receiving handshake bytes that contain a ClientHello
message, a TLS server might signal that 0-RTT keys are available.

如果可以使用 0-RTT ，在客户端发送 TLS ClientHello 消息或者服务端收到该消息之后，
客户端就准备好了。在向 QUIC 客户端提供第一个握手字节后，TLS 堆栈可能会向 0-RTT 密钥
发出更改信号。在服务器上，在接收到包含 ClientHello 消息的握手字节后，TLS 服务器可能
会发出 0-RTT 密钥可用的信号。

Although TLS only uses one encryption level at a time, QUIC may use more than
one level. For instance, after sending its Finished message (using a CRYPTO
frame at the Handshake encryption level) an endpoint can send STREAM data (in
1-RTT encryption). If the Finished message is lost, the endpoint uses the
Handshake encryption level to retransmit the lost message.  Reordering or loss
of packets can mean that QUIC will need to handle packets at multiple encryption
levels.  During the handshake, this means potentially handling packets at higher
and lower encryption levels than the current encryption level used by TLS.

虽然， TLS 一次只使用一个加密级别， 但 QUIC 可以使用多个加密级别。例如，在发送完成
消息（使用握手加密级别的 CRYPTO 帧）之后，端点可以发送 STREAM 数据（1-RTT 加密）。
如果完成消息丢失了，端点可以使用握手加密级别重传丢失的消息。数据包的重新排序或丢失
意味着 QUIC 需要在多个加密级别上处理数据包。在握手期间，意味着要在比当前 TLS 使用的
加密级别更高和更低的加密级别来处理数据包。

In particular, server implementations need to be able to read packets at the
Handshake encryption level at the same time as the 0-RTT encryption level.  A
client could interleave ACK frames that are protected with Handshake keys with
0-RTT data and the server needs to process those acknowledgments in order to
detect lost Handshake packets.

特别地，服务端实现需要能够在 0-RTT、Handshake 加密级别同时读取数据包。客户端可以
将受握手密钥保护的 ACK 帧与 0-RTT 数据交织在一起，服务端需要处理这些确认以检测丢失的
握手数据包。

QUIC also needs access to keys that might not ordinarily be available to a TLS
implementation.  For instance, a client might need to acknowledge Handshake
packets before it is ready to send CRYPTO frames at that encryption level.  TLS
therefore needs to provide keys to QUIC before it might produce them for its own
use.

QUIC 还需要访问 TLS 实现通常不可用的密钥。例如，客户端可能需要确认握手数据包，然后才能
准备在该加密级别发送 CRYPTO 帧。因此，TLS 需要在 QUIC 生成密钥供自己使用之前向 QUIC 提
供密钥。

### TLS Interface Summary - TLS 接口概要

{{exchange-summary}} summarizes the exchange between QUIC and TLS for both
client and server. Solid arrows indicate packets that carry handshake data;
dashed arrows show where application data can be sent.  Each arrow is tagged
with the encryption level used for that transmission.

{{exchange-summary}} 总结了客户端和服务器的 QUIC 和 TLS 之间的交换。实线箭头表示携带握手
数据的数据包；虚线箭头表示可以将应用程序数据发送到的位置。每个箭头都标记有用于该传输的加
密级别。

~~~
Client                                                    Server
======                                                    ======

Get Handshake
                     Initial ------------->
Install tx 0-RTT Keys
                     0-RTT - - - - - - - ->

                                              Handshake Received
                                                   Get Handshake
                     <------------- Initial
                                           Install rx 0-RTT keys
                                          Install Handshake keys
                                                   Get Handshake
                     <----------- Handshake
                                           Install tx 1-RTT keys
                     <- - - - - - - - 1-RTT

Handshake Received (Initial)
Install Handshake keys
Handshake Received (Handshake)
Get Handshake
                     Handshake ----------->
Handshake Complete
Install 1-RTT keys
                     1-RTT - - - - - - - ->

                                              Handshake Received
                                              Handshake Complete
                                             Handshake Confirmed
                                           Install rx 1-RTT keys
                     <--------------- 1-RTT
                           (HANDSHAKE_DONE)
Handshake Confirmed
~~~
{: #exchange-summary title="Interaction Summary between QUIC and TLS"}

{{exchange-summary}} shows the multiple packets that form a single "flight" of
messages being processed individually, to show what incoming messages trigger
different actions. This shows multiple "Get Handshake" invocations to retrieve
handshake messages at different encryption levels. New handshake messages are
requested after incoming packets have been processed.

{{exchange-summary}} 展示了形成单个"传输中"消息的多个数据包，这些消息被单独处理，
以显示哪些传入消息触发了不同的操作；这显示了多个 "Get Handshake" 调用，以不同的
加密级别检索了握手消息。在处理完收到的数据包之后请求新的握手消息。

{{exchange-summary}} shows one possible structure for a simple handshake
exchange. The exact process varies based on the structure of endpoint
implementations and the order in which packets arrive. Implementations could
use a different number of operations or execute them in other orders.

{{exchange-summary}} 显示了一个简单握手交换的可行的结构。具体的过程根据端点实现的
结构和数据包到达的顺序而有所不同。实现可以使用不同数量的操作或以其他顺序执行它们。

## TLS Version - TLS 版本 {#tls-version}

This document describes how TLS 1.3 {{!TLS13}} is used with QUIC.

文档介绍如何一起使用 TLS1.3 {{!TLS13}} 与 QUIC。

In practice, the TLS handshake will negotiate a version of TLS to use.  This
could result in a newer version of TLS than 1.3 being negotiated if both
endpoints support that version.  This is acceptable provided that the features
of TLS 1.3 that are used by QUIC are supported by the newer version.

实际上，TLS 握手会协商要使用的 TLS 版本。如果两端都支持 TLS，则可能会协商出比 1.3 更
高的 TLS 版本。如果新版本支持 QUIC 使用的 TLS 1.3 功能，则这是可以接受的。

Clients MUST NOT offer TLS versions older than 1.3.  A badly configured TLS
implementation could negotiate TLS 1.2 or another older version of TLS.  An
endpoint MUST terminate the connection if a version of TLS older than 1.3 is
negotiated.

客户端不得提供比 1.3 更低的 TLS 版本。配置错误的 TLS 可能会协商 TLS1.2 或其他较旧
的 TLS 版本。如果协商的 TLS 版本低于 1.3，则端点必须终止连接。

## ClientHello Size - ClientHello 大小 {#clienthello-size}

The first Initial packet from a client contains the start or all of its first
cryptographic handshake message, which for TLS is the ClientHello.  Servers
might need to parse the entire ClientHello (e.g., to access extensions such as
Server Name Identification (SNI) or Application Layer Protocol Negotiation
(ALPN)) in order to decide whether to accept the new incoming QUIC connection.
If the ClientHello spans multiple Initial packets, such servers would need to
buffer the first received fragments, which could consume excessive resources if
the client's address has not yet been validated.  To avoid this, servers MAY
use the Retry feature (see {{Section 8.1 of QUIC-TRANSPORT}}) to only buffer
partial ClientHello messages from clients with a validated address.

从客户端收到的第一个 Initial 数据包，它包含第一个加密握手消息的开始部分或全部，
对于 TLS 来说，它是 ClientHello。服务器可能需要解析整个 ClientHello（例如，访问诸如
服务器名称标识 (SNI) 或应用层协议协商 (ALPN) 之类的扩展），以便决定是否接受新的 QUIC 连接。
如果 ClientHello 跨越多个 Initial 数据包，那么服务器将需要缓冲第一个接收到的片段，如果
客户端的地址还没有被验证，这可能会消耗过多的资源。为了避免这种情况，服务器可以使用重试特性
（见 {{Section 8.1 of QUIC-TRANSPORT}}）只缓冲来自已验证地址的客户端的部分 ClientHello 消息。

QUIC packet and framing add at least 36 bytes of overhead to the ClientHello
message.  That overhead increases if the client chooses a source connection ID
longer than zero bytes.  Overheads also do not include the token or a
destination connection ID longer than 8 bytes, both of which might be required
if a server sends a Retry packet.

QUIC 数据包和帧至少给 Clientello 消息添加 36 字节的开销。如果客户端选择的源连接 ID 大于
零字节，则开销还会增加。开销还不包括令牌或超过 8 字节的目标连接 ID，如果服务器发送重试
数据包，这两个字节都可能需要。

A typical TLS ClientHello can easily fit into a 1200-byte packet.  However, in
addition to the overheads added by QUIC, there are several variables that could
cause this limit to be exceeded.  Large session tickets, multiple or large key
shares, and long lists of supported ciphers, signature algorithms, versions,
QUIC transport parameters, and other negotiable parameters and extensions could
cause this message to grow.

一个典型的 TLS ClientHello 可以很容易地放入一个 1200 字节的数据包中。然而，除了 QUIC 增加的
管理开销外，还有几个变量可能导致超过这一限制。大的会话票、多个或大的密钥共享、支持的密码、
签名算法、版本、QUIC 传输参数以及其他可协商参数和扩展的长列表都可能会导致此消息的开销增加。

For servers, in addition to connection IDs and tokens, the size of TLS session
tickets can have an effect on a client's ability to connect efficiently.
Minimizing the size of these values increases the probability that clients can
use them and still fit their entire ClientHello message in their first Initial
packet.

对于服务器，除了连接 ID 和令牌之外，TLS 会话票的大小还可能影响客户端高效连接的能力。
最小化这些值的大小会增加客户机可以使用它们并且仍然将其整个 ClientHello 消息放在第一个
初始数据包中的可能性。

The TLS implementation does not need to ensure that the ClientHello is large
enough to meet QUIC's requirements for datagrams that carry Initial packets; see
{{Section 14.1 of QUIC-TRANSPORT}}. QUIC implementations use PADDING frames or
packet coalescing to ensure that datagrams are large enough.

TLS 实现不需要确保 ClientHello 足够大以满足 QUIC 对携带初始数据包的数据报的要求
（{{Section 14.1 of QUIC-TRANSPORT}}）。QUIC 实现使用 PADDING 帧或包合并来确保数据报足够大。

## Peer Authentication - 身份验证

The requirements for authentication depend on the application protocol that is
in use.  TLS provides server authentication and permits the server to request
client authentication.

身份验证的要求取决于正在使用的应用程序协议。TLS 提供服务器身份验证，并允许服务器
请求客户端身份验证。

A client MUST authenticate the identity of the server.  This typically involves
verification that the identity of the server is included in a certificate and
that the certificate is issued by a trusted entity (see for example
{{?RFC2818}}).

客户端必须验证服务器的身份。这通常涉及验证服务器的身份是否包含在证书中以及证书是否
由受信任实体颁发（见 {{?RFC2818}}）。

Note:

: Where servers provide certificates for authentication, the size of
  the certificate chain can consume a large number of bytes.  Controlling the
  size of certificate chains is critical to performance in QUIC as servers are
  limited to sending 3 bytes for every byte received prior to validating the
  client address; see {{Section 8.1 of QUIC-TRANSPORT}}.  The size of a
  certificate chain can be managed by limiting the number of names or
  extensions; using keys with small public key representations, like ECDSA; or
  by using certificate compression
  {{?COMPRESS=I-D.ietf-tls-certificate-compression}}.

注意:

: 当服务器提供用于身份验证的证书时，证书链的大小可能会消耗大量字节。控制证书链的大小
  对 QUIC 的性能至关重要，因为在验证客户机地址之前，服务器只能为接收到的每个字节发送
  3 个字节（{{Section 8.1 of QUIC-TRANSPORT}}）。证书链的大小可以通过以下方式进行管理：
  限制名称或扩展名的数量；使用具有较小公钥表示形式的密钥（比如 ECDSA）；或者使用证书压缩
  （{{?COMPRESS=I-D.ietf-tls-certificate-compression}}）。

A server MAY request that the client authenticate during the handshake. A server
MAY refuse a connection if the client is unable to authenticate when requested.
The requirements for client authentication vary based on application protocol
and deployment.

服务器可以在握手期间请求客户端认证。如果客户端不能在请求时进行认证，则服务器可以拒绝连接。
客户端身份验证的要求因应用程序协议和部署而异。

A server MUST NOT use post-handshake client authentication (as defined in
{{Section 4.6.2 of TLS13}}), because the multiplexing offered by QUIC prevents
clients from correlating the certificate request with the application-level
event that triggered it (see {{?HTTP2-TLS13=RFC8740}}).
More specifically, servers MUST NOT send post-handshake TLS CertificateRequest
messages and clients MUST treat receipt of such messages as a connection error
of type PROTOCOL_VIOLATION.

服务器不得使用握手后客户端身份验证（如 {{Section 4.6.2 of TLS13}} 中所定义），因为 QUIC 提供的
多路复用阻止客户端将证书请求与触发该请求的应用程序级事件相关联（见 {{?HTTP2-TLS13=RFC8740}}）。
更具体地说，服务器不得发送握手后的 TLS 证书请求消息，客户端必须将此类消息的接收视为
PROTOCOL_VIOLATION 类型的连接错误。

## Session Resumption - 会话恢复 {#resumption}

QUIC can use the session resumption feature of TLS 1.3. It does this by
carrying NewSessionTicket messages in CRYPTO frames after the handshake is
complete. Session resumption can be used to provide 0-RTT, and can also be
used when 0-RTT is disabled.

QUIC 可以使用 TLS 1.3 的会话恢复功能。它通过在握手完成后在 CRYPTO 帧中携带
NewSessionTicket 消息来完成此操作。会话恢复可用于提供 0-RTT，也可以在禁用 0-RTT 时使用。

Endpoints that use session resumption might need to remember some information
about the current connection when creating a resumed connection. TLS requires
that some information be retained; see {{Section 4.6.1 of TLS13}}. QUIC itself
does not depend on any state being retained when resuming a connection, unless
0-RTT is also used; see {{Section 7.4.1 of QUIC-TRANSPORT}} and
{{enable-0rtt}}. Application protocols could depend on state that is retained
between resumed connections.

使用会话恢复的端点在创建恢复的连接时可能需要记住一些有关当前连接的信息。TLS 要求保留一些
信息（{{Section 4.6.1 of TLS13}}）。除非也使用 0-RTT，否则 QUIC 本身不依赖于恢复连接时
保留的任何状态（见 {{Section 7.4.1 of QUIC-TRANSPORT}} 和 {{enable-0rtt}}）。应用程序协议
可能取决于恢复的连接之间保留的状态。

Clients can store any state required for resumption along with the session
ticket. Servers can use the session ticket to help carry state.

客户端可以将恢复状态所需的任何状态与会话票证一起存储。服务器可以使用会话票证来帮助保持状态。

Session resumption allows servers to link activity on the original connection
with the resumed connection, which might be a privacy issue for clients.
Clients can choose not to enable resumption to avoid creating this correlation.
Clients SHOULD NOT reuse tickets as that allows entities other than the server
to correlate connections; see {{Section C.4 of TLS13}}.

会话恢复允许服务器将原始连接上的活动与恢复的连接链接起来，这可能是客户端的隐私问题。客户可以
选择不启用恢复以避免创建此关联。客户端不应该重复使用票据，因为它允许服务器以外的实体关联连接
（见 {{Section C.4 of TLS13}}）。

## 0-RTT

The 0-RTT feature in QUIC allows a client to send application data before the
handshake is complete.  This is made possible by reusing negotiated parameters
from a previous connection.  To enable this, 0-RTT depends on the client
remembering critical parameters and providing the server with a TLS session
ticket that allows the server to recover the same information.

QUIC 中的 0-RTT 特性允许客户端在握手完成之前发送应用层数据。这可以通过重用以前连接中协商的
参数来实现。为了实现这一点，0-RTT 依赖于客户端记住关键参数并向服务器提供 TLS 会话票证，该票证
允许服务器恢复相同的信息。

This information includes parameters that determine TLS state, as governed by
{{!TLS13}}, QUIC transport parameters, the chosen application protocol, and any
information the application protocol might need; see {{app-0rtt}}.  This
information determines how 0-RTT packets and their contents are formed.

这个信息包括确定 TLS 状态的参数（见 {{!TLS13}}），QUIC 传输参数，所选的应用层协议
以及应用层协议可能需要的信息（见 {{app-0rtt}}）。此信息决定如何产生 0-RTT 数据包及其内容。

To ensure that the same information is available to both endpoints, all
information used to establish 0-RTT comes from the same connection.  Endpoints
cannot selectively disregard information that might alter the sending or
processing of 0-RTT.

为了确保两个端点都可以使用相同的信息，用于建立 0-RTT 的所有信息都来自同一个连接。端点
不能选择性地忽略可能改变 0-RTT 的发送或处理的信息。

{{!TLS13}} sets a limit of 7 days on the time between the original connection
and any attempt to use 0-RTT.  There are other constraints on 0-RTT usage,
notably those caused by the potential exposure to replay attack; see {{replay}}.

{{!TLS13}} 将原始连接与任何尝试使用 0-RTT 之间的时间限制为 7 天。对 0-RTT 的使用还有
其他限制，特别是那些可能暴露于重放攻击的限制（见 {{replay}}）。

### Enabling 0-RTT - 启用 0-RTT {#enable-0rtt}

The TLS "early_data" extension in the NewSessionTicket message is defined
to convey (in the "max_early_data_size" parameter) the amount of TLS 0-RTT
data the server is willing to accept.  QUIC does not use TLS 0-RTT data.
QUIC uses 0-RTT packets to carry early data.  Accordingly, the
"max_early_data_size" parameter is repurposed to hold a sentinel value
0xffffffff to indicate that the server is willing to accept QUIC 0-RTT data;
to indicate that the server does not accept 0-RTT data, the "early_data"
extension is omitted from the NewSessionTicket.
The amount of data that the client can send in QUIC 0-RTT is
controlled by the initial_max_data transport parameter supplied by the server.

NewSessionTicket 消息中的 TLS "early_data" 扩展定义为（在 "max_early_data_size" 参数中）
传递服务器愿意接受的 TLS 0-RTT 数据量。QUIC 不使用 TLS 0-RTT 数据。QUIC 使用 0-RTT 数据包
来传送早期数据。因此，"max_early_data_size" 参数被重新调整用途，以保持哨兵值 0xffffffff ，
以指示服务器愿意接受 QUIC 0-RTT 数据；为了指示服务器不接受 0-RTT 数据，NewSessionTicket 中
的 "early_data" 扩展是被忽略的。客户端在 QUIC 0-RTT 中可以发送的数据量由服务器
提供的 initial_max_data 传输参数控制。

Servers MUST NOT send the early_data extension with a max_early_data_size field
set to any value other than 0xffffffff.  A client MUST treat receipt of a
NewSessionTicket that contains an early_data extension with any other value as
a connection error of type PROTOCOL_VIOLATION.

服务器不得发送将 max_early_data_size 字段设置为 0xffffffff 以外的任何值的 early_data 扩展。
客户端必须将包含带有任何其他值的 early_data 扩展的 NewSessionTicket 的接收
视为 PROTOCOL_VIOLATION 类型的连接错误。

A client that wishes to send 0-RTT packets uses the early_data extension in the
ClientHello message of a subsequent handshake; see {{Section 4.2.10 of TLS13}}.
It then sends application data in 0-RTT packets.

希望发送 0-RTT 数据包的客户端在后续握手的 ClientHello 消息中使用 early_data 扩展
（见 {{Section 4.2.10 of TLS13}}）。然后，它以 0-RTT 数据包的形式发送应用程序数据。

A client that attempts 0-RTT might also provide an address validation token if
the server has sent a NEW_TOKEN frame; see {{Section 8.1 of QUIC-TRANSPORT}}.

如果服务器发送了 NEW_TOKEN 帧，则尝试 0-RTT 的客户端也可能提供地址验证令牌
（见 {{Section 8.1 of QUIC-TRANSPORT}}）。

### Accepting and Rejecting 0-RTT - 接受和拒绝 0-RTT

A server accepts 0-RTT by sending an early_data extension in the
EncryptedExtensions; see {{Section 4.2.10 of TLS13}}.  The server then
processes and acknowledges the 0-RTT packets that it receives.

服务器通过在 EncryptedExtensions 中发送 early_data 扩展来接受 0-RTT
（见 {{Section 4.2.10 of TLS13}}）。然后，服务器处理并确认收到的 0-RTT 数据包。

A server rejects 0-RTT by sending the EncryptedExtensions without an early_data
extension.  A server will always reject 0-RTT if it sends a TLS
HelloRetryRequest.  When rejecting 0-RTT, a server MUST NOT process any 0-RTT
packets, even if it could.  When 0-RTT was rejected, a client SHOULD treat
receipt of an acknowledgment for a 0-RTT packet as a connection error of type
PROTOCOL_VIOLATION, if it is able to detect the condition.

服务器通过发送不包含 early_data 扩展的 EncryptedExtensions 拒绝 0-RTT。如果服务器
发送 TLS HelloRetryRequest，它将始终拒绝 0-RTT。拒绝 0-RTT 时，即使可以，服务器也
不得处理任何 0-RTT 数据包。当 0-RTT 被拒绝时，如果客户端能够检测到条件，则应该将
收到 0-RTT 包的确认消息视为 PROTOCOL_VIOLATION 类型的连接错误。

When 0-RTT is rejected, all connection characteristics that the client assumed
might be incorrect.  This includes the choice of application protocol, transport
parameters, and any application configuration.  The client therefore MUST reset
the state of all streams, including application state bound to those streams.

拒绝 0-RTT 时，客户端假定的所有连接特征可能都不正确。这包括应用程序协议，传输参数
和任何应用程序配置的选择。因此，客户端必须重置所有流的状态，包括绑定到这些流的应用
程序状态。

A client MAY reattempt 0-RTT if it receives a Retry or Version Negotiation
packet.  These packets do not signify rejection of 0-RTT.

如果客户端收到重试或版本协商包，则可以重新尝试 0-RTT。这些数据包不表示拒绝 0-RTT。

### Validating 0-RTT Configuration - 验证 0-RTT 配置 {#app-0rtt}

When a server receives a ClientHello with the early_data extension, it has to
decide whether to accept or reject early data from the client. Some of this
decision is made by the TLS stack (e.g., checking that the cipher suite being
resumed was included in the ClientHello; see {{Section 4.2.10 of TLS13}}). Even
when the TLS stack has no reason to reject early data, the QUIC stack or the
application protocol using QUIC might reject early data because the
configuration of the transport or application associated with the resumed
session is not compatible with the server's current configuration.

服务器收到扩展为 early_data 的 ClientHello 时，必须决定是接受还是拒绝来自客户端的
早期数据。某些决定是由 TLS 堆栈决定的（例如，检查 ClientHello 中是否包含要恢复的
密码套件；见 {{Section 4.2.10 of TLS13}}）。即使 TLS 堆栈没有理由拒绝早期数据，
QUIC 堆栈或使用 QUIC 的应用程序协议也可能拒绝早期数据，因为与恢复的会话关联的传输
或应用程序的配置与服务器的当前配置不兼容。

QUIC requires additional transport state to be associated with a 0-RTT session
ticket. One common way to implement this is using stateless session tickets and
storing this state in the session ticket. Application protocols that use QUIC
might have similar requirements regarding associating or storing state. This
associated state is used for deciding whether early data must be rejected. For
example, HTTP/3 ({{QUIC-HTTP}}) settings determine how early data from the
client is interpreted. Other applications using QUIC could have different
requirements for determining whether to accept or reject early data.

QUIC 要求将其他传输状态与 0-RTT 会话票证相关联。 实现此目的的一种常用方法是使用无
状态会话票证，并将此状态存储在会话票证中。使用 QUIC 的应用程序协议可能在关联或存储
状态方面有相似的要求。此关联状态用于确定是否必须拒绝早期数据。例如，HTTP/3（{{QUIC-HTTP}}）的
设置决定如何解释来自客户端的早期数据。使用 QUIC 的其他应用程序可能对确定是接受还是
拒绝早期数据有不同的要求。

## HelloRetryRequest

The HelloRetryRequest message (see {{Section 4.1.4 of TLS13}}) can be used to
request that a client provide new information, such as a key share, or to
validate some characteristic of the client.  From the perspective of QUIC,
HelloRetryRequest is not differentiated from other cryptographic handshake
messages that are carried in Initial packets. Although it is in principle
possible to use this feature for address verification, QUIC implementations
SHOULD instead use the Retry feature; see {{Section 8.1 of QUIC-TRANSPORT}}.

HelloRetryRequest 消息（见 {{Section 4.1.4 of TLS13}}）可以用来要求客户端提供
新的信息（例如密钥共享）或验证客户端的某些特性。从 QUIC 的角度来看，HelloRetryRequest
与 Initial 数据包中携带的其他加密握手消息没有区别。尽管原则上可以使用此功能进行
地址验证，但 QUIC 实现应改为使用重试功能（见 {{Section 8.1 of QUIC-TRANSPORT}}）。

## TLS Errors - TLS 错误 {#tls-errors}

If TLS experiences an error, it generates an appropriate alert as defined in
{{Section 6 of TLS13}}.

如果 TLS 遇到错误，则会生成 {{Section 6 of TLS13}} 中定义的适当警报。

A TLS alert is converted into a QUIC connection error. The AlertDescription
value is
added to 0x100 to produce a QUIC error code from the range reserved for
CRYPTO_ERROR. The resulting value is sent in a QUIC CONNECTION_CLOSE frame of
type 0x1c.

TLS 警报将转换为 QUIC 连接错误。AlertDescription 值添加到 0x100，以从为 CRYPTO_ERROR
保留的范围内产生 QUIC 错误代码。结果值在类型为 0x1c 的 QUIC CONNECTION_CLOSE 帧中发送。

QUIC is only able to convey an alert level of "fatal". In TLS 1.3, the only
existing uses for the "warning" level are to signal connection close; see
{{Section 6.1 of TLS13}}. As QUIC provides alternative mechanisms for
connection termination and the TLS connection is only closed if an error is
encountered, a QUIC endpoint MUST treat any alert from TLS as if it were at the
"fatal" level.

QUIC 仅能传达 "fatal" 警报级别。 在 TLS 1.3 中，"fatal" 级别的唯一现有用法是发出
信号以表明连接已关闭（{{Section 6.1 of TLS13}}）。由于 QUIC 提供了用于终止连接的
替代机制，并且 TLS 连接仅在遇到错误时才关闭，因此 QUIC 端点务必将来自 TLS 的任何
警报视为处于 "fatal" 级别。

QUIC permits the use of a generic code in place of a specific error code; see
{{Section 11 of QUIC-TRANSPORT}}. For TLS alerts, this includes replacing any
alert with a generic alert, such as handshake_failure (0x128 in QUIC).
Endpoints MAY use a generic error code to avoid possibly exposing confidential
information.

QUIC 允许使用通用代码代替特定的错误代码（{{Section 11 of QUIC-TRANSPORT}}）。
对于 TLS 警报，这包括用通用警报替换所有警报，例如 handshake_failure（ QUIC 中为 0x128）。
端点可以使用通用错误代码，以避免可能暴露机密信息。

## Discarding Unused Keys - 丢弃未使用的密钥

After QUIC has completed a move to a new encryption level, packet protection
keys for previous encryption levels can be discarded.  This occurs several times
during the handshake, as well as when keys are updated; see {{key-update}}.

在 QUIC 完成转移到新的加密级别后，可以丢弃先前加密级别的数据包保护密钥。在握手期间
以及在更新密钥时，这种情况会发生多次，见 {{key-update}}。

Packet protection keys are not discarded immediately when new keys are
available.  If packets from a lower encryption level contain CRYPTO frames,
frames that retransmit that data MUST be sent at the same encryption level.
Similarly, an endpoint generates acknowledgments for packets at the same
encryption level as the packet being acknowledged.  Thus, it is possible that
keys for a lower encryption level are needed for a short time after keys for a
newer encryption level are available.

当新密钥可用时，不会立即丢弃数据包保护密钥。如果来自较低加密级别的数据包包含 CRYPTO 帧，
则必须以相同的加密级别发送重传该数据的帧。同样，端点会以与要确认的数据包相同的加密级别
为数据包生成确认。因此，可能在较新的加密级别的密钥可用之后的短时间内需要较低加密级别的
密钥。

An endpoint cannot discard keys for a given encryption level unless it has
received all the cryptographic handshake messages from its peer at that
encryption level and its peer has done the same.  Different methods for
determining this are provided for Initial keys ({{discard-initial}}) and
Handshake keys ({{discard-handshake}}).  These methods do not prevent packets
from being received or sent at that encryption level because a peer might not
have received all the acknowledgments necessary.

端点无法丢弃给定加密级别的密钥，除非它已从该加密级别的对等方接收到所有加密握手消息，
并且对等方也已这样做。确定 Initial 密钥（{{discard-initial}}）和 Handshake 密钥
（{{discard-handshake}}）的方法不同。这些方法不会阻止在该加密级别接收或发送数据包，
因为对等端可能未收到所有必需的确认。

Though an endpoint might retain older keys, new data MUST be sent at the highest
currently-available encryption level.  Only ACK frames and retransmissions of
data in CRYPTO frames are sent at a previous encryption level.  These packets
MAY also include PADDING frames.

尽管端点可能保留了旧密钥，但必须以当前可用的最高加密级别发送新数据。在先前的加密级别
仅发送 ACK 帧和 CRYPTO 帧中的数据重传。这些数据包还可以包括 PADDING 帧。

### Discarding Initial Keys - 丢弃 Initial 密钥 {#discard-initial}

Packets protected with Initial secrets ({{initial-secrets}}) are not
authenticated, meaning that an attacker could spoof packets with the intent to
disrupt a connection.  To limit these attacks, Initial packet protection keys
are discarded more aggressively than other keys.

未验证使用 Initial 密码（{{initial-secrets}}）保护的数据包，这意味着攻击者可能会欺骗
意图中断连接的数据包。为了限制这些攻击，初始包保护密钥比其他密钥更为积极地丢弃。

The successful use of Handshake packets indicates that no more Initial packets
need to be exchanged, as these keys can only be produced after receiving all
CRYPTO frames from Initial packets.  Thus, a client MUST discard Initial keys
when it first sends a Handshake packet and a server MUST discard Initial keys
when it first successfully processes a Handshake packet.  Endpoints MUST NOT
send Initial packets after this point.

握手数据包的成功使用表明不再需要交换 Initial 数据包，因为只有在从初始数据包接收到
所有 CRYPTO 帧之后才能生成这些密钥。因此，客户端在第一次发送握手包时必须丢弃初始密钥，
而服务器在第一次成功处理握手包时必须丢弃初始密钥。端点在此之后不得发送初始数据包。

This results in abandoning loss recovery state for the Initial encryption level
and ignoring any outstanding Initial packets.

这导致放弃 Initial 加密级别的丢失恢复状态，并忽略任何未完成的初始数据包。

### Discarding Handshake Keys - 丢弃 Handshake 密钥 {#discard-handshake}

An endpoint MUST discard its handshake keys when the TLS handshake is confirmed
({{handshake-confirmed}}).

端点必须在握手被确认时丢弃 Handshake 密钥（见 {{handshake-confirmed}}）。

### Discarding 0-RTT Keys - 丢弃 0-RTT 密钥

0-RTT and 1-RTT packets share the same packet number space, and clients do not
send 0-RTT packets after sending a 1-RTT packet ({{using-early-data}}).

0-RTT 和 1-RTT 数据包共享相同的数据包编号空间，客户端不能在发送 1-RTT 数据包之后
发送 0-RTT 数据包（{{using-early-data}}）。

Therefore, a client SHOULD discard 0-RTT keys as soon as it installs 1-RTT
keys, since they have no use after that moment.

因此，客户端应该在应用 1-RTT 密钥后立即丢弃 0-RTT 密钥，因为在那一刻之后它们
将不再使用。

Additionally, a server MAY discard 0-RTT keys as soon as it receives a 1-RTT
packet.  However, due to packet reordering, a 0-RTT packet could arrive after
a 1-RTT packet.  Servers MAY temporarily retain 0-RTT keys to allow decrypting
reordered packets without requiring their contents to be retransmitted with
1-RTT keys.  After receiving a 1-RTT packet, servers MUST discard 0-RTT keys
within a short time; the RECOMMENDED time period is three times the Probe
Timeout (PTO, see {{QUIC-RECOVERY}}).  A server MAY discard 0-RTT keys earlier
if it determines that it has received all 0-RTT packets, which can be done by
keeping track of missing packet numbers.

另外，服务器一旦接收到 1-RTT 包，就可以丢弃 0-RTT 密钥。但是，由于数据包重新排序，
0-RTT 数据包可能会在 1-RTT 数据包之后到达。服务器可以临时保留 0-RTT 密钥，以允许
解密重新排序的数据包，而无需使用 1-RTT 密钥重新发送其内容。收到 1-RTT 数据包后，
服务器务必在短时间内丢弃 0-RTT 密钥。推荐时间是探测超时的三倍（PTO 见 {{QUIC-RECOVERY}}）。
如果服务器确定已收到所有 0-RTT 数据包，则服务器可以更早地丢弃 0-RTT 密钥，这可以
通过跟踪丢失的数据包编号来完成。

# Packet Protection - 数据包保护 {#packet-protection}

As with TLS over TCP, QUIC protects packets with keys derived from the TLS
handshake, using the AEAD algorithm {{!AEAD}} negotiated by TLS.

与 TCP 上的 TLS 一样，QUIC 使用 TLS 协商的 AEAD 算法 {{!AEAD}} 来保护从 TLS 握手
产生的密钥的数据包。

QUIC packets have varying protections depending on their type:

QUIC 数据包根据它们的类型采用不同的保护策略：

* Version Negotiation packets have no cryptographic protection.

* 版本协商数据包没有加密保护。

* Retry packets use AEAD_AES_128_GCM to provide protection against accidental
  modification and to limit the entities that can produce a valid Retry;
  see {{retry-integrity}}.

* 重试数据包使用 AEAD_AES_128_GCM 提供保护以防止意外修改并限制可以产生有效重试的实体
  （见 {{retry-integrity}}）。

* Initial packets use AEAD_AES_128_GCM with keys derived from the Destination
  Connection ID field of the first Initial packet sent by the client; see
  {{initial-secrets}}.

* Initial 数据包使用 AEAD_AES_128_GCM，密钥来自客户端发送的第一个 Initial 数据包中的
  Destination Connection ID 字段（见 {{initial-secrets}}）。

* All other packets have strong cryptographic protections for confidentiality
  and integrity, using keys and algorithms negotiated by TLS.

* 所有其他的数据包都使用 TLS 协商的密钥和算法，对机密性和完整性具有很强的加密保护。

This section describes how packet protection is applied to Handshake packets,
0-RTT packets, and 1-RTT packets. The same packet protection process is applied
to Initial packets. However, as it is trivial to determine the keys used for
Initial packets, these packets are not considered to have confidentiality or
integrity protection. Retry packets use a fixed key and so similarly lack
confidentiality and integrity protection.

这章节描述如何将数据包保护应用到 Handshake、0-RTT、1-RTT 数据包。同样的数据包保护
过程将应用到 Initial 数据包。然而，因为决定用于 Initial 数据包的密钥很简单，所以这
些数据包不被认为具有机密性或完整性保护。重试数据包使用固定密钥，因此同样缺乏机密性
和完整性保护。


## Packet Protection Keys - 数据包保护密钥 {#protection-keys}

QUIC derives packet protection keys in the same way that TLS derives record
protection keys.

QUIC 生成数据包保护密钥的方式与 TLS 生成记录保护密钥的方式相同。

Each encryption level has separate secret values for protection of packets sent
in each direction. These traffic secrets are derived by TLS (see {{Section 7.1
of TLS13}}) and are used by QUIC for all encryption levels except the Initial
encryption level. The secrets for the Initial encryption level are computed
based on the client's initial Destination Connection ID, as described in
{{initial-secrets}}.

每个加密级别都有单独的秘密值，用来保护在每个方向上发送的数据包。这些流量秘密是由 TLS 派生的
（见 {{Section 7.1 of TLS13}}），QUIC 将其用在除 Initial 加密级别之外的所有加密级别。
如 {{initial-secrets}} 中所述，将根据客户端的初始目标连接 ID 计算 Initial 加密级别的秘密。

The keys used for packet protection are computed from the TLS secrets using the
KDF provided by TLS.  In TLS 1.3, the HKDF-Expand-Label function described in
{{Section 7.1 of TLS13}} is used, using the hash function from the negotiated
cipher suite.  All uses of HKDF-Expand-Label in QUIC use a zero-length Context.

用于数据包保护的密钥是由 TLS 提供的 KDF 从 TLS 秘密计算出来的。在 TLS1.3 中，使用了
{{Section 7.1 of TLS13}} 中描述的 HKDF-Expand-Label 函数，它使用了协商密码套件中的哈希函数。
所有在 QUIC 中使用的 HKDF-Expand-Label 函数都使用零长度上下文。

Note that labels, which are described using strings, are encoded
as bytes using ASCII {{?ASCII=RFC0020}} without quotes or any trailing NUL
byte.

请注意，那些使用字符串描述的标签使用不带引号的 ASCII 编码为字节，也没有任何尾部 NUL 字节。

Other versions of TLS MUST provide a similar function in order to be
used with QUIC.

其他版本的 TLS 必须提供类似的函数才能与 QUIC 一起使用。

The current encryption level secret and the label "quic key" are input to the
KDF to produce the AEAD key; the label "quic iv" is used to derive the
Initialization Vector (IV); see {{aead}}.  The header protection key uses the
"quic hp" label; see {{header-protect}}.  Using these labels provides key
separation between QUIC and TLS; see {{key-diversity}}.

当前加密级别 secret 和标签 "quic key" 被输入到 KDF 以生成 AEAD 密钥；标签 "quic iv" 用于
导出初始化向量 (IV)（见 {{aead}}）。Header 保护密钥使用 "quic hp" 标签（{{header-protect}}）。
使用这些标签可以在 QUIC 和 TLS 之间提供密钥分离（见 {{key-diversity}}）。

Both "quic key" and "quic hp" are used to produce keys, so the Length provided
to HKDF-Expand-Label along with these labels is determined by the size of keys
in the AEAD or header protection algorithm. The Length provided with "quic iv"
is the minimum length of the AEAD nonce, or 8 bytes if that is larger; see
{{!AEAD}}.

"quic key" 和 "quic hp" 都用于生成密钥，因此提供给 HKDF-Expand-Label 的长度以及
这些标签由 AEAD 或 Header 保护算法中密钥的大小确定。 "quic iv" 提供的长度是 AEAD 随机
数的最小长度，如果较大，则为 8 个字节（见 {{!AEAD}}）。

The KDF used for initial secrets is always the HKDF-Expand-Label function from
TLS 1.3; see {{initial-secrets}}.

用于 Initial secrets 的 KDF 始终是 TLS 1.3 中的 HKDF-Expand-Label 函数（见 {{initial-secrets}}）。

## Initial Secrets - Initial 密码 {#initial-secrets}

Initial packets apply the packet protection process, but use a secret derived
from the Destination Connection ID field from the client's first Initial
packet.

Initial 数据包应用数据包保护过程，是使用从客户端的第一个 Initial 数据包的「目标连接ID」
字段派生出来的密码。

This secret is determined by using HKDF-Extract (see {{Section 2.2 of HKDF}})
with a salt of 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a and a IKM of the
Destination Connection ID field. This produces an intermediate pseudorandom key
(PRK) that is used to derive two separate secrets for sending and receiving.

这个密码是通过使用 HKDF-Extract （见 {{Section 2.2 of HKDF}})）和
一个盐 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a 以及目标连接 ID 字段的 IKM 来确定的。
这将产生一个中间伪随机密钥（PRK），用于导出用于发送和接收的两个独立密钥。

The secret used by clients to construct Initial packets uses the PRK and the
label "client in" as input to the HKDF-Expand-Label function from TLS
{{!TLS13}} to produce a 32-byte secret.  Packets constructed by the server use
the same process with the label "server in".  The hash function for HKDF when
deriving initial secrets and keys is SHA-256
{{!SHA=DOI.10.6028/NIST.FIPS.180-4}}.

客户端用来构造 Initial 数据包的 secret 使用 PRK 和 "client-in" 标签作为
HKDF-Expand-Label 函数的输入，从 TLS {{!TLS13}} 产生一个 32 字节的 secret。
服务器使用相同的过程加上 "server in" 标签构造数据包。HKDF 在派生初始 secret 和
密钥时的哈希函数是 SHA-256 {{!SHA=DOI.10.6028/NIST.FIPS.180-4}}。

This process in pseudocode is:

伪代码处理过程：

~~~
initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
initial_secret = HKDF-Extract(initial_salt,
                              client_dst_connection_id)

client_initial_secret = HKDF-Expand-Label(initial_secret,
                                          "client in", "",
                                          Hash.length)
server_initial_secret = HKDF-Expand-Label(initial_secret,
                                          "server in", "",
                                          Hash.length)
~~~

The connection ID used with HKDF-Expand-Label is the Destination Connection ID
in the Initial packet sent by the client.  This will be a randomly-selected
value unless the client creates the Initial packet after receiving a Retry
packet, where the Destination Connection ID is selected by the server.

与 HKDF-Expand-Label 一起使用的连接 ID 是客户端发送的初始数据包中的目标连接 ID。
这将是随机选择的值，除非客户端在接收到重试数据包后创建初始数据包，其中目标
连接 ID 由服务器选择。

Future versions of QUIC SHOULD generate a new salt value, thus ensuring that
the keys are different for each version of QUIC.  This prevents a middlebox that
recognizes only one version of QUIC from seeing or modifying the contents of
packets from future versions.

未来版本的 QUIC 应该生成一个新的 salt 值，从而确保每个版本的 QUIC 的密钥是不同的。
这可以防止只识别一个 QUIC 版本的中间盒子看到或修改来自未来版本的数据包的内容。

The HKDF-Expand-Label function defined in TLS 1.3 MUST be used for Initial
packets even where the TLS versions offered do not include TLS 1.3.

在 TLS1.3 中定义的 HKDF-Expand-Label 函数必须用于初始数据包，即使提供的 TLS 实现
不支持 TLS1.3 。

The secrets used for constructing subsequent Initial packets change when a
server sends a Retry packet, to use the connection ID value selected by the
server.  The secrets do not change when a client changes the Destination
Connection ID it uses in response to an Initial packet from the server.

当服务器发送重试数据包时，用于构造后续初始数据包的 secrets 将会更改，以使用服务器
选择的连接 ID。当客户端响应于来自服务器的初始数据包而更改其使用的目标连接 ID 时，
secrets 不会更改。

Note:

: The Destination Connection ID field could be any length up to 20 bytes,
  including zero length if the server sends a Retry packet with a zero-length
  Source Connection ID field. After a Retry, the Initial keys provide the client
  no assurance that the server received its packet, so the client has to rely on
  the exchange that included the Retry packet to validate the server address;
  see {{Section 8.1 of QUIC-TRANSPORT}}.

注意：

: 如果服务器发送带有长度为零长度的源连接 ID 字段的重试数据包，则目标连接 ID 字段的长度
  可以为 0-20 个字节。重试之后，Initial 密钥不能保证客户端已收到服务器的数据包，因此客户端
  必须依靠包含重试数据包的交换来验证服务器地址（见 {{Section 8.1 of QUIC-TRANSPORT}}）。

{{test-vectors}} contains sample Initial packets.

{{test-vectors}} 包含初始数据包样本。


## AEAD Usage - AEAD 的用法 {#aead}

The Authenticated Encryption with Associated Data (AEAD; see {{!AEAD}}) function
used for QUIC packet protection is the AEAD that is negotiated for use with the
TLS connection.  For example, if TLS is using the TLS_AES_128_GCM_SHA256 cipher
suite, the AEAD_AES_128_GCM function is used.

用于 QUIC 数据包保护的带有关联数据的认证加密 (AEAD {{!AEAD}}) 功能是 AEAD，
它经过协商可与 TLS 连接一起使用。例如，如果 TLS 使用 TLS_AES_128_GCM_SHA256 密码套件，
则使用 AEAD_AES_128_GCM 函数。

QUIC can use any of the cipher suites defined in {{!TLS13}} with the exception
of TLS_AES_128_CCM_8_SHA256.  A cipher suite MUST NOT be negotiated unless a
header protection scheme is defined for the cipher suite.  This document defines
a header protection scheme for all cipher suites defined in {{!TLS13}} aside
from TLS_AES_128_CCM_8_SHA256.  These cipher suites have a 16-byte
authentication tag and produce an output 16 bytes larger than their input.

QUIC 可以使用 {{!TLS13}} 中定义的任意加密套件，除了 TLS_AES_128_CCM_8_SHA256。
除非为密码套件定义了 Header 保护方案，否则不得协商密码套件。除了 TLS_AES_128_CCM_8_SHA256 之外，
本文档还为 {{!TLS13}} 中定义的所有密码套件定义了 Header 保护方案。这些密码套件含有 16 字节的身份
验证标签，并产生比其输入多 16 个字节的输出。

Note:

: An endpoint MUST NOT reject a ClientHello that offers a cipher suite that it
  does not support, or it would be impossible to deploy a new cipher suite.
  This also applies to TLS_AES_128_CCM_8_SHA256.

注意：

: 端点不能拒绝提供不支持的密码套件的 ClientHello，否则将无法部署新的密码套件。
  这也适用于 TLS_AES_128_CCM_8_SHA256 。

When constructing packets, the AEAD function is applied prior to applying
header protection; see {{header-protect}}. The unprotected packet header is part
of the associated data (A). When processing packets, an endpoint first
removes the header protection.

构造数据包时，在应用 Header 保护之前先应用 AEAD 函数（{{header-protect}}）。
未受保护的数据包 Header 是关联数据 (A) 的一部分。在处理数据包时，端点首先移除
Header 保护。

The key and IV for the packet are computed as described in {{protection-keys}}.
The nonce, N, is formed by combining the packet protection IV with the packet
number.  The 62 bits of the reconstructed QUIC packet number in network byte
order are left-padded with zeros to the size of the IV.  The exclusive OR of the
padded packet number and the IV forms the AEAD nonce.

数据包的密钥和 IV 如 {{protection-keys}} 中所述进行计算。随机数 N 是通过将数据包
保护 IV 与数据包编号组合而成的。以网络字节顺序将重构的 QUIC 数据包编号的 62 位用
零填充到 IV 的大小。填充数据包编号与 IV 的异或构成 AEAD 随机数。

The associated data, A, for the AEAD is the contents of the QUIC header,
starting from the first byte of either the short or long header, up to and
including the unprotected packet number.

AEAD 的关联数据 A 是 QUIC 报头的内容，从短报头或长报头的第一个字节开始，直到并
包括不受保护的包编号。

The input plaintext, P, for the AEAD is the payload of the QUIC packet, as
described in {{QUIC-TRANSPORT}}.

AEAD 的输入明文 P 是 QUIC 数据包的有效负载，如 {{QUIC-TRANSPORT}} 中所述。

The output ciphertext, C, of the AEAD is transmitted in place of P.

AEAD 的输出密文 C 替换 P 发送。

Some AEAD functions have limits for how many packets can be encrypted under the
same key and IV; see {{aead-limits}}.  This might be lower than the packet
number limit.  An endpoint MUST initiate a key update ({{key-update}}) prior to
exceeding any limit set for the AEAD that is in use.

一些 AEAD 函数对使用相同密钥和 IV 可以加密多少个数据包有限制（见 {{aead-limits}}）。
这可能低于数据包数量限制。端点必须在超过为使用的 AEAD 设置的任何限制之前启动密钥
更新（{{key-update}}）。

## Header Protection - Header 保护 {#header-protect}

Parts of QUIC packet headers, in particular the Packet Number field, are
protected using a key that is derived separately from the packet protection key
and IV.  The key derived using the "quic hp" label is used to provide
confidentiality protection for those fields that are not exposed to on-path
elements.

QUIC 数据包头的一部分，特别是「数据包编号」字段，使用与数据包保护密钥和 IV 分别
派生的密钥进行保护。使用 "quic hp" 标签派生的密钥用于为那些未暴露于路径元素的字段
提供机密保护。

This protection applies to the least-significant bits of the first byte, plus
the Packet Number field.  The four least-significant bits of the first byte are
protected for packets with long headers; the five least significant bits of the
first byte are protected for packets with short headers.  For both header forms,
this covers the reserved bits and the Packet Number Length field; the Key Phase
bit is also protected for packets with a short header.

这种保护适用于第一个字节的最低有效位，再加上「数据包编号」字段。对于使用长包头的数据包，
第一个字节的四个最低有效位受到保护；对于使用短包头的数据包，将保护第一个字节的五个最低
有效位。对于这两种包头形式，这都包括保留位和「数据包编号长度」字段。对于具有短报头的
数据包，密钥相位位也受到保护。

The same header protection key is used for the duration of the connection, with
the value not changing after a key update (see {{key-update}}).  This allows
header protection to be used to protect the key phase.

连接期间使用相同的报头保护密钥，密钥更新后该值不变（见 {{key-update}}）。
这允许把 Header 保护用来保护关键阶段。

This process does not apply to Retry or Version Negotiation packets, which do
not contain a protected payload or any of the fields that are protected by this
process.

此过程不适用于重试或版本协商数据包，这些数据包不包含受保护的有效负载或此过程
保护的任何字段。

### Header Protection Application - Header 保护应用

Header protection is applied after packet protection is applied (see {{aead}}).
The ciphertext of the packet is sampled and used as input to an encryption
algorithm.  The algorithm used depends on the negotiated AEAD.

在应用包保护（见 {{aead}}）之后应用报头保护。对数据包的密文进行采样，并将其用作
加密算法的输入。使用的算法取决于协商的 AEAD。

The output of this algorithm is a 5-byte mask that is applied to the protected
header fields using exclusive OR.  The least significant bits of the first byte
of the packet are masked by the least significant bits of the first mask byte,
and the packet number is masked with the remaining bytes.  Any unused bytes of
mask that might result from a shorter packet number encoding are unused.

该算法的输出是一个 5 字节的掩码，该掩码使用异或运算应用于受保护的包头字段。数据包
第一个字节的最低有效位被第一个屏蔽字节的最低有效位屏蔽，而数据包号被其余字节屏蔽。
较短的数据包编号编码可能导致的任何未使用的掩码字节都未被使用。

{{pseudo-hp}} shows a sample algorithm for applying header protection. Removing
header protection only differs in the order in which the packet number length
(pn_length) is determined (here "^" is used to represent exclusive or).

{{pseudo-hp}} 显示了用于应用标头保护的示例算法。移除报头保护的区别仅在于确定数据包
编号长度 (pn_length) 的顺序不同（这里的 "^" 用于表示异或）。

~~~
mask = header_protection(hp_key, sample)

pn_length = (packet[0] & 0x03) + 1
if (packet[0] & 0x80) == 0x80:
   # Long header: 4 bits masked
   packet[0] ^= mask[0] & 0x0f
else:
   # Short header: 5 bits masked
   packet[0] ^= mask[0] & 0x1f

# pn_offset is the start of the Packet Number field.
packet[pn_offset:pn_offset+pn_length] ^= mask[1:1+pn_length]
~~~
{: #pseudo-hp title="Header Protection Pseudocode"}

Specific header protection functions are defined based on the selected cipher
suite; see {{hp-aes}} and {{hp-chacha}}.

根据所选的密码套件定义特定的报头保护功能（见 {{hp-aes}} 和 {{hp-chacha}}）。

{{fig-sample}} shows an example long header packet (Initial) and a short header
packet (1-RTT). {{fig-sample}} shows the fields in each header that are covered
by header protection and the portion of the protected packet payload that is
sampled.

{{fig-sample}} 显示了一个示例长标头包 (Initial) 和短标头包 (1-RTT)。{{fig-sample}}
显示了标头保护所覆盖的每个标头中的字段以及所采样的受保护数据包有效负载的一部分。

~~~
Initial Packet {
  Header Form (1) = 1,
  Fixed Bit (1) = 1,
  Long Packet Type (2) = 0,
  Reserved Bits (2),         # Protected
  Packet Number Length (2),  # Protected
  Version (32),
  DCID Len (8),
  Destination Connection ID (0..160),
  SCID Len (8),
  Source Connection ID (0..160),
  Token Length (i),
  Token (..),
  Length (i),
  Packet Number (8..32),     # Protected
  Protected Payload (0..24), # Skipped Part
  Protected Payload (128),   # Sampled Part
  Protected Payload (..)     # Remainder
}

1-RTT Packet {
  Header Form (1) = 0,
  Fixed Bit (1) = 1,
  Spin Bit (1),
  Reserved Bits (2),         # Protected
  Key Phase (1),             # Protected
  Packet Number Length (2),  # Protected
  Destination Connection ID (0..160),
  Packet Number (8..32),     # Protected
  Protected Payload (0..24), # Skipped Part
  Protected Payload (128),   # Sampled Part
  Protected Payload (..),    # Remainder
}
~~~
{: #fig-sample title="Header Protection and Ciphertext Sample"}

Before a TLS cipher suite can be used with QUIC, a header protection algorithm
MUST be specified for the AEAD used with that cipher suite.  This document
defines algorithms for AEAD_AES_128_GCM, AEAD_AES_128_CCM, AEAD_AES_256_GCM (all
these AES AEADs are defined in {{!AEAD=RFC5116}}), and AEAD_CHACHA20_POLY1305
(defined in {{!CHACHA=RFC8439}}).  Prior to TLS selecting a cipher suite, AES
header protection is used ({{hp-aes}}), matching the AEAD_AES_128_GCM packet
protection.

在 TLS 密码套件可以与 QUIC 一起使用之前，必须为与该密码套件一起使用的 AEAD 指定
标头保护算法。本文档定义了 AEAD_AES_128_GCM、AEAD_AES_128_CCM、AEAD_AES_256_GCM
（所有这些 AES AEADs 在 {{!AEAD=RFC5116}}）和 AEAD_CHACHA20_POLY1305
（在 {{!CHACHA=RFC8439}} 中定义）的算法。在 TLS 选择密码套件之前，使用 AES 标头
保护（{{hp-aes}}），与 AEAD_AES_128_GCM 数据包保护相匹配。

### Header Protection Sample - Header 保护例子 {#hp-sample}

The header protection algorithm uses both the header protection key and a sample
of the ciphertext from the packet Payload field.

Header 保护算法同时使用 Header 保护密钥和来自数据包有效载荷字段的密文样本。

The same number of bytes are always sampled, but an allowance needs to be made
for the endpoint removing protection, which will not know the length of the
Packet Number field.  The sample of ciphertext is taken starting from an offset
of 4 bytes after the start of the Packet Number field.  That is, in sampling
packet ciphertext for header protection, the Packet Number field is assumed to
be 4 bytes long (its maximum possible encoded length).

总是采样相同数量的字节，但是需要为端点移除保护留出余地，因为不知道数据包编号
字段的长度。密文的样本从数据包编号字段开始后 4 个字节的偏移量开始获取。也就是说，
在对用于报头保护的分组密文进行采样时，分组编号字段假定为 4 字节长（其最大可能编码长度）。

An endpoint MUST discard packets that are not long enough to contain a complete
sample.

端点必须丢弃长度不足以包含完整样本的数据包。

To ensure that sufficient data is available for sampling, packets are padded so
that the combined lengths of the encoded packet number and protected payload is
at least 4 bytes longer than the sample required for header protection.  The
cipher suites defined in {{!TLS13}} - other than TLS_AES_128_CCM_8_SHA256, for
which a header protection scheme is not defined in this document - have 16-byte
expansions and 16-byte header protection samples.  This results in needing at
least 3 bytes of frames in the unprotected payload if the packet number is
encoded on a single byte, or 2 bytes of frames for a 2-byte packet number
encoding.

为了确保有足够的数据可用于采样，对数据包进行填充，以使编码的数据包编号和受保护的
有效载荷的组合长度至少比标头保护所需的样本长 4 个字节。 在 {{!TLS13}} 中定义的
密码套件（TLS_AES_128_CCM_8_SHA256 除外，在本文中未定义标头保护方案）具有 16 字节
扩展和 16 字节标头保护样本。如果将数据包号编码在单个字节上，则需要在未受保护的
有效载荷中至少包含 3 个字节的帧；对于 2 字节的数据包号编码，则需要 2 个字节的帧。

The sampled ciphertext can be determined by the following pseudocode:

可以通过下面的伪代码确定采样的密文：

~~~
# pn_offset is the start of the Packet Number field.
# pn_offset 为数据包编号字段的开始。
sample_offset = pn_offset + 4

sample = packet[sample_offset..sample_offset+sample_length]
~~~

where the packet number offset of a short header packet can be calculated as:

其中，短头数据包的编号偏移可以计算为：

~~~
pn_offset = 1 + len(connection_id)
~~~

and the packet number offset of a long header packet can be calculated as:

并且长头数据包的编号偏移量可以计算为：

~~~
pn_offset = 7 + len(destination_connection_id) +
                len(source_connection_id) +
                len(payload_length)
if packet_type == Initial:
    pn_offset += len(token_length) +
                 len(token)
~~~

For example, for a packet with a short header, an 8-byte connection ID, and
protected with AEAD_AES_128_GCM, the sample takes bytes 13 to 28 inclusive
(using zero-based indexing).

例如，对于使用短头、8 字节连接 ID 并受 AEAD_AES_128_GCM 保护的数据包，该示例
将获取包含 13-28 个字节（使用基于零的索引）。

Multiple QUIC packets might be included in the same UDP datagram. Each packet
is handled separately.

同一个 UDP 数据报中可能包含多个 QUIC 数据包。每个数据包是分开处理的。

### AES-Based Header Protection - 基于 AES 的 Header 保护 {#hp-aes}

This section defines the packet protection algorithm for AEAD_AES_128_GCM,
AEAD_AES_128_CCM, and AEAD_AES_256_GCM. AEAD_AES_128_GCM and AEAD_AES_128_CCM
use 128-bit AES in electronic code-book (ECB) mode. AEAD_AES_256_GCM uses
256-bit AES in ECB mode.  AES is defined in {{!AES=DOI.10.6028/NIST.FIPS.197}}.

这部分定义了 AEAD_AES_128_GCM、AEAD_AES_128_CCM 和 AEAD_AES_256_GCM 的数据包保护算法。
AEAD_AES_128_GCM 和 AEAD_AES_128_CCM 在电子密码簿 (ECB) 模式下使用 128 位 AES。
AEAD_AES_256_GCM 在 ECB 模式下使用 256 位 AES。AES 定义在 {{!AES=DOI.10.6028/NIST.FIPS.197}}。

This algorithm samples 16 bytes from the packet ciphertext. This value is used
as the input to AES-ECB.  In pseudocode, the header protection function is
defined as:

该算法从数据包密文中采样 16 个字节。该值用作 AES-ECB 的输入。在伪代码中，
Header 保护函数定义为：

~~~
header_protection(hp_key, sample):
  mask = AES-ECB(hp_key, sample)
~~~


### ChaCha20-Based Header Protection - 基于 ChaCha20 的 Header 保护 {#hp-chacha}

When AEAD_CHACHA20_POLY1305 is in use, header protection uses the raw ChaCha20
function as defined in {{Section 2.4 of CHACHA}}.  This uses a 256-bit key and
16 bytes sampled from the packet protection output.

使用 AEAD_CHACHA20_POLY1305 时，Header 保护使用 {{Section 2.4 of CHACHA}} 中定义的
原始 ChaCha20 函数。它使用一个 256 位密钥和 16 个字节从数据包保护输出中采样。

The first 4 bytes of the sampled ciphertext are the block counter.  A ChaCha20
implementation could take a 32-bit integer in place of a byte sequence, in
which case the byte sequence is interpreted as a little-endian value.

采样密文的前 4 个字节是块计数器。ChaCha20 实现可以使用 32 位整数代替字节序列，
在这种情况下，字节序列被解释为低位字节序值。

The remaining 12 bytes are used as the nonce. A ChaCha20 implementation might
take an array of three 32-bit integers in place of a byte sequence, in which
case the nonce bytes are interpreted as a sequence of 32-bit little-endian
integers.

剩余的 12 个字节用作随机数。 ChaCha20 实现可能采用三个 32 位整数数组来代替字节序列，
在这种情况下，现时字节被解释为 32 位 Little-endian 整数序列。

The encryption mask is produced by invoking ChaCha20 to protect 5 zero bytes. In
pseudocode, the header protection function is defined as:

加密掩码是通过调用 ChaCha20 来保护 5 个零字节而产生的。在伪代码中，
Header 保护函数定义为：

~~~
header_protection(hp_key, sample):
  counter = sample[0..3]
  nonce = sample[4..15]
  mask = ChaCha20(hp_key, counter, nonce, {0,0,0,0,0})
~~~


## Receiving Protected Packets - 接收保护数据包

Once an endpoint successfully receives a packet with a given packet number, it
MUST discard all packets in the same packet number space with higher packet
numbers if they cannot be successfully unprotected with either the same key, or
- if there is a key update - a subsequent packet protection key; see
{{key-update}}.  Similarly, a packet that appears to trigger a key update, but
cannot be unprotected successfully MUST be discarded.

一旦端点成功地接收到特定数据包编号的数据包，它必须丢弃相同数据包编号空间中具有更高
数据包编号的所有数据包，如果它们不能用相同的密钥或（如果有密钥更新）后续的数据包保护
密钥成功取消保护（见 {{key-update}}）。类似地，必须丢弃看似触发密钥更新但无法成功取消
保护的数据包。

Failure to unprotect a packet does not necessarily indicate the existence of a
protocol error in a peer or an attack.  The truncated packet number encoding
used in QUIC can cause packet numbers to be decoded incorrectly if they are
delayed significantly.

未能解除对数据包的保护并不一定表明对等方中存在协议错误或攻击。在 QUIC 中使用的截断包编
号编码可能会导致包编号被错误地解码，如果它们被严重延迟的话。

## Use of 0-RTT Keys - 使用 0-RTT 密钥 {#using-early-data}

If 0-RTT keys are available (see {{enable-0rtt}}), the lack of replay protection
means that restrictions on their use are necessary to avoid replay attacks on
the protocol.

如果 0-RTT 密钥可用（见 {{enable-0rtt}}），则缺少重放保护意味着需要限制它们的使用，
以避免对协议的重播攻击。

Of the frames defined in {{QUIC-TRANSPORT}}, the STREAM, RESET_STREAM,
STOP_SENDING, and CONNECTION_CLOSE frames are potentially unsafe for use with
0-RTT as they carry application data. Application data that is received in
0-RTT could cause an application at the server to process the data multiple
times rather than just once. Additional actions taken by a server as a result
of processing replayed application data could have unwanted consequences. A
client therefore MUST NOT use 0-RTT for application data unless specifically
requested by the application that is in use.

在 {{QUIC-TRANSPORT}} 中定义的 STREAM、RESET_STREAM、STOP_SENDING、CONNECTION_CLOSE 帧
可能与 0-RTT 一起使用，因为它们携带应用程序数据。在 0-RT 中收到的应用程序数据可能导致
服务器上的应用程序多次处理数据，而不是一次。服务器在处理重放的应用程序数据时所采取的
其他操作可能会产生不必要的后果。因此，客户端不得对应用程序数据使用 0-RTT，除非正在使用的
应用程序明确要求。

An application protocol that uses QUIC MUST include a profile that defines
acceptable use of 0-RTT; otherwise, 0-RTT can only be used to carry QUIC frames
that do not carry application data. For example, a profile for HTTP is
described in {{?HTTP-REPLAY=RFC8470}} and used for HTTP/3; see
{{Section 10.9 of QUIC-HTTP}}.

使用 QUIC 的应用程序协议必须包含一个定义 0-RTT 可接受使用的配置文件；否则，0-RTT 只能
用于承载不承载应用程序数据的 QUIC 帧。例如，{{?HTTP-REPLAY=RFC8470}} 中描述了 HTTP 的概要
文件，并将其用于 HTTP/3（见 {{Section 10.9 of QUIC-HTTP}}）。

Though replaying packets might result in additional connection attempts, the
effect of processing replayed frames that do not carry application data is
limited to changing the state of the affected connection. A TLS handshake
cannot be successfully completed using replayed packets.

尽管重放数据包可能会导致额外的连接尝试，但处理不携带应用程序数据的重放帧的效果
仅限于更改受影响连接的状态。用重放的数据包无法成功完成 TLS 握手。

A client MAY wish to apply additional restrictions on what data it sends prior
to the completion of the TLS handshake.

客户端可能希望在 TLS 握手完成之前对其发送的数据应用附加限制。

A client otherwise treats 0-RTT keys as equivalent to 1-RTT keys, except that
it cannot send certain frames with 0-RTT keys; see
{{Section 12.5 of QUIC-TRANSPORT}}.

否则，客户端将 0-RTT 密钥视为等同于 1-RTT 密钥，只是它不能用 0-RTT 密钥发送某些帧
{{Section 12.5 of QUIC-TRANSPORT}}。

A client that receives an indication that its 0-RTT data has been accepted by a
server can send 0-RTT data until it receives all of the server's handshake
messages.  A client SHOULD stop sending 0-RTT data if it receives an indication
that 0-RTT data has been rejected.

接收到服务器已接受 0-RTT 数据的指示的客户端可以发送 0-RTT 数据，直到它接收到服务器
的所有握手消息为止。如果客户端收到 0-RTT 数据已被拒绝的指示，则应停止发送 0-RTT 数据。

A server MUST NOT use 0-RTT keys to protect packets; it uses 1-RTT keys to
protect acknowledgments of 0-RTT packets.  A client MUST NOT attempt to
decrypt 0-RTT packets it receives and instead MUST discard them.

服务器不能使用 0-RTT 密钥来保护数据包；它使用 1-RTT 密钥来保护 0-RTT 数据包的确认。
客户端不能试图解密它接收到的 0-RTT 数据包，而是必须丢弃它们。

Once a client has installed 1-RTT keys, it MUST NOT send any more 0-RTT
packets.
一旦客户端安装了 1-RTT 密钥，就不能再发送任何 0-RTT 数据包。

Note:

: 0-RTT data can be acknowledged by the server as it receives it, but any
  packets containing acknowledgments of 0-RTT data cannot have packet protection
  removed by the client until the TLS handshake is complete.  The 1-RTT keys
  necessary to remove packet protection cannot be derived until the client
  receives all server handshake messages.

注意：

: 服务器在接收到 0-RTT 数据时可以对其进行确认，但是在 TLS 握手完成之前，任何包含 0-RTT 数据
  确认的数据包都不能被客户端删除数据包保护。在客户端接收到所有服务器握手消息之前，无法导出
  删除数据包保护所需的 1-RTT 密钥。

## Receiving Out-of-Order Protected Packets - 接收无序受保护的数据包 {#pre-hs-protected}

Due to reordering and loss, protected packets might be received by an endpoint
before the final TLS handshake messages are received.  A client will be unable
to decrypt 1-RTT packets from the server, whereas a server will be able to
decrypt 1-RTT packets from the client.  Endpoints in either role MUST NOT
decrypt 1-RTT packets from their peer prior to completing the handshake.

由于重新排序和丢失，在接收到最终 TLS 握手消息之前，端点可能会接收到
受保护的数据包。客户端将无法从服务器解密 1-RTT 数据包，而服务器将能够
从客户端解密 1-RTT 数据包。在完成握手之前，任一角色的端点都不能解密来
自其对等方的 1-RTT 数据包。

Even though 1-RTT keys are available to a server after receiving the first
handshake messages from a client, it is missing assurances on the client state:

即使在从客户端接收到第一个握手消息后，服务器可以使用 1-RTT 密钥，
但它在客户端状态上缺少保证：

- The client is not authenticated, unless the server has chosen to use a
  pre-shared key and validated the client's pre-shared key binder; see {{Section
  4.2.11 of TLS13}}.

- 除非服务器选择使用预共享密钥并验证了客户端的预共享密钥绑定器，否则
  客户端不会被验证（见 {{Section 4.2.11 of TLS13}}）。

- The client has not demonstrated liveness, unless the server has validated the
  client's address with a Retry packet or other means; see
  {{Section 8.1 of QUIC-TRANSPORT}}.

- 客户端没有表现出活跃性，除非服务器用重试包或其他方法验证了客户机的地址
  （见 {{Section 8.1 of QUIC-TRANSPORT}}）。

- Any received 0-RTT data that the server responds to might be due to a replay
  attack.

- 服务器响应的任何接收到的 0-RTT 数据都可能是由于重播攻击造成的。

Therefore, the server's use of 1-RTT keys before the handshake is complete is
limited to sending data.  A server MUST NOT process incoming 1-RTT protected
packets before the TLS handshake is complete.  Because sending acknowledgments
indicates that all frames in a packet have been processed, a server cannot send
acknowledgments for 1-RTT packets until the TLS handshake is complete.  Received
packets protected with 1-RTT keys MAY be stored and later decrypted and used
once the handshake is complete.

因此，在握手完成之前，服务器对 1-RTT 密钥的使用仅限于发送数据。在 TLS 握手完成之前，
服务器不得处理传入的 1-RTT 保护的数据包。因为发送确认表示数据包中的所有帧都已处理，
所以在 TLS 握手完成之前，服务器无法发送 1-RTT 数据包的确认。接收到的由 1-RTT 密钥
保护的分组可以被存储，并且在握手完成之后被解密和使用。

Note:

: TLS implementations might provide all 1-RTT secrets prior to handshake
  completion.  Even where QUIC implementations have 1-RTT read keys, those keys
  are not to be used prior to completing the handshake.

注意：

: TLS 实现可能在握手完成之前提供所有 1-RTT 秘密。即使 QUIC 实现有 1-RTT 读取密钥，
  在完成握手之前也不能使用这些密钥。

The requirement for the server to wait for the client Finished message creates
a dependency on that message being delivered.  A client can avoid the
potential for head-of-line blocking that this implies by sending its 1-RTT
packets coalesced with a Handshake packet containing a copy of the CRYPTO frame
that carries the Finished message, until one of the Handshake packets is
acknowledged.  This enables immediate server processing for those packets.

服务器等待客户端完成消息的要求会在正在传递的消息上创建依赖关系。客户端可以通过发送
其 1-RTT 数据包与包含承载完成消息的加密帧副本的握手数据包合并，直到其中一个握手数据
包被确认为止，来避免意味着的可能的线路头阻塞。这使得服务器能够立即处理这些数据包。

A server could receive packets protected with 0-RTT keys prior to receiving a
TLS ClientHello.  The server MAY retain these packets for later decryption in
anticipation of receiving a ClientHello.

服务器可以在接收 TLS ClientHello 之前接收受 0-RTT 密钥保护的数据包。服务器可以
保留这些数据包，以便在接收预期的 ClientHello 时解密。

A client generally receives 1-RTT keys at the same time as the handshake
completes.  Even if it has 1-RTT secrets, a client MUST NOT process
incoming 1-RTT protected packets before the TLS handshake is complete.

客户端通常在握手完成的同时接收 1-RTT 密钥。即使它有 1-RTT 秘密，客户端也不能
在 TLS 握手完成之前处理传入的 1-RTT 保护的数据包。

## Retry Packet Integrity {#retry-integrity}

Retry packets (see the Retry Packet section of {{QUIC-TRANSPORT}}) carry a
Retry Integrity Tag that provides two properties: it allows discarding
packets that have accidentally been corrupted by the network; only an
entity that observes an Initial packet can send a valid Retry packet.

The Retry Integrity Tag is a 128-bit field that is computed as the output of
AEAD_AES_128_GCM ({{!AEAD}}) used with the following inputs:

- The secret key, K, is 128 bits equal to 0xbe0c690b9f66575a1d766b54e368c84e.
- The nonce, N, is 96 bits equal to 0x461599d35d632bf2239825bb.
- The plaintext, P, is empty.
- The associated data, A, is the contents of the Retry Pseudo-Packet, as
  illustrated in {{retry-pseudo}}:

The secret key and the nonce are values derived by calling HKDF-Expand-Label
using 0xd9c9943e6101fd200021506bcc02814c73030f25c79d71ce876eca876e6fca8e as the
secret, with labels being "quic key" and "quic iv" ({{protection-keys}}).

~~~
Retry Pseudo-Packet {
  ODCID Length (8),
  Original Destination Connection ID (0..160),
  Header Form (1) = 1,
  Fixed Bit (1) = 1,
  Long Packet Type (2) = 3,
  Unused (4),
  Version (32),
  DCID Len (8),
  Destination Connection ID (0..160),
  SCID Len (8),
  Source Connection ID (0..160),
  Retry Token (..),
}
~~~
{: #retry-pseudo title="Retry Pseudo-Packet"}

The Retry Pseudo-Packet is not sent over the wire. It is computed by taking
the transmitted Retry packet, removing the Retry Integrity Tag and prepending
the two following fields:

ODCID Length:

: The ODCID Length field contains the length in bytes of the Original
  Destination Connection ID field that follows it, encoded as an 8-bit unsigned
  integer.

Original Destination Connection ID:

: The Original Destination Connection ID contains the value of the Destination
  Connection ID from the Initial packet that this Retry is in response to. The
  length of this field is given in ODCID Length. The presence of this field
  ensures that a valid Retry packet can only be sent by an entity that
  observes the Initial packet.


# Key Update - 密钥更新 {#key-update}

Once the handshake is confirmed (see {{handshake-confirmed}}), an endpoint MAY
initiate a key update.

The Key Phase bit indicates which packet protection keys are used to protect the
packet.  The Key Phase bit is initially set to 0 for the first set of 1-RTT
packets and toggled to signal each subsequent key update.

The Key Phase bit allows a recipient to detect a change in keying material
without needing to receive the first packet that triggered the change.  An
endpoint that notices a changed Key Phase bit updates keys and decrypts the
packet that contains the changed value.

Initiating a key update results in both endpoints updating keys.  This differs
from TLS where endpoints can update keys independently.

This mechanism replaces the key update mechanism of TLS, which relies on
KeyUpdate messages sent using 1-RTT encryption keys.  Endpoints MUST NOT send a
TLS KeyUpdate message.  Endpoints MUST treat the receipt of a TLS KeyUpdate
message as a connection error of type 0x10a, equivalent to a
fatal TLS alert of unexpected_message; see {{tls-errors}}.

{{ex-key-update}} shows a key update process, where the initial set of keys used
(identified with @M) are replaced by updated keys (identified with @N).  The
value of the Key Phase bit is indicated in brackets \[].

~~~
   Initiating Peer                    Responding Peer

@M [0] QUIC Packets

... Update to @N
@N [1] QUIC Packets
                      -------->
                                         Update to @N ...
                                      QUIC Packets [1] @N
                      <--------
                                      QUIC Packets [1] @N
                                    containing ACK
                      <--------
... Key Update Permitted

@N [1] QUIC Packets
         containing ACK for @N packets
                      -------->
                                 Key Update Permitted ...
~~~
{: #ex-key-update title="Key Update"}


## Initiating a Key Update {#key-update-initiate}

Endpoints maintain separate read and write secrets for packet protection.  An
endpoint initiates a key update by updating its packet protection write secret
and using that to protect new packets.  The endpoint creates a new write secret
from the existing write secret as performed in {{Section 7.2 of TLS13}}.  This
uses the KDF function provided by TLS with a label of "quic ku".  The
corresponding key and IV are created from that secret as defined in
{{protection-keys}}.  The header protection key is not updated.

For example, to update write keys with TLS 1.3, HKDF-Expand-Label is used as:

~~~
secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku",
                                 "", Hash.length)
~~~

The endpoint toggles the value of the Key Phase bit and uses the updated key and
IV to protect all subsequent packets.

An endpoint MUST NOT initiate a key update prior to having confirmed the
handshake ({{handshake-confirmed}}).  An endpoint MUST NOT initiate a subsequent
key update unless it has received an acknowledgment for a packet that was sent
protected with keys from the current key phase.  This ensures that keys are
available to both peers before another key update can be initiated.  This can be
implemented by tracking the lowest packet number sent with each key phase, and
the highest acknowledged packet number in the 1-RTT space: once the latter is
higher than or equal to the former, another key update can be initiated.

Note:

: Keys of packets other than the 1-RTT packets are never updated; their keys are
  derived solely from the TLS handshake state.

The endpoint that initiates a key update also updates the keys that it uses for
receiving packets.  These keys will be needed to process packets the peer sends
after updating.

An endpoint MUST retain old keys until it has successfully unprotected a packet
sent using the new keys.  An endpoint SHOULD retain old keys for some time
after unprotecting a packet sent using the new keys.  Discarding old keys too
early can cause delayed packets to be discarded.  Discarding packets will be
interpreted as packet loss by the peer and could adversely affect performance.


## Responding to a Key Update

A peer is permitted to initiate a key update after receiving an acknowledgment
of a packet in the current key phase.  An endpoint detects a key update when
processing a packet with a key phase that differs from the value used to protect
the last packet it sent.  To process this packet, the endpoint uses the next
packet protection key and IV.  See {{receive-key-generation}} for considerations
about generating these keys.

If a packet is successfully processed using the next key and IV, then the peer
has initiated a key update.  The endpoint MUST update its send keys to the
corresponding key phase in response, as described in {{key-update-initiate}}.
Sending keys MUST be updated before sending an acknowledgment for the packet
that was received with updated keys.  By acknowledging the packet that triggered
the key update in a packet protected with the updated keys, the endpoint signals
that the key update is complete.

An endpoint can defer sending the packet or acknowledgment according to its
normal packet sending behaviour; it is not necessary to immediately generate a
packet in response to a key update.  The next packet sent by the endpoint will
use the updated keys.  The next packet that contains an acknowledgment will
cause the key update to be completed.  If an endpoint detects a second update
before it has sent any packets with updated keys containing an
acknowledgment for the packet that initiated the key update, it indicates that
its peer has updated keys twice without awaiting confirmation.  An endpoint MAY
treat such consecutive key updates as a connection error of type
KEY_UPDATE_ERROR.

An endpoint that receives an acknowledgment that is carried in a packet
protected with old keys where any acknowledged packet was protected with newer
keys MAY treat that as a connection error of type KEY_UPDATE_ERROR.  This
indicates that a peer has received and acknowledged a packet that initiates a
key update, but has not updated keys in response.


## Timing of Receive Key Generation {#receive-key-generation}

Endpoints responding to an apparent key update MUST NOT generate a timing
side-channel signal that might indicate that the Key Phase bit was invalid (see
{{header-protect-analysis}}).  Endpoints can use dummy packet protection keys in
place of discarded keys when key updates are not yet permitted.  Using dummy
keys will generate no variation in the timing signal produced by attempting to
remove packet protection, and results in all packets with an invalid Key Phase
bit being rejected.

The process of creating new packet protection keys for receiving packets could
reveal that a key update has occurred. An endpoint MAY generate new keys as
part of packet processing, but this creates a timing signal that could be used
by an attacker to learn when key updates happen and thus leak the value of the
Key Phase bit.

Endpoints are generally expected to have current and next receive packet
protection keys available. For a short period after a key update completes, up
to the PTO, endpoints MAY defer generation of the next set of
receive packet protection keys. This allows endpoints
to retain only two sets of receive keys; see {{old-keys-recv}}.

Once generated, the next set of packet protection keys SHOULD be retained, even
if the packet that was received was subsequently discarded.  Packets containing
apparent key updates are easy to forge and - while the process of key update
does not require significant effort - triggering this process could be used by
an attacker for DoS.

For this reason, endpoints MUST be able to retain two sets of packet protection
keys for receiving packets: the current and the next.  Retaining the previous
keys in addition to these might improve performance, but this is not essential.


## Sending with Updated Keys {#old-keys-send}

An endpoint never sends packets that are protected with old keys.  Only the
current keys are used.  Keys used for protecting packets can be discarded
immediately after switching to newer keys.

Packets with higher packet numbers MUST be protected with either the same or
newer packet protection keys than packets with lower packet numbers.  An
endpoint that successfully removes protection with old keys when newer keys were
used for packets with lower packet numbers MUST treat this as a connection error
of type KEY_UPDATE_ERROR.


## Receiving with Different Keys {#old-keys-recv}

For receiving packets during a key update, packets protected with older keys
might arrive if they were delayed by the network.  Retaining old packet
protection keys allows these packets to be successfully processed.

As packets protected with keys from the next key phase use the same Key Phase
value as those protected with keys from the previous key phase, it is necessary
to distinguish between the two, if packets protected with old keys are to be
processed.  This can be done using packet numbers.  A recovered packet number
that is lower than any packet number from the current key phase uses the
previous packet protection keys; a recovered packet number that is higher than
any packet number from the current key phase requires the use of the next packet
protection keys.

Some care is necessary to ensure that any process for selecting between
previous, current, and next packet protection keys does not expose a timing side
channel that might reveal which keys were used to remove packet protection.  See
{{hp-side-channel}} for more information.

Alternatively, endpoints can retain only two sets of packet protection keys,
swapping previous for next after enough time has passed to allow for reordering
in the network.  In this case, the Key Phase bit alone can be used to select
keys.

An endpoint MAY allow a period of approximately the Probe Timeout (PTO; see
{{QUIC-RECOVERY}}) after promoting the next set of receive keys to be current
before it creates the subsequent set of packet protection keys. These updated
keys MAY replace the previous keys at that time. With the caveat that PTO is a
subjective measure - that is, a peer could have a different view of the RTT -
this time is expected to be long enough that any reordered packets would be
declared lost by a peer even if they were acknowledged and short enough to
allow a peer to initiate further key updates.

Endpoints need to allow for the possibility that a peer might not be able to
decrypt packets that initiate a key update during the period when the peer
retains old keys.  Endpoints SHOULD wait three times the PTO before initiating a
key update after receiving an acknowledgment that confirms that the previous key
update was received.  Failing to allow sufficient time could lead to packets
being discarded.

An endpoint SHOULD retain old read keys for no more than three times the PTO
after having received a packet protected using the new keys. After this period,
old read keys and their corresponding secrets SHOULD be discarded.


## Limits on AEAD Usage {#aead-limits}

This document sets usage limits for AEAD algorithms to ensure that overuse does
not give an adversary a disproportionate advantage in attacking the
confidentiality and integrity of communications when using QUIC.

The usage limits defined in TLS 1.3 exist for protection against attacks
on confidentiality and apply to successful applications of AEAD protection. The
integrity protections in authenticated encryption also depend on limiting the
number of attempts to forge packets. TLS achieves this by closing connections
after any record fails an authentication check. In comparison, QUIC ignores any
packet that cannot be authenticated, allowing multiple forgery attempts.

QUIC accounts for AEAD confidentiality and integrity limits separately. The
confidentiality limit applies to the number of packets encrypted with a given
key. The integrity limit applies to the number of packets decrypted within a
given connection. Details on enforcing these limits for each AEAD algorithm
follow below.

Endpoints MUST count the number of encrypted packets for each set of keys. If
the total number of encrypted packets with the same key exceeds the
confidentiality limit for the selected AEAD, the endpoint MUST stop using those
keys. Endpoints MUST initiate a key update before sending more protected packets
than the confidentiality limit for the selected AEAD permits. If a key update
is not possible or integrity limits are reached, the endpoint MUST stop using
the connection and only send stateless resets in response to receiving packets.
It is RECOMMENDED that endpoints immediately close the connection with a
connection error of type AEAD_LIMIT_REACHED before reaching a state where key
updates are not possible.

For AEAD_AES_128_GCM and AEAD_AES_256_GCM, the confidentiality limit is
2<sup>23</sup> encrypted packets; see {{gcm-bounds}}. For
AEAD_CHACHA20_POLY1305, the confidentiality limit is greater than the number of
possible packets (2<sup>62</sup>) and so can be disregarded. For
AEAD_AES_128_CCM, the confidentiality limit is 2<sup>21.5</sup> encrypted
packets; see {{ccm-bounds}}. Applying a limit reduces the probability that an
attacker can distinguish the AEAD in use from a random permutation; see
{{AEBounds}}, {{ROBUST}}, and {{?GCM-MU=DOI.10.1145/3243734.3243816}}.

In addition to counting packets sent, endpoints MUST count the number of
received packets that fail authentication during the lifetime of a connection.
If the total number of received packets that fail authentication within the
connection, across all keys, exceeds the integrity limit for the selected AEAD,
the endpoint MUST immediately close the connection with a connection error of
type AEAD_LIMIT_REACHED and not process any more packets.

For AEAD_AES_128_GCM and AEAD_AES_256_GCM, the integrity limit is 2<sup>52</sup>
invalid packets; see {{gcm-bounds}}. For AEAD_CHACHA20_POLY1305, the integrity
limit is 2<sup>36</sup> invalid packets; see {{AEBounds}}. For AEAD_AES_128_CCM,
the integrity limit is 2<sup>21.5</sup> invalid packets; see
{{ccm-bounds}}. Applying this limit reduces the probability that an attacker can
successfully forge a packet; see {{AEBounds}}, {{ROBUST}}, and {{?GCM-MU}}.

Endpoints that limit the size of packets MAY use higher confidentiality and
integrity limits; see {{aead-analysis}} for details.

Future analyses and specifications MAY relax confidentiality or integrity limits
for an AEAD.

Any TLS cipher suite that is specified for use with QUIC MUST define limits on
the use of the associated AEAD function that preserves margins for
confidentiality and integrity. That is, limits MUST be specified for the number
of packets that can be authenticated and for the number of packets that can fail
authentication.  Providing a reference to any analysis upon which values are
based - and any assumptions used in that analysis - allows limits to be adapted
to varying usage conditions.


## Key Update Error Code {#key-update-error}

The KEY_UPDATE_ERROR error code (0xe) is used to signal errors related to key
updates.


# Security of Initial Messages

Initial packets are not protected with a secret key, so they are subject to
potential tampering by an attacker.  QUIC provides protection against attackers
that cannot read packets, but does not attempt to provide additional protection
against attacks where the attacker can observe and inject packets.  Some forms
of tampering -- such as modifying the TLS messages themselves -- are detectable,
but some -- such as modifying ACKs -- are not.

For example, an attacker could inject a packet containing an ACK frame that
makes it appear that a packet had not been received or to create a false
impression of the state of the connection (e.g., by modifying the ACK Delay).
Note that such a packet could cause a legitimate packet to be dropped as a
duplicate.  Implementations SHOULD use caution in relying on any data that is
contained in Initial packets that is not otherwise authenticated.

It is also possible for the attacker to tamper with data that is carried in
Handshake packets, but because that tampering requires modifying TLS handshake
messages, that tampering will cause the TLS handshake to fail.


# QUIC-Specific Adjustments to the TLS Handshake - QUIC 对 TLS 握手的调整

Certain aspects of the TLS handshake are different when used with QUIC.

与 QUIC 一起使用时，TLS 握手的某些方面是不同的。

QUIC also requires additional features from TLS.  In addition to negotiation of
cryptographic parameters, the TLS handshake carries and authenticates values for
QUIC transport parameters.

QUIC 还需要 TLS 的其他特性。除了协商密码参数外，TLS 握手还携带并验证 QUIC 传输参数的值。

## Protocol Negotiation - 协议协商 {#protocol-negotiation}

QUIC requires that the cryptographic handshake provide authenticated protocol
negotiation.  TLS uses Application Layer Protocol Negotiation
({{!ALPN=RFC7301}}) to select an application protocol.  Unless another mechanism
is used for agreeing on an application protocol, endpoints MUST use ALPN for
this purpose.

QUIC 要求加密握手提供经过身份验证的协议协商。TLS 使用应用层协议协商 ({{!ALPN=RFC7301}})
来选择应用层协议。除非使用另一种机制来商定应用程序协议，否则端点必须为此使用 ALPN。

When using ALPN, endpoints MUST immediately close a connection (see {{Section
10.2 of QUIC-TRANSPORT}}) with a no_application_protocol TLS alert (QUIC error
code 0x178; see {{tls-errors}}) if an application protocol is not negotiated.
While {{!ALPN}} only specifies that servers use this alert, QUIC clients MUST
use error 0x178 to terminate a connection when ALPN negotiation fails.

在使用 ALPN 时，如果应用层协议没有协商，端点必须立即关闭带有 no_application_protocol
TLS 警报（QUIC 错误代码 0x178；见{{tls-errors}}）的连接（见 {{Section
10.2 of QUIC-TRANSPORT}}）。而 {{!ALPN}} 仅指定服务器使用此警报，当 ALPN 协商
失败时，QUIC 客户端必须使用错误 0x178 终止连接。

An application protocol MAY restrict the QUIC versions that it can operate over.
Servers MUST select an application protocol compatible with the QUIC version
that the client has selected.  The server MUST treat the inability to select a
compatible application protocol as a connection error of type 0x178
(no_application_protocol).  Similarly, a client MUST treat the selection of an
incompatible application protocol by a server as a connection error of type
0x178.

应用层协议可能会限制它可以操作的 QUIC 版本。服务器必须选择与客户端选择的 QUIC 版本
兼容的应用层协议。服务器必须将无法选择兼容的应用层协议视为 0x178 类型的连接错误
(no_application_protocol)。类似地，客户端必须将服务器选择的不兼容应用程序协议
视为 0x178 类型的连接错误。

## QUIC Transport Parameters Extension - QUIC 传输参数扩展 {#quic_parameters}

QUIC transport parameters are carried in a TLS extension. Different versions of
QUIC might define a different method for negotiating transport configuration.

QUIC 传输参数在 TLS 扩展中携带。不同版本的 QUIC 可能会定义不同的方法来协商传输配置。

Including transport parameters in the TLS handshake provides integrity
protection for these values.

在 TLS 握手中包含传输参数可以为这些值提供完整性保护。

~~~
   enum {
      quic_transport_parameters(0x39), (65535)
   } ExtensionType;
~~~

The extension_data field of the quic_transport_parameters extension contains a
value that is defined by the version of QUIC that is in use.

quic_transport_parameters扩展的extension_data字段包含一个值，该值由正在使用的 QUIC 版本定义。

The quic_transport_parameters extension is carried in the ClientHello and the
EncryptedExtensions messages during the handshake. Endpoints MUST send the
quic_transport_parameters extension; endpoints that receive ClientHello or
EncryptedExtensions messages without the quic_transport_parameters extension
MUST close the connection with an error of type 0x16d (equivalent to a fatal TLS
missing_extension alert, see {{tls-errors}}).

quic_transport_parameters 扩展在 ClientHello 和握手期间的加密数据中携带。端点必须
发送 quic_transport_parameters 扩展; 在没有 quic_transport_parameters 扩展的情况下
接收 ClientHello 或 EncryptedExtensions 消息的端点必须以 0x16d 错误类型关闭连接
（相当于 TLS missing_extension 警告，见 {{tls-errors}}）。

Transport parameters become available prior to the completion of the handshake.
A server might use these values earlier than handshake completion. However, the
value of transport parameters is not authenticated until the handshake
completes, so any use of these parameters cannot depend on their authenticity.
Any tampering with transport parameters will cause the handshake to fail.

传输参数在握手完成之前可用。服务器可能在握手完成之前使用这些值。但是，在握手完成
之前，传输参数的值未被验证，因此任何使用这些参数都不能依赖于他们的真实性。任何带
有传输参数的篡改都会导致握手失败。

Endpoints MUST NOT send this extension in a TLS connection that does not use
QUIC (such as the use of TLS with TCP defined in {{!TLS13}}).  A fatal
unsupported_extension alert MUST be sent by an implementation that supports this
extension if the extension is received when the transport is not QUIC.

终端不能在没有使用 QUIC 的 TLS 连接中发送此扩展（例如，如在 {{!TLS13}} 中定义了
使用 TCP 的 TLS）。如果在传输不是 QUIC 时接收到扩展，则支持此扩展的实现必须发送
unsupported_extension 警告。

Negotiating the quic_transport_parameters extension causes the EndOfEarlyData to
be removed; see {{remove-eoed}}.

协商 quic_transport_parameters 扩展会导致 EndOfEarlyData 被移除（见 {{remove-eoed}}）。

## Removing the EndOfEarlyData Message - 移除 EndOfEarlyData 消息 {#remove-eoed}

The TLS EndOfEarlyData message is not used with QUIC.  QUIC does not rely on
this message to mark the end of 0-RTT data or to signal the change to Handshake
keys.

TLS 的 EndOfEarlyData 消息不与 QUIC 一起使用。QUIC 不依赖此消息来标记 0-RTT 数据
的结束或向握手键发出更改信号。

Clients MUST NOT send the EndOfEarlyData message.  A server MUST treat receipt
of a CRYPTO frame in a 0-RTT packet as a connection error of type
PROTOCOL_VIOLATION.

客户端不能发送 EndOfEarlyData 消息。服务器必须将收到 0-RTT 数据包中的加密帧视为
违反协议类型的连接错误。

As a result, EndOfEarlyData does not appear in the TLS handshake transcript.

因此，EndOfEarlyData 不会出现在 TLS 握手记录中。

## Prohibit TLS Middlebox Compatibility Mode - 禁止 TLS 中间件兼容模式 {#compat-mode}

Appendix D.4 of {{!TLS13}} describes an alteration to the TLS 1.3 handshake as
a workaround for bugs in some middleboxes. The TLS 1.3 middlebox compatibility
mode involves setting the legacy_session_id field to a 32-byte value in the
ClientHello and ServerHello, then sending a change_cipher_spec record. Both
field and record carry no semantic content and are ignored.

{{!TLS13}} 附录 D.4 描述了对 TLS1.3 握手的更改作为一些中间件中错误的解决方法。
TLS1.3 中间件兼容模式涉及将 legacy_session_id 字段设置为 ClientHello 和 ServerHello 中的
32-byte，然后发送一个 change_cipher_spec 记录。这两个字段和记录都没有语义内容并被忽略。

This mode has no use in QUIC as it only applies to middleboxes that interfere
with TLS over TCP. QUIC also provides no means to carry a change_cipher_spec
record. A client MUST NOT request the use of the TLS 1.3 compatibility mode. A
server SHOULD treat the receipt of a TLS ClientHello with a non-empty
legacy_session_id field as a connection error of type PROTOCOL_VIOLATION.

这种模式在 QUIC 中没有用处，因为它只适用于通过 TLS over TCP 的中间件。
QUIC 也没有提供任何方法来携带 change_cipher_spec 记录。客户端不得请求
使用 TLS1.3 兼容模式。服务器应该将收到的 TLS ClientHello 处理为非空
legacy_session_id 字段，作为 PROTOCOL_VIOLATION 类型的连接错误。

# Security Considerations - 安全注意事项

All of the security considerations that apply to TLS also apply to the use of
TLS in QUIC. Reading all of {{!TLS13}} and its appendices is the best way to
gain an understanding of the security properties of QUIC.

所有适用于 TLS 的安全考虑也适用于在 QUIC 中使用的 TLS。阅读 {{!TLS13}} 及其附录
是了解 QUIC 安全性的最佳方法。

This section summarizes some of the more important security aspects specific to
the TLS integration, though there are many security-relevant details in the
remainder of the document.

本节概述了 TLS 集成中一些更重要的安全方面，尽管文档的其余部分中有许多与安全相关
的详细信息。

## Session Linkability - 会话关联

Use of TLS session tickets allows servers and possibly other entities to
correlate connections made by the same client; see {{resumption}} for details.

使用 TLS 会话凭证允许服务器和其他实体可能要关联的由同一个客户端建立的连接
（详细信息，见 {{resumption}}）。

## Replay Attacks with 0-RTT {#replay}

As described in {{Section 8 of TLS13}}, use of TLS early data comes with an
exposure to replay attack.  The use of 0-RTT in QUIC is similarly vulnerable to
replay attack.

Endpoints MUST implement and use the replay protections described in {{!TLS13}},
however it is recognized that these protections are imperfect.  Therefore,
additional consideration of the risk of replay is needed.

QUIC is not vulnerable to replay attack, except via the application protocol
information it might carry.  The management of QUIC protocol state based on the
frame types defined in {{QUIC-TRANSPORT}} is not vulnerable to replay.
Processing of QUIC frames is idempotent and cannot result in invalid connection
states if frames are replayed, reordered or lost.  QUIC connections do not
produce effects that last beyond the lifetime of the connection, except for
those produced by the application protocol that QUIC serves.

Note:

: TLS session tickets and address validation tokens are used to carry QUIC
  configuration information between connections.  Specifically, to enable a
  server to efficiently recover state that is used in connection establishment
  and address validation.  These MUST NOT be used to communicate application
  semantics between endpoints; clients MUST treat them as opaque values.  The
  potential for reuse of these tokens means that they require stronger
  protections against replay.

A server that accepts 0-RTT on a connection incurs a higher cost than accepting
a connection without 0-RTT.  This includes higher processing and computation
costs.  Servers need to consider the probability of replay and all associated
costs when accepting 0-RTT.

Ultimately, the responsibility for managing the risks of replay attacks with
0-RTT lies with an application protocol.  An application protocol that uses QUIC
MUST describe how the protocol uses 0-RTT and the measures that are employed to
protect against replay attack.  An analysis of replay risk needs to consider
all QUIC protocol features that carry application semantics.

Disabling 0-RTT entirely is the most effective defense against replay attack.

QUIC extensions MUST describe how replay attacks affect their operation, or
prohibit their use in 0-RTT.  Application protocols MUST either prohibit the use
of extensions that carry application semantics in 0-RTT or provide replay
mitigation strategies.


## Packet Reflection Attack Mitigation {#reflection}

A small ClientHello that results in a large block of handshake messages from a
server can be used in packet reflection attacks to amplify the traffic generated
by an attacker.

QUIC includes three defenses against this attack. First, the packet containing
a ClientHello MUST be padded to a minimum size. Second, if responding to an
unverified source address, the server is forbidden to send more than three
times as many bytes as the number of bytes it has received (see {{Section 8.1
of QUIC-TRANSPORT}}). Finally, because acknowledgments of Handshake packets are
authenticated, a blind attacker cannot forge them. Put together, these defenses
limit the level of amplification.


## Header Protection Analysis {#header-protect-analysis}

{{?NAN=DOI.10.1007/978-3-030-26948-7_9}} analyzes authenticated encryption
algorithms that provide nonce privacy, referred to as "Hide Nonce" (HN)
transforms. The general header protection construction in this document is
one of those algorithms (HN1). Header protection is applied after the packet
protection AEAD, sampling a set of bytes (`sample`) from the AEAD output and
encrypting the header field using a pseudorandom function (PRF) as follows:

~~~
protected_field = field XOR PRF(hp_key, sample)
~~~

The header protection variants in this document use a pseudorandom permutation
(PRP) in place of a generic PRF. However, since all PRPs are also PRFs {{IMC}},
these variants do not deviate from the HN1 construction.

As `hp_key` is distinct from the packet protection key, it follows that header
protection achieves AE2 security as defined in {{NAN}} and therefore guarantees
privacy of `field`, the protected packet header. Future header protection
variants based on this construction MUST use a PRF to ensure equivalent
security guarantees.

Use of the same key and ciphertext sample more than once risks compromising
header protection. Protecting two different headers with the same key and
ciphertext sample reveals the exclusive OR of the protected fields.  Assuming
that the AEAD acts as a PRF, if L bits are sampled, the odds of two ciphertext
samples being identical approach 2<sup>-L/2</sup>, that is, the birthday bound.
For the algorithms described in this document, that probability is one in
2<sup>64</sup>.

To prevent an attacker from modifying packet headers, the header is transitively
authenticated using packet protection; the entire packet header is part of the
authenticated additional data.  Protected fields that are falsified or modified
can only be detected once the packet protection is removed.


## Header Protection Timing Side-Channels {#hp-side-channel}

An attacker could guess values for packet numbers or Key Phase and have an
endpoint confirm guesses through timing side channels.  Similarly, guesses for
the packet number length can be tried and exposed.  If the recipient of a
packet discards packets with duplicate packet numbers without attempting to
remove packet protection they could reveal through timing side-channels that the
packet number matches a received packet.  For authentication to be free from
side-channels, the entire process of header protection removal, packet number
recovery, and packet protection removal MUST be applied together without timing
and other side-channels.

For the sending of packets, construction and protection of packet payloads and
packet numbers MUST be free from side-channels that would reveal the packet
number or its encoded size.

During a key update, the time taken to generate new keys could reveal through
timing side-channels that a key update has occurred.  Alternatively, where an
attacker injects packets this side-channel could reveal the value of the Key
Phase on injected packets.  After receiving a key update, an endpoint SHOULD
generate and save the next set of receive packet protection keys, as described
in {{receive-key-generation}}.  By generating new keys before a key update is
received, receipt of packets will not create timing signals that leak the value
of the Key Phase.

This depends on not doing this key generation during packet processing and it
can require that endpoints maintain three sets of packet protection keys for
receiving: for the previous key phase, for the current key phase, and for the
next key phase.  Endpoints can instead choose to defer generation of the next
receive packet protection keys until they discard old keys so that only two sets
of receive keys need to be retained at any point in time.


## Key Diversity

In using TLS, the central key schedule of TLS is used.  As a result of the TLS
handshake messages being integrated into the calculation of secrets, the
inclusion of the QUIC transport parameters extension ensures that handshake and
1-RTT keys are not the same as those that might be produced by a server running
TLS over TCP.  To avoid the possibility of cross-protocol key synchronization,
additional measures are provided to improve key separation.

The QUIC packet protection keys and IVs are derived using a different label than
the equivalent keys in TLS.

To preserve this separation, a new version of QUIC SHOULD define new labels for
key derivation for packet protection key and IV, plus the header protection
keys.  This version of QUIC uses the string "quic".  Other versions can use a
version-specific label in place of that string.

The initial secrets use a key that is specific to the negotiated QUIC version.
New QUIC versions SHOULD define a new salt value used in calculating initial
secrets.


## Randomness

QUIC depends on endpoints being able to generate secure random numbers, both
directly for protocol values such as the connection ID, and transitively via
TLS. See {{!RFC4086}} for guidance on secure random number generation.


# IANA Considerations

IANA has registered a codepoint of 57 (or 0x39) for the
quic_transport_parameters extension (defined in {{quic_parameters}}) in the TLS
ExtensionType Values Registry {{!TLS-REGISTRIES=RFC8447}}.

The Recommended column for this extension is marked Yes. The TLS 1.3 Column
includes CH and EE.


--- back

# Sample Packet Protection {#test-vectors}

This section shows examples of packet protection so that implementations can be
verified incrementally. Samples of Initial packets from both client and server,
plus a Retry packet are defined. These packets use an 8-byte client-chosen
Destination Connection ID of 0x8394c8f03e515708. Some intermediate values are
included. All values are shown in hexadecimal.


## Keys

The labels generated during the execution of the HKDF-Expand-Label function
(that is, HkdfLabel.label) and part of the value given to the HKDF-Expand
function in order to produce its output are:

client in:
: 00200f746c73313320636c69656e7420696e00

server in:
: 00200f746c7331332073657276657220696e00

quic key:
: 00100e746c7331332071756963206b657900

quic iv:
: 000c0d746c733133207175696320697600

quic hp:
: 00100d746c733133207175696320687000

The initial secret is common:

~~~
initial_secret = HKDF-Extract(initial_salt, cid)
    = 7db5df06e7a69e432496adedb0085192
      3595221596ae2ae9fb8115c1e9ed0a44
~~~

The secrets for protecting client packets are:

~~~
client_initial_secret
    = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    = c00cf151ca5be075ed0ebfb5c80323c4
      2d6b7db67881289af4008f1f6c357aea

key = HKDF-Expand-Label(client_initial_secret, "quic key", "", 16)
    = 1f369613dd76d5467730efcbe3b1a22d

iv  = HKDF-Expand-Label(client_initial_secret, "quic iv", "", 12)
    = fa044b2f42a3fd3b46fb255c

hp  = HKDF-Expand-Label(client_initial_secret, "quic hp", "", 16)
    = 9f50449e04a0e810283a1e9933adedd2
~~~

The secrets for protecting server packets are:

~~~
server_initial_secret
    = HKDF-Expand-Label(initial_secret, "server in", "", 32)
    = 3c199828fd139efd216c155ad844cc81
      fb82fa8d7446fa7d78be803acdda951b

key = HKDF-Expand-Label(server_initial_secret, "quic key", "", 16)
    = cf3a5331653c364c88f0f379b6067e37

iv  = HKDF-Expand-Label(server_initial_secret, "quic iv", "", 12)
    = 0ac1493ca1905853b0bba03e

hp  = HKDF-Expand-Label(server_initial_secret, "quic hp", "", 16)
    = c206b8d9b9f0f37644430b490eeaa314
~~~


## Client Initial {#sample-client-initial}

The client sends an Initial packet.  The unprotected payload of this packet
contains the following CRYPTO frame, plus enough PADDING frames to make a
1162-byte payload:

~~~
060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
0d0010000e0403050306030203080408 050806002d00020101001c0002400100
3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
75300901100f088394c8f03e51570806 048000ffff
~~~

The unprotected header indicates a length of 1182 bytes: the 4-byte packet
number, 1162 bytes of frames, and the 16-byte authentication tag.  The header
includes the connection ID and a packet number of 2:

~~~
c300000001088394c8f03e5157080000449e00000002
~~~

Protecting the payload produces output that is sampled for header protection.
Because the header uses a 4-byte packet number encoding, the first 16 bytes of
the protected payload is sampled, then applied to the header:

~~~
sample = d1b1c98dd7689fb8ec11d242b123dc9b

mask = AES-ECB(hp, sample)[0..4]
     = 437b9aec36

header[0] ^= mask[0] & 0x0f
     = c0
header[18..21] ^= mask[1..4]
     = 7b9aec34
header = c000000001088394c8f03e5157080000449e7b9aec34
~~~

The resulting protected packet is:

~~~
c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11
d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399
1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c
8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212
30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5
457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208
4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec
4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3
485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db
059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c
7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8
9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556
be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74
68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a
c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00
f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632
291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964
25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd
14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff
ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198
e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd
c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73
203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f
cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e
fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade
a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047
90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2
162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4
40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0
6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e
8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0
be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400
54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab
760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9
f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4
056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064
7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241
e221af44860018ab0856972e194cd934
~~~


## Server Initial

The server sends the following payload in response, including an ACK frame, a
CRYPTO frame, and no PADDING frames:

~~~
02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739
88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94
0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00
020304
~~~

The header from the server includes a new connection ID and a 2-byte packet
number encoding for a packet number of 1:

~~~
c1000000010008f067a5502a4262b50040750001
~~~

As a result, after protection, the header protection sample is taken starting
from the third protected byte:

~~~
sample = 2cd0991cd25b0aac406a5816b6394100
mask   = 2ec0d8356a
header = cf000000010008f067a5502a4262b5004075c0d9
~~~

The final protected packet is then:

~~~
cf000000010008f067a5502a4262b500 4075c0d95a482cd0991cd25b0aac406a
5816b6394100f37a1c69797554780bb3 8cc5a99f5ede4cf73c3ec2493a1839b3
dbcba3f6ea46c5b7684df3548e7ddeb9 c3bf9c73cc3f3bded74b562bfb19fb84
022f8ef4cdd93795d77d06edbb7aaf2f 58891850abbdca3d20398c276456cbc4
2158407dd074ee
~~~


## Retry

This shows a Retry packet that might be sent in response to the Initial packet
in {{sample-client-initial}}. The integrity check includes the client-chosen
connection ID value of 0x8394c8f03e515708, but that value is not
included in the final Retry packet:

~~~
ff000000010008f067a5502a4262b574 6f6b656e04a265ba2eff4d829058fb3f
0f2496ba
~~~


## ChaCha20-Poly1305 Short Header Packet

This example shows some of the steps required to protect a packet with
a short header.  This example uses AEAD_CHACHA20_POLY1305.

In this example, TLS produces an application write secret from which a server
uses HKDF-Expand-Label to produce four values: a key, an IV, a header
protection key, and the secret that will be used after keys are updated (this
last value is not used further in this example).

~~~
secret
    = 9ac312a7f877468ebe69422748ad00a1
      5443f18203a07d6060f688f30f21632b

key = HKDF-Expand-Label(secret, "quic key", "", 32)
    = c6d98ff3441c3fe1b2182094f69caa2e
      d4b716b65488960a7a984979fb23e1c8

iv  = HKDF-Expand-Label(secret, "quic iv", "", 12)
    = e0459b3474bdd0e44a41c144

hp  = HKDF-Expand-Label(secret, "quic hp", "", 32)
    = 25a282b9e82f06f21f488917a4fc8f1b
      73573685608597d0efcb076b0ab7a7a4

ku  = HKDF-Expand-Label(secret, "quic ku", "", 32)
    = 1223504755036d556342ee9361d25342
      1a826c9ecdf3c7148684b36b714881f9
~~~

The following shows the steps involved in protecting a minimal packet with an
empty Destination Connection ID. This packet contains a single PING frame (that
is, a payload of just 0x01) and has a packet number of 654360564. In this
example, using a packet number of length 3 (that is, 49140 is encoded) avoids
having to pad the payload of the packet; PADDING frames would be needed if the
packet number is encoded on fewer bytes.

~~~
pn                 = 654360564 (decimal)
nonce              = e0459b3474bdd0e46d417eb0
unprotected header = 4200bff4
payload plaintext  = 01
payload ciphertext = 655e5cd55c41f69080575d7999c25a5bfb
~~~

The resulting ciphertext is the minimum size possible. One byte is skipped to
produce the sample for header protection.

~~~
sample = 5e5cd55c41f69080575d7999c25a5bfb
mask   = aefefe7d03
header = 4cfe4189
~~~

The protected packet is the smallest possible packet size of 21 bytes.

~~~
packet = 4cfe4189655e5cd55c41f69080575d7999c25a5bfb
~~~


# AEAD Algorithm Analysis {#aead-analysis}

This section documents analyses used in deriving AEAD algorithm limits for
AEAD_AES_128_GCM, AEAD_AES_128_CCM, and AEAD_AES_256_GCM. The analyses that
follow use symbols for multiplication (*), division (/), and exponentiation (^),
plus parentheses for establishing precedence. The following symbols are also
used:

t:

: The size of the authentication tag in bits. For these ciphers, t is 128.

n:

: The size of the block function in bits. For these ciphers, n is 128.

k:

: The size of the key in bits. This is 128 for AEAD_AES_128_GCM and
  AEAD_AES_128_CCM; 256 for AEAD_AES_256_GCM.

l:

: The number of blocks in each packet (see below).

q:

: The number of genuine packets created and protected by endpoints. This value
  is the bound on the number of packets that can be protected before updating
  keys.

v:

: The number of forged packets that endpoints will accept. This value is the
  bound on the number of forged packets that an endpoint can reject before
  updating keys.

o:

: The amount of offline ideal cipher queries made by an adversary.

The analyses that follow rely on a count of the number of block operations
involved in producing each message. This analysis is performed for packets of
size up to 2<sup>11</sup> (l = 2<sup>7</sup>) and 2<sup>16</sup> (l =
2<sup>12</sup>). A size of 2<sup>11</sup> is expected to be a limit that matches
common deployment patterns, whereas the 2<sup>16</sup> is the maximum possible
size of a QUIC packet. Only endpoints that strictly limit packet size can use
the larger confidentiality and integrity limits that are derived using the
smaller packet size.

For AEAD_AES_128_GCM and AEAD_AES_256_GCM, the message length (l) is the length
of the associated data in blocks plus the length of the plaintext in blocks.

For AEAD_AES_128_CCM, the total number of block cipher operations is the sum of:
the length of the associated data in blocks, the length of the ciphertext in
blocks, the length of the plaintext in blocks, plus 1. In this analysis, this is
simplified to a value of twice the length of the packet in blocks (that is,
<tt>2l = 2<sup>8</sup></tt> for packets that are limited to 2<sup>11</sup>
bytes, or <tt>2l = 2<sup>13</sup></tt> otherwise). This simplification is based
on the packet containing all of the associated data and ciphertext. This results
in a 1 to 3 block overestimation of the number of operations per packet.


## Analysis of AEAD_AES_128_GCM and AEAD_AES_256_GCM Usage Limits {#gcm-bounds}

{{?GCM-MU}} specify concrete bounds for AEAD_AES_128_GCM and AEAD_AES_256_GCM as
used in TLS 1.3 and QUIC. This section documents this analysis using several
simplifying assumptions:

- The number of ciphertext blocks an attacker uses in forgery attempts is
bounded by v * l, the number of forgery attempts and the size of each packet (in
blocks).

- The amount of offline work done by an attacker does not dominate other factors
in the analysis.

The bounds in {{?GCM-MU}} are tighter and more complete than those used in
{{AEBounds}}, which allows for larger limits than those described in
{{?TLS13}}.


### Confidentiality Limit

For confidentiality, Theorum (4.3) in {{?GCM-MU}} establishes that - for a
single user that does not repeat nonces - the dominant term in determining the
distinguishing advantage between a real and random AEAD algorithm gained by an
attacker is:

~~~
2 * (q * l)^2 / 2^n
~~~

For a target advantage of 2<sup>-57</sup>, this results in the relation:

~~~
q <= 2^35 / l
~~~

Thus, endpoints that do not send packets larger than 2<sup>11</sup> bytes cannot
protect more than 2<sup>28</sup> packets in a single connection without causing
an attacker to gain an larger advantage than the target of 2<sup>-57</sup>. The
limit for endpoints that allow for the packet size to be as large as
2<sup>16</sup> is instead 2<sup>23</sup>.


### Integrity Limit

For integrity, Theorem (4.3) in {{?GCM-MU}} establishes that an attacker gains
an advantage in successfully forging a packet of no more than:

~~~
(1 / 2^(8 * n)) + ((2 * v) / 2^(2 * n))
        + ((2 * o * v) / 2^(k + n)) + (n * (v + (v * l)) / 2^k)
~~~

The goal is to limit this advantage to 2<sup>-57</sup>.  For AEAD_AES_128_GCM,
the fourth term in this inequality dominates the rest, so the others can be
removed without significant effect on the result. This produces the following
approximation:

~~~
v <= 2^64 / l
~~~

Endpoints that do not attempt to remove protection from packets larger than
2<sup>11</sup> bytes can attempt to remove protection from at most
2<sup>57</sup> packets. Endpoints that do not restrict the size of processed
packets can attempt to remove protection from at most 2<sup>52</sup> packets.

For AEAD_AES_256_GCM, the same term dominates, but the larger value of k
produces the following approximation:

~~~
v <= 2^192 / l
~~~

This is substantially larger than the limit for AEAD_AES_128_GCM.  However, this
document recommends that the same limit be applied to both functions as either
limit is acceptably large.


## Analysis of AEAD_AES_128_CCM Usage Limits {#ccm-bounds}

TLS {{?TLS13}} and {{AEBounds}} do not specify limits on usage
for AEAD_AES_128_CCM. However, any AEAD that is used with QUIC requires limits
on use that ensure that both confidentiality and integrity are preserved. This
section documents that analysis.

{{?CCM-ANALYSIS=DOI.10.1007/3-540-36492-7_7}} is used as the basis of this
analysis. The results of that analysis are used to derive usage limits that are
based on those chosen in {{?TLS13}}.

For confidentiality, Theorem 2 in {{?CCM-ANALYSIS}} establishes that an attacker
gains a distinguishing advantage over an ideal pseudorandom permutation (PRP) of
no more than:

~~~
(2l * q)^2 / 2^n
~~~

The integrity limit in Theorem 1 in {{?CCM-ANALYSIS}} provides an attacker a
strictly higher advantage for the same number of messages. As the targets for
the confidentiality advantage and the integrity advantage are the same, only
Theorem 1 needs to be considered.

Theorem 1 establishes that an attacker gains an advantage over an
ideal PRP of no more than:

~~~
v / 2^t + (2l * (v + q))^2 / 2^n
~~~

As `t` and `n` are both 128, the first term is negligible relative to the
second, so that term can be removed without a significant effect on the result.

This produces a relation that combines both encryption and decryption attempts
with the same limit as that produced by the theorem for confidentiality alone.
For a target advantage of 2<sup>-57</sup>, this results in:

~~~
v + q <= 2^34.5 / l
~~~

By setting `q = v`, values for both confidentiality and integrity limits can be
produced. Endpoints that limit packets to 2<sup>11</sup> bytes therefore have
both confidentiality and integrity limits of 2<sup>26.5</sup> packets. Endpoints
that do not restrict packet size have a limit of 2<sup>21.5</sup>.


# Change Log

> **RFC Editor's Note:** Please remove this section prior to publication of a
> final version of this document.

Issue and pull request numbers are listed with a leading octothorp.

## Since draft-ietf-quic-tls-32

- Added final values for Initial key derivation, Retry authentication, and TLS
  extension type for the QUIC Transport Parameters extension (#4431)
  (#4431)

- Corrected rules for handling of 0-RTT (#4393, #4394)

## Since draft-ietf-quic-tls-31

- Packet protection limits are based on maximum-sized packets; improved
  analysis (#3701, #4175)

## Since draft-ietf-quic-tls-30

- Add a new error code for AEAD_LIMIT_REACHED code to avoid conflict (#4087,
  #4088)

## Since draft-ietf-quic-tls-29

- Updated limits on packet protection (#3788, #3789)
- Allow for packet processing to continue while waiting for TLS to provide
  keys (#3821, #3874)

## Since draft-ietf-quic-tls-28

- Defined limits on the number of packets that can be protected with a single
  key and limits on the number of packets that can fail authentication (#3619,
  #3620)
- Update Initial salt, Retry keys, and samples (#3711)

## Since draft-ietf-quic-tls-27

- Allowed CONNECTION_CLOSE in any packet number space, with restrictions on
  use of the application-specific variant (#3430, #3435, #3440)
- Prohibit the use of the compatibility mode from TLS 1.3 (#3594, #3595)

## Since draft-ietf-quic-tls-26

- No changes

## Since draft-ietf-quic-tls-25

- No changes

## Since draft-ietf-quic-tls-24

- Rewrite key updates (#3050)
  - Allow but don't recommend deferring key updates (#2792, #3263)
  - More completely define received behavior (#2791)
  - Define the label used with HKDF-Expand-Label (#3054)

## Since draft-ietf-quic-tls-23

- Key update text update (#3050):
  - Recommend constant-time key replacement (#2792)
  - Provide explicit labels for key update key derivation (#3054)
- Allow first Initial from a client to span multiple packets (#2928, #3045)
- PING can be sent at any encryption level (#3034, #3035)


## Since draft-ietf-quic-tls-22

- Update the salt used for Initial secrets (#2887, #2980)


## Since draft-ietf-quic-tls-21

- No changes


## Since draft-ietf-quic-tls-20

- Mandate the use of the QUIC transport parameters extension (#2528, #2560)
- Define handshake completion and confirmation; define clearer rules when it
  encryption keys should be discarded (#2214, #2267, #2673)


## Since draft-ietf-quic-tls-18

- Increased the set of permissible frames in 0-RTT (#2344, #2355)
- Transport parameter extension is mandatory (#2528, #2560)


## Since draft-ietf-quic-tls-17

- Endpoints discard initial keys as soon as handshake keys are available (#1951,
  #2045)
- Use of ALPN or equivalent is mandatory (#2263, #2284)


## Since draft-ietf-quic-tls-14

- Update the salt used for Initial secrets (#1970)
- Clarify that TLS_AES_128_CCM_8_SHA256 isn't supported (#2019)
- Change header protection
  - Sample from a fixed offset (#1575, #2030)
  - Cover part of the first byte, including the key phase (#1322, #2006)
- TLS provides an AEAD and KDF function (#2046)
  - Clarify that the TLS KDF is used with TLS (#1997)
  - Change the labels for calculation of QUIC keys (#1845, #1971, #1991)
- Initial keys are discarded once Handshake keys are available (#1951, #2045)


## Since draft-ietf-quic-tls-13

- Updated to TLS 1.3 final (#1660)


## Since draft-ietf-quic-tls-12

- Changes to integration of the TLS handshake (#829, #1018, #1094, #1165, #1190,
  #1233, #1242, #1252, #1450)
  - The cryptographic handshake uses CRYPTO frames, not stream 0
  - QUIC packet protection is used in place of TLS record protection
  - Separate QUIC packet number spaces are used for the handshake
  - Changed Retry to be independent of the cryptographic handshake
  - Limit the use of HelloRetryRequest to address TLS needs (like key shares)
- Changed codepoint of TLS extension (#1395, #1402)


## Since draft-ietf-quic-tls-11

- Encrypted packet numbers.


## Since draft-ietf-quic-tls-10

- No significant changes.


## Since draft-ietf-quic-tls-09

- Cleaned up key schedule and updated the salt used for handshake packet
  protection (#1077)


## Since draft-ietf-quic-tls-08

- Specify value for max_early_data_size to enable 0-RTT (#942)
- Update key derivation function (#1003, #1004)


## Since draft-ietf-quic-tls-07

- Handshake errors can be reported with CONNECTION_CLOSE (#608, #891)


## Since draft-ietf-quic-tls-05

No significant changes.


## Since draft-ietf-quic-tls-04

- Update labels used in HKDF-Expand-Label to match TLS 1.3 (#642)


## Since draft-ietf-quic-tls-03

No significant changes.


## Since draft-ietf-quic-tls-02

- Updates to match changes in transport draft


## Since draft-ietf-quic-tls-01

- Use TLS alerts to signal TLS errors (#272, #374)
- Require ClientHello to fit in a single packet (#338)
- The second client handshake flight is now sent in the clear (#262, #337)
- The QUIC header is included as AEAD Associated Data (#226, #243, #302)
- Add interface necessary for client address validation (#275)
- Define peer authentication (#140)
- Require at least TLS 1.3 (#138)
- Define transport parameters as a TLS extension (#122)
- Define handling for protected packets before the handshake completes (#39)
- Decouple QUIC version and ALPN (#12)


## Since draft-ietf-quic-tls-00

- Changed bit used to signal key phase
- Updated key phase markings during the handshake
- Added TLS interface requirements section
- Moved to use of TLS exporters for key derivation
- Moved TLS error code definitions into this document

## Since draft-thomson-quic-tls-01

- Adopted as base for draft-ietf-quic-tls
- Updated authors/editors list
- Added status note


# Contributors
{:numbered="false"}

The IETF QUIC Working Group received an enormous amount of support from many
people. The following people provided substantive contributions to this
document:

- Adam Langley
- Alessandro Ghedini
- Christian Huitema
- Christopher Wood
- David Schinazi
- Dragana Damjanovic
- Eric Rescorla
- Felix Günther
- Ian Swett
- Jana Iyengar
- <t><t><contact asciiFullname="Kazuho Oku" fullname="奥 一穂"/></t></t>
- Marten Seemann
- Martin Duke
- Mike Bishop
- <t><t><contact fullname="Mikkel Fahnøe Jørgensen"/></t></t>
- Nick Banks
- Nick Harper
- Roberto Peon
- Rui Paulo
- Ryan Hamilton
- Victor Vasiliev
