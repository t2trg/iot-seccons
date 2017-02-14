---
abbrev: Security Considerations for the IoT
title: Security Considerations in the IP-based Internet of Things
docname: draft-irtf-t2trg-iot-seccons
cat: info
stand_alone: true
informative:
  RFC6568: 
  RFC2818: 
  RFC6345: 
  RFC7252:
  RFC7390:
  RFC7696:
  ID-Daniel:
    title: IPv6 over Low Power WPAN Security Analysis
    author:
    - ins: S. Park
    - ins: K. Kim
    - ins: W. Haddad
    - ins: S. Chakrabarti
    - ins: J. Laganier
    date: 2011-03
    seriesinfo:
      Internet: Draft draft-daniel-6lowpan-security-analysis-05
  ID-HIP:
    title: HIP Diet EXchange (DEX)
    author:
    - ins: R. Moskowitz
    date: 2012-05
    seriesinfo:
      draft-moskowitz-hip-rg-dex-06: "(work in progress)"
  ID-Hartke:
    title: Datagram Transport Layer Security in Constrained Environments
    author:
    - ins: K. Hartke
    - ins: O. Bergmann
    date: 2012-07
    seriesinfo:
      draft-hartke-core-codtls-02: "(work in progress)"
  RFC7401:
  ID-Nikander:
    title: A Bound End-to-End Tunnel(BEET) mode for ESP
    author:
    - ins: P. Nikander
    - ins: J. Melen
    date: 2008-08
    seriesinfo:
      draft-nikander-esp-beet-mode-09: ''
  ID-OFlynn:
    title: Security Bootstrapping of Resource-Constrained Devices
    author:
    - ins: C. O'Flynn
    - ins: B. Sarikaya
    - ins: Y. Ohba
    - ins: Z. Cao
    - ins: R. Cragie
    date: 2010-11
    seriesinfo:
      draft-oflynn-core-bootstrapping-03: "(work in progress)"
  ID-Tsao:
    title: A Security Framework for Routing over Low Power and Lossy Networks
    author:
    - ins: T. Tsao
    - ins: R. Alexander
    - ins: M. Dohler
    - ins: V. Daza
    - ins: A. Lozano
    date: 2012-01
    seriesinfo:
      draft-ietf-roll-security-framework-07: ''
  ID-Moore:
    title: Best Current Practices for Securing Internet of Things (IoT) Devices
    author:
    - ins: K. Moore
    - ins: R. Barnes
    - ins: H. Tschofenig
    date: 2016-10
    seriesinfo:
      draft-moore-iot-security-bcp-00: ''    
  ID-Williams:
    title: Mobile DTLS
    author:
    - ins: M. Williams
    - ins: J. Barrett
    date: 2009-03
    seriesinfo:
      draft-barrett-mobile-dtls-00: ''
  ID-proHTTPCoAP:
    title: Best practices for HTTP-CoAP mapping implementation
    author:
    - ins: A. Castellani
    - ins: S. Loreto
    - ins: A. Rahman
    - ins: T. Fossati
    - ins: E. Dijk
    date: 2013-02
    seriesinfo:
      draft-castellani-core-http-mapping-07(work: in progress)
  ID-OSCOAP:
    title: Object Security of CoAP (OSCOAP)
    author:
    - ins: G. Selander
    - ins: J. Mattsson
    - ins: F. Palombini
    - ins: L. Seitz    
    date: 2016-07    
    seriesinfo:
      draft-selander-ace-object-security-05  
  ENISA_ICS:
    title: "Communication network dependencies for ICS/SCADA Systems"
    date: 2017-02
    seriesinfo: European Union Agency For Network And Information Security
  ID-bootstrap:
    title: "Secure IoT Bootstrapping : A Survey"
    author:
    - ins: B. Sarikaya
    - ins: M. Sethi
    date: 2016-07
    seriesinfo:
      draft-sarikaya-t2trg-sbootstrapping-01
  RFC3261: 
  RFC3748: 
  RFC3756: 
  RFC3833: 
  RFC4016: 
  RFC5246: 
  RFC4251: 
  RFC7296: 
  RFC4555: 
  RFC4621: 
  RFC4738: 
  RFC4919: 
  RFC4944: 
  RFC5191: 
  RFC5206: 
  RFC5238: 
  RFC5713: 
  RFC5903: 
  RFC2119:
  AUTO-ID:
    title: AUTO-ID LABS
    date: 2010-09
    seriesinfo:
      Web: http://www.autoidlabs.org/
  BACNET:
    title: BACnet
    date: 2011-02
    seriesinfo:
      Web: http://www.bacnet.org/
  DALI:
    title: DALI
    date: 2011-02
    seriesinfo:
      Web: http://www.dalibydesign.us/dali.html
  JOURNAL-Perrig:
    title: 'SPINS: Security protocols for Sensor Networks'
    author:
    - ins: A. Perrig
    - ins: R. Szewczyk
    - ins: V. Wen
    - ins: D. Culler
    - ins: J. Tygar
    date: 2002-09
    seriesinfo:
      Journal: Wireless Networks
  NIST:
    title: NIST Specification Publication 800-38B
    author:
    - ins: M. Dworkin
    date: 2005
  SPEKE:
    title: 'IEEE P1363.2: Password-based Cryptography'
    date: 2008
  PROC-Chan:
    title: Random Key Predistribution Schemes for Sensor Networks
    author:
    - ins: H. Chan
    - ins: A. Perrig
    - ins: D. Song
    date: 2003
    seriesinfo:
      Proceedings: IEEE Symposium on Security and Privacy
  PROC-Gupta:
    title: 'Sizzle: A Standards-based End-to-End Security Architecture for the Embedded
      Internet'
    author:
    - ins: V. Gupta
    - ins: M. Wurm
    - ins: Y. Zhu
    - ins: M. Millard
    - ins: S. Fung
    - ins: N. Gura
    - ins: H. Eberle
    - ins: S. Shantz
    date: 2005
    seriesinfo:
      Proceedings: Pervasive Computing and Communications (PerCom)
  PROC-Smetters-02:
    title: 'Talking To Strangers: Authentication in Ad-Hoc Wireless Networks'
    author:
    - ins: D. Balfanz
    - ins: D. Smetters
    - ins: P. Steward
    - ins: H. Chi Wong,
    date: 2002
    seriesinfo:
      Paper: NDSS
  Ziegeldorf:
    title: 'Privacy in the Internet of Things: Threats and Challenges'
    author:
    - ins: J.H. Ziegeldorf
    - ins: O. Garcia-Morchon
    - ins: K. Wehrle,
    date: 2013
    seriesinfo:
      Paper: Security and Communication Networks - Special Issue on Security in a Completely Interconnected World
  d2dsecurity:
    title: 'Security and Privacy in Device-to-Device (D2D) Communication: A Review'
    author:
    - ins: M. Haus
    - ins: M. Waqas
    - ins: A. Ding
    - ins: Y. Li
    - ins: S. Tarkoma
    - ins: J. Ott
    date: 2016
    seriesinfo:
      Paper: IEEE Communications Surveys and Tutorials
  PROC-Smetters-04:
    title: 'Network-in-a-Box: How to Set Up a Secure Wireless Network in Under a Minute'
    author:
    - ins: D. Balfanz
    - ins: G. Durfee
    - ins: R. Grinter
    - ins: D. Smetters
    - ins: P. Steward
    date: 2004
    seriesinfo:
      Paper: USENIX
  PROC-Stajano-99:
    title: Resurrecting Duckling - Security Issues for Adhoc Wireless Networks
    author:
    - ins: F. Stajano
    - ins: R. Anderson
    date: 1999-11
    seriesinfo:
      7th: International Workshop Proceedings
  THESIS-Langheinrich:
    title: Personal Privacy in Ubiquitous Computing
    author:
    - ins: M. Langheinrich
    date: 2005
    seriesinfo:
      PhD: Thesis ETH Zurich
  TinyDTLS:
    title: TinyDTLS
    date: 2012-02
    seriesinfo:
      Web: http://tinydtls.sourceforge.net/
  WG-6LoWPAN:
    title: IETF 6LoWPAN Working Group
    date: 2011-02
    seriesinfo:
      Web: http://tools.ietf.org/wg/6lowpan/
  WG-CoRE:
    title: IETF Constrained RESTful Environment (CoRE) Working Group
    date: 2011-02
    seriesinfo:
      Web: https://datatracker.ietf.org/wg/core/charter/
  WG-MSEC:
    title: MSEC Working Group
    seriesinfo:
      Web: http://datatracker.ietf.org/wg/msec/
  IEEE802ah:
    title: 'Status of Project IEEE 802.11ah, IEEE P802.11- Task Group AH-Meeting Update.'
    seriesinfo:
      Web: http://www.ieee802.org/11/Reports/tgah_update.htm      
  nbiot:
    title: 'NarrowBand IoT'
    seriesinfo:
      Web: http://www.3gpp.org/ftp/tsg_ran/TSG_RAN/TSGR_69/Docs/RP-151621.zip 
  lora:
    title: 'LoRa - Wide Area Networks for IoT'
    seriesinfo:
      Web: https://www.lora-alliance.org/     
  sigfox:
    title: 'Sigfox - The Global Communications Service Provider for the Internet of Things (IoT)'
    seriesinfo:
      Web: https://www.sigfox.com/
  ZB:
    title: ZigBee Alliance
    date: 2011-02
    seriesinfo:
      Web: http://www.zigbee.org/
  Thread:
    title: Thread Alliance
    seriesinfo:
      Web: http://threadgroup.org/
  NHTSA:
    title: Cybersecurity Best Practices for Modern Vehicles
    seriesinfo:
      Web: https://www.nhtsa.gov/staticfiles/nvs/pdf/812333_CybersecurityForModernVehicles.pdf     
  NIST-Guide:
    title: Systems Security Engineering
    author:
    - ins: R. Ross
    - ins: M. McEVILLEY
    - ins: J. C. Oren
    seriesinfo:
      Web: http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-160.pdf   
  DHS:
    title: Strategic Principles For Securing the Internet of Things (IoT)
    seriesinfo:
      Web: https://www.dhs.gov/sites/default/files/publications/Strategic_Principles_for_Securing_the_Internet_of_Things-2016-1115-FINAL....pdf   
  OWASP:
    title: IoT Security Guidance
    seriesinfo:
      Web: https://www.owasp.org/index.php/IoT_Security_Guidance     
  IoTSecFoundation:
    title: Establishing Principles for Internet of Things Security
    seriesinfo:
      Web: https://iotsecurityfoundation.org/establishing-principles-for-internet-of-things-security/           
  GSMAsecurity:
    title: GSMA IoT Security Guidelines
    seriesinfo:
      Web: http://www.gsma.com/connectedliving/future-iot-networks/iot-security-guidelines/
  BITAG:
    title: Internet of Things (IoT) Security and Privacy Recommendations
    seriesinfo:
      Web: http://www.bitag.org/report-internet-of-things-security-privacy-recommendations.php
  CSA:
    title: Security Guidance for Early Adopters of the Internet of Things (IoT)
    seriesinfo:
      Web: https://downloads.cloudsecurityalliance.org/whitepapers/Security_Guidance_for_Early_Adopters_of_the_Internet_of_Things.pdf      
  SchneierSecurity:
    title: The Internet of Things Is Wildly Insecure—And Often Unpatchable
    seriesinfo:
      Web: https://www.schneier.com/essays/archives/2014/01/the_internet_of_thin.html  
  FTCreport:
    title: FTC Report on Internet of Things Urges Companies to Adopt Best Practices to Address Consumer Privacy and Security Risks
    seriesinfo:
      Web: https://www.ftc.gov/news-events/press-releases/2015/01/ftc-report-internet-things-urges-companies-adopt-best-practices
  Article29:
    title: Opinion 8/2014 on the on Recent Developments on the Internet of Things
    seriesinfo:
      Web: http://ec.europa.eu/justice/data-protection/article-29/documentation/opinion-recommendation/files/2014/wp223_en.pdf 
  TR69:
    title: Too Many Cooks - Exploiting the Internet-of-TR-069-Things
    seriesinfo:
      Web: https://media.ccc.de/v/31c3_-_6166_-_en_-_saal_6_-_201412282145_-_too_many_cooks_-_exploiting_the_internet-of-tr-069-things_-_lior_oppenheim_-_shahar_tal 
  wink:
    title: Wink’s Outage Shows Us How Frustrating Smart Homes Could Be
    seriesinfo:
      Web: http://www.wired.com/2015/04/smart-home-headaches/  
  iotsu:
    title: "Patching the Internet of Things: IoT Software Update Workshop 2016"
    seriesinfo:
      Web: https://www.ietf.org/blog/2016/07/patching-the-internet-of-things-iot-software-update-workshop-2016/
  cctv:
    title: "Backdoor In MVPower DVR Firmware Sends CCTV Stills To an Email Address In China"
    seriesinfo:
      Web: https://hardware.slashdot.org/story/16/02/17/0422259/backdoor-in-mvpower-dvr-firmware-sends-cctv-stills-to-an-email-address-in-china   
  ETSI_GR_QSC_001:
    title: Quantum-Safe Cryptography (QSC);Quantum-safe algorithmic framework 
    date: 2016-06
    seriesinfo: European Telecommunications Standards Institute (ETSI)
  FCC:
    title: Federal Communications Comssion Response 12-05-2016 
    date: 12-02-2016 
    seriesinfo: FCC
 
author:
- name: Oscar Garcia-Morchon
  ins: O. Garcia-Morchon
  org: Philips Research
  street: Canal Park 2
  city: Cambridge,   02141
  country: United States
  email: oscar.garcia@philips.com
- name: Sandeep S. Kumar
  ins: S. Kumar
  org: Philips Research
  street: High Tech Campus
  city: Eindhoven,   5656 AA
  country: The Netherlands
  email: sandeep.kumar@philips.com
- name: Mohit Sethi
  ins: M. Sethi
  org: Ericsson
  street: Hirsalantie 11
  city: Jorvas
  country: Finland
  email: mohit@piuha.net
- name: Oliver Pfaff
  ins: O. Pfaff
  org: Siemens
  street: 
  city: 
  country: 
  email: 
pi:
- toc
- sortrefs
- symrefs
- compact
- comments


--- abstract

The Internet of Things concept refers to the usage
of standard Internet protocols to allow for human-to-thing or thing-to-thing
communication. Although the security needs are well-recognized, it is still
not fully clear how existing IP-based security protocols should be applied to
this new setting. This Internet-Draft first provides an overview of security
architecture, its deployment model and general security needs in the context
of the lifecycle of a thing. Then, it presents challenges and requirements
for the successful roll-out of new applications and usage of standard IP-based
security protocols when applied to get a functional Internet of Things.


--- middle

# Conventions and Terminology Used in this Document {#sec1}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to
be interpreted as described in "Key words for use in RFCs to Indicate Requirement
Levels" {{RFC2119}}.

# Introduction {#sec2}

The Internet of Things (IoT) denotes the interconnection of highly heterogeneous networked entities and networks following a number of communication patterns such as: human-to-human (H2H), human-to-thing (H2T), thing-to-thing (T2T), or thing-to-things (T2Ts). The term IoT was first coined by the Auto-ID center {{AUTO-ID}} in 1999. Since then, the development of the underlying concepts has ever increased its pace. Nowadays, the IoT presents a strong focus of research with various initiatives working on the (re)design, application, and usage of standard Internet technology in the IoT.

The introduction of IPv6 and web services as fundamental building blocks
for IoT applications {{RFC6568}} promises to bring a number of basic advantages including: (i) a homogeneous protocol ecosystem that allows simple integration with Internet hosts; (ii) simplified development of very different appliances; (iii) an unified interface for applications, removing the need for application-level proxies. Such features greatly simplify the deployment of the envisioned scenarios ranging from building automation to production environments to personal area networks, in which very different things such as a temperature sensor, a luminaire, or an RFID tag might interact with each other, with a human carrying a smart phone, or with backend services.

This Internet Draft presents an overview of the security aspects of the envisioned all-IP architecture as well as of the lifecycle of an IoT device, a thing, within this architecture. 
In particular, we review the most pressing aspects and functionalities that are required for a secure all-IP solution.

With this, this Internet-Draft pursues several goals. First, we aim at presenting a comprehensive view of the interactions and relationships between an IoT application and security. Second, we aim at describing challenges for a secure IoT in the specific context of the lifecycle of a resource-constrained device. The final goal of this draft is to discuss the security considerations that need to be taken into consideration towards a secure IoT.

The rest of the Internet-Draft is organized as follows. 
{{sec3}} depicts the lifecycle of a thing and gives general definitions for the main security building blocks within the IoT domain. 
In {{sec4}}, we discuss threats and methodologies for managing risks when designing a secure IoT system. 
{{sec5}} reviews existing IP-based (security) protocols for the IoT and briefly summarizes existing guidelines and regulations in IoT security. 
{{sec6}} proposes a number of illustrative security profiles describing how different applications would require distinct security solutions.
{{sec7}} identifies existing challenges for a secure IoT and discusses potential solutions. 
{{sec7}} includes final remarks and conclusions.

# Motivation and background {#sec3}



## The Thing Lifecycle {#sec3-1}

The lifecycle of a thing refers to the operational phases of a thing in the context of a given application or use case.
{{fig1}} shows the generic phases of the lifecycle of a thing. This generic lifecycle is applicable to very different IoT applications and scenarios.

We consider an example, a Building Automation and Control (BAC) system, to illustrate the lifecycle and the meaning of these different phases. 
A BAC system consists of a network of interconnected nodes that performs various functions in the domains of HVAC (Heating, Ventilating, and Air Conditioning), lighting, safety etc. The nodes vary in functionality and a majority of them represent resource constrained devices such as sensors and luminaries. Some devices may also be battery operated or battery-less nodes, demanding for a focus on low energy consumption and on sleeping devices.
In our example, the life of a thing starts when it is manufactured. Due to the different application areas (i.e., HVAC, lighting, safety) nodes are tailored to a specific task. It is therefore unlikely that one single manufacturer will create all nodes in a building. Hence, interoperability as well as trust bootstrapping between nodes of different vendors is important. The thing is later installed and commissioned within a network by an installer during the bootstrapping phase. Specifically, the device identity and the secret keys used during normal operation are provided to the device during this phase. Different subcontractors may install different IoT devices for
different purposes. Furthermore, the installation and bootstrapping procedures may not be a defined event but may stretch over an extended period of time. After being bootstrapped, the device and the system of things are in operational mode and run the functions of the BAC system. During this operational phase, the device is under the control of the system owner. For devices with lifetimes spanning several years, occasional maintenance cycles may be required. During each maintenance phase, the software on the device can be upgraded or applications running on the device can be reconfigured. The maintenance tasks can thereby be performed either locally or from a backend system by means of an end-to-end connection. Depending on the operational changes of the device, it may be required to re-bootstrap at the end of a maintenance cycle. The device continues to loop through the operational phase and the eventual maintenance phase until the device is decommissioned at the end of its lifecycle. However, the end-of- life of a device does not necessarily mean that it is defective but rather denotes a need to replace and upgrade the network to next- generation devices in order to provide additional  functionality. Therefore the device can be removed and re-commissioned to be used in a different system under a different owner by starting the lifecycle over again. 




~~~~
 _Manufactured           _SW update          _Decommissioned
/                       /                   /
|   _Installed          |   _ Application   |   _Removed &
|  /                    |  / reconfigured   |  /  replaced
|  |   _Commissioned    |  |                |  |
|  |  /                 |  |                |  |   _Reownership &
|  |  |    _Application |  |   _Application |  |  / recommissioned
|  |  |   /   running   |  |  / running     |  |  |
|  |  |   |             |  |  |             |  |  |             \\
+##+##+###+#############+##+##+#############+##+##+##############>>>
    \/  \______________/ \/  \_____________/ \___/         time //
    /           /         \          \          \
Bootstrapping  /      Maintenance &   \     Maintenance &
              /      re-bootstrapping  \   re-bootstrapping
        Operational                Operational
~~~~
{: #fig1 title="The lifecycle of a thing in the Internet of Things."}

## Security building blocks {#sec3-2}

Security is a key requirement in the IoT due to several reasons.
First, an IoT systems enable very specific applications in which users are involved. A broken IoT system means that the privacy and safety of the users is endagered, this is key requirement in application ares such as critial infrastructure or healthcare.
Second, a compromised IoT system means that an attacker altered the functionality of the devices of a given manufacturer, this not only affects the manufacturer brand image in a negative way but can also leak information that is very valuable for the manufacturer, such as propietary algorithms.
Third, the impact of attacking the IoT goes beyond a specific device or isolated systems since compromised IoT systems can be misused at scale, e.g., performing a DDoD attack that limits the availability of the compromised system or even other IT networks. 
The fact that many IoT systems rely on standard IP protocols allows for easier system integration increasing the value of the realized use cases, but this also makes standard attacks applicable to a wide number of devices deployed in multiple systems.
This results in new requirements regarding the implementation of security.

The term security subsumes a wide range of primitives, protocols, and procedures. 
In the first place, it includes to the basic provision of security services including confidentiality, authentication, integrity, authorization, non-repudiation, and availability, and some augmented services, such as duplicate detection and detection of stale packets (timeliness). 
These security services can be implemented by a combination of cryptographic mechanisms, such as block ciphers, hash functions, or signature algorithms, and non-cryptographic mechanisms, which implement authorization and other security policy enforcement aspects. For each of the cryptographic mechanisms, a solid key management infrastructure is fundamental to handling the required cryptographic keys, whereas for security policy enforcement, one needs to properly codify authorizations as a function of device roles and a security policy engine that implements these authorization checks and that can implement changes hereto throughout the system's lifecycle.

In the particular context of the IoT, security must not only focus on the required security services, but also pay special attention to how these are realized in the overall system and how the security functionalities are executed. 
To this end, we consider five mayor "building blocks" to analyze and classify security aspects in the IoT:

1. The IoT security architecture: refers to the system elements involved in the management of the security relationships between things and the way these security interactions are handled (e.g., centralized or distributed) during the lifecycle of a thing. For instance, a smart home could rely on a centralized key distribution center in charge of managing cryptographic keys, devices & users, access control and privacy policies. 

2. The security model within a smart object: describes the way security parameters, key, processes, and applications are managed within a smart object. This includes aspects such as process separation, secure storage of key materials, protection of algorithms, etc. For instance, some smart objects might have extremely limited resources and have limited capabilities to protect secret keys; in contrast, other devices used in critical applications, e.g., a pacemaker, would rely on methods to securely protect cryptographic keys and functionality making sure that an attacker having physical access to the device cannot modify its operation.

3. Security bootstrapping: denotes the process by which a thing securely joins an IoT system at a given location and point in time. For instance, bootstrapping of a connected camera can include the authentication and authorization of a device as well as the transfer of security parameters allowing for its trusted operation in a given network.  

4. Network security: describes the mechanisms applied within a network to ensure trusted operation of the IoT. Specifically, it prevents attackers from endangering or modifying the expected operation of networked things. For instance, network security can include a number of mechanisms ranging from data link layer security, MAC filtering, secure routing, and network layer security.

5. Application security: describes mechanisms to allow transfer of application data at transport or upper layers (object security). For instance, assuming an smart object such as an environmental sensor and a backend system, it can mean the exchange of secured blocks of data such as data sensed by the sensor or a software update. This data is exchanged end-to-end  independently of communication pattern, for e.g through proxies or other store-and-forward mechanisms.


~~~~
            ..........................
            :           +-----------+:
            :       *+*>|Application|*****
            :       *|  +-----------+:   *
            :       *|  +-----------+:   *
            :       *|->| Transport |:   *
            :    * _*|  +-----------+:   *
            :    *|  |  +-----------+:   *
            :    *|  |->|  Network  |:   *
            :    *|  |  +-----------+:   *
            :    *|  |  +-----------+:   *    *** Bootstrapping
            :    *|  +->|     L2    |:   *    ~~~ Transport Security
            :    *|     +-----------+:   *    ''' Object Security
            :+--------+              :   *
            :|Security| Configuration:   *
            :|Service |   Entity     :   *
            :+--------+              :   *
            :........................:   *
                                         *
.........................                *  .........................
:+--------+             :                *  :             +--------+:
:|Security|   Node B    :                *  :   Node A    |Security|:
:|Service |             :                *  :             |Service |:
:+--------+             :                *  :             +--------+:
:    |     +-----------+:                *  :+-----------+     |*   :
:    |  +->|Application|:                ****|Application|<*+* |*   :
:    |  |  +-----------+:''''''''''''''''''''+-----------+  |* |*   :
:    |  |  +-----------+:                   :+-----------+  |* |*   :
:    |  |->| Transport |~~~~~~~~~~~~~~~~~~~~~| Transport |<-|* |*   :
:    |__|  +-----------+: ................. :+-----------+  |*_|*   :
:       |  +-----------+: : +-----------+ : :+-----------+  | *     :
:       |->|  Network  |: : |  Network  | : :|  Network  |<-|       :
:       |  +-----------+: : +-----------+ : :+-----------+  |       :
:       |  +-----------+: : +-----------+ : :+-----------+  |       :
:       +->|     L2    |: : |     L2    | : :|     L2    |<-+       :
:          +-----------+: : +-----------+ : :+-----------+          :
:.......................: :...............: :.......................:
                   Overview of Security Mechanisms.
~~~~
{: #fig2}

We now discuss an exemplary security architecture relying on a configuration entity for the management of the system with regard to the introduced security aspects (see {{fig2}}). 
Inspired by the security framework for routing over low power and lossy network {{ID-Tsao}}, we show an example of the security model of a smart object and illustrates how different security concepts and the lifecycle phases map to the Internet communication stack. 

In our example, we consider a centralized architecture in which a configuration entity stores and manages the identities of the things associated with BAC system along with their cryptographic keys. 
During the bootstrapping phase, each thing executes the bootstrapping protocol with the configuration entity, thus obtaining the required device identities and some operational keying material. 
The security service on a thing in turn stores the received keying material for the network layer and application security mechanisms for secure communication. 
The criticality of the application requires an implementaiton of cryptographic algorithms that is resistant to side-channel attacks and the protection of the propietary application-related algorithms executed in the device.
Things can then securely communicate with each other during their operational phase by means of the employed network and application security mechanisms.
Wihin the network, communication is protected by the network provider at MAC and network layer.
At applicaiton layer, the communicaiton between any smart object and the application server is protected end-to-end, ensuring the forward secrecy of the communication.

# Managing Threats and Risks {#sec4}

This section explores security threats and vulnerabilities in the IoT and discussess how to manage risks.

Security threats have been analyzed in related IP protocols including HTTPS {{RFC2818}}, COAP{{RFC7252}} 6LoWPAN {{RFC4919}}, ANCP {{RFC5713}}, DNS security threats {{RFC3833}}, SIP {{RFC3261}}, IPv6 ND {{RFC3756}}, and PANA {{RFC4016}}. 
Nonetheless, the challenge is about their impacts on scenarios of the IoTs. In this section, we specifically discuss the threats that could compromise an individual thing, or network as a whole. 
Note that these set of threats might go beyond the scope of Internet protocols but we gather them here for the sake of completeness.
We also note that these threats can be classified according to either (i) the thing's lifecycle phases (when does the threat occur?) or (ii) the security building blocks (which functionality is affected by the threat?). 
All these threats are summarized in Table 2.

1. Cloning of things: During the manufacturing process of a thing, an untrusted manufacturer can easily clone the physical characteristics, firmware/software, or security configuration of the thing. Deployed things might also be compromised and their software reserve engineered allowing for cloning or software modifications. Such a cloned thing may be sold at a cheaper price in the market, and yet be still able to function normally, as a genuine thing. For example, two cloned devices can still be associated and work with each other. In the worst case scenario, a cloned device can be used to control a genuine device or perform an attack. One should note here, that an untrusted manufacturer may also change functionality of the cloned thing, resulting in degraded functionality with respect to the genuine thing (thereby, inflicting potential reputational risk to the original thing manufacturer). Moreover, it can implement additional functionality with the cloned thing, such as a backdoor.

2. Malicious substitution of things: During the installation of a thing, a genuine thing may be substituted with a similar variant of lower quality without being detected. The main motivation may be cost savings, where the installation of lower-quality things (e.g., non-certified products) may significantly reduce the installation and operational costs. The installers can subsequently resell the genuine things in order to gain further financial benefits. Another motivation may be to inflict reputational damage on a competitor's offerings.

3. Eavesdropping attack: During the commissioning of a thing into a network, it may be susceptible to eavesdropping, especially if operational keying materials, security parameters, or configuration settings, are exchanged in clear using a wireless medium or if used crytographic algorithms are not suitable for the envisioned lifetime of the device and the system. After obtaining the keying material, the attacker might be able to recover the secret keys established between the communicating entities (e.g., H2T, T2Ts, or Thing to the backend management system), thereby compromising the authenticity and confidentiality of the communication channel, as well as the authenticity of commands and other traffic exchanged over this communication channel. When the network is in operation, T2T communication may be eavesdropped upon if the communication channel is not sufficiently protected or in the event of session key compromise due to a long period of usage without key renewal or updates.

4. Man-in-the-middle attack: Both the commissioning phase and operational phases may also be vulnerable to man-in-the-middle attacks, e.g., when keying material between communicating entities is exchanged in the clear and the security of the key establishment protocol depends on the tacit assumption that no third party is able to eavesdrop on or sit in between the two communicating entities during the execution of this protocol. Additionally, device authentication or device authorization may be nontrivial, or may need support of a human decision process, since things usually do not have a priori knowledge about each other and can, therefore, not always be able to differentiate friends and foes via completely automated mechanisms. Thus, even if the key establishment protocol provides cryptographic device authentication, this knowledge on device identities may still need complementing with a human-assisted authorization step (thereby, presenting a weak link and offering the potential of man-in-the-middle attacks this way).

5. Firmware Replacement attack: When a thing is in operation or maintenance phase, its firmware or software may be updated to allow for new functionality or new features. An attacker may be able to exploit such a firmware upgrade by replacing the thing's with malicious software, thereby influencing the operational behavior of the thing. For example, an attacker could add a piece of malicious code to the firmware that will cause it to periodically report the energy usage of the lamp to a data repository for analysis. Similarly, devices whose software has not been properly maintained and updated might contained vulnerabilities that might be exploited by attackers.

6. Extraction of private information: in the ambient environment (such as sensors, actuators, etc.) is usually physically unprotected and could easily be captured by an attacker. Such an attacker may then attempt to extract private information such as keys (e.g., device's key, private-key, group key), sensed data (e.g., healthcare status of a user), configuration parameters (e.g., the WiFi key), or propietary algorithms (e.g., algorithm performing some data analytics task) from this thing or try and re-program it to serve his needs. If a group key is used and compromised this way, the whole network may be compromised as well. Compromise of a thing's unique key has less security impact, since only the communication channels of this particular thing in question are compromised. Here, one should caution that compromise of the communication channel may also compromise all data communicated over this channel. In particular, one has to be weary of, e.g., compromise of group keys communicated over this channel (thus, leading to transitive exposure ripple effects). 

7. Routing attack: As highlighted in {{ID-Daniel}}, routing information in IoT can be spoofed, altered, or replayed, in order to create routing loops, attract/repel network traffic, extend/ shorten source routes, etc. Other relevant routing attacks include 1) Sinkhole attack (or blackhole attack), where an attacker declares himself to have a high-quality route/path to the base station, thus allowing him to do anything to all packets passing through it. 2) Selective forwarding, where an attacker may selectively forward packets or simply drop a packet. 3) Wormhole attack, where an attacker may record packets at one location in the network and tunnel them to another location, thereby influencing perceived network behavior and potentially distorting statistics, thus greatly impacting the functionality of routing. 4) Sybil attack, whereby an attacker presents multiple identities to other things in the network.

8. Privacy threat: The tracking of a thing's location and usage may pose a privacy risk to its users. An attacker can infer information based on the information gathered about individual things, thus deducing behavioral patterns of the user of interest to him. Such information can subsequently be sold to interested parties for marketing purposes and targeted advertising.

9. Denial-of-Service attack: Typically, things have tight memory and limited computation, they are thus vulnerable to resource exhaustion attack. Attackers can continuously send requests to be processed by specific things so as to deplete their resources. This is especially dangerous in the IoTs since an attacker might be located in the backend and target resource-constrained devices in an LLN. Additionally, DoS attack can be launched by physically jamming the communication channel, thus breaking down the T2T communication channel. Network availability can also be disrupted by flooding the network with a large number of packets. On the other hand, things compromised by attackers can be used to disrupt the operation of other networks or systesm by means of a Distributed DoS attack.

The following table summarizes the above generic security threats and the potential point of vulnerabilities at different layers of the communication stack. We also include related RFCs and ongoing standarization efforts that include a threat model that might apply to the IoTs.


~~~~
             +------------------+------------------+------------------+
             | Manufacturing    | Installation/    | Operation        |
             |                  | Commissioning    |                  |
+------------+------------------+------------------+------------------+
|Thing's     | Device Cloning   |Substitution      |Privacy threat    |
|Model       |                  |ACE-OAuth(draft)  |Extraction of     |
|            |                  |                  |private inform.   |
+------------+------------------+------------------+------------------+
|Application |                  |RFC2818, RFC7252  |RFC2818, Firmware |
|Layer       |                  |OSCOAP(draft)     |replacement       |
+------------+------------------+------------------+------------------+
|Transport   |                  | Eavesdropping &  |Eavesdropping     |
|Layer       |                  | Man-in-the-middle|Man-in-the-middle |
+------------+------------------| attack, RFC7925  |------------------+
|Network     |                  | RFC4919, RFC5713 |RFC4919,DoS attack|
|Layer       |                  | RFC3833, RFC3756 |Routing attack    |
|            |                  |                  |RFC3833           |
+------------+------------------+------------------+------------------+
|Physical    |                  |                  |DoS attack        |
|Layer       |                  |                  |                  |
+-------------------------------+------------------+------------------+
~~~~
{: #fig3 title="Classification of threats according to the lifecycle phases and security building blocks."}

Dealing with above threats and finding suitable security mitigations is challenging: there are very sofisticated threats that a very powerful attacker could use; also, new threats and exploits appear in a daily basis.
Therefore, the existence of proper secure product creation processes that allow managing and minimizing risks during the lifecycle of the IoT devices is at least as important as being aware of the theats. 
A non-exhaustive list of relevant processes include: 

1. A Business Impact Analysis (BIA) assesses the consequences of lost of basic security attributes, namely, confidentiality, integrity and availability in an IoT system. These consequences might include impact on people data, data lost, sales lost, increased expenses, regulatory fines, customer dissatisfaction, etc. Performing a business impact analyis allow determinining the business relevance of having a proper security design placing security on the focus.

2. A Risk Assessment (RA) analyzes security threats to the IoT system, considering their likelihood and impact, and deriving for each of them a risk level. Risks classified as moderate or high must be mitigated, i.e., security architecture should be able to deal with that threat bringing the risk to a low level. Note that threats are usually classified according to their goal: confidentiality, integrity, and availability. For instance, a specific threat to recover a symmetric-key used in the system relates to confidentiality.

3. A privacy impact assessment (PIA) aims at assessing Personal Identifiable Information (PII) that is collected, processed, or used in the IoT system. By doing so, the goals is to fulfil applicable legal requirements, determine risks and effects of the manipulation of PII, and evaluate proposed protections. 

4. Procedures for incident reporting and mitigation refer to the methodologies that allow becoming aware of any security issues that affect an IoT system. Furthermore, this includes steps towards the actual deployment of patches that mitigate the identified vulnerabilities.

BIA, RA, and PIA are usually to be realized during the creation of a new IoT system, introduction of new technologies in the IoT system, or deplozment of significant system upgrades. In general, it is recommended to re-assess them in a regular basis taking into account new use cases or threats. 


# State of the Art {#sec5}

This section is organized as follows. Section {{sec5-1}} summarizes state of the art on IP-based systems, within IETF and in other standardization bodies.
Section {{sec5-2}} summarizes state of the art on IP-based security protocols and their usage. Section {{sec5-3}} discusses guidelines for securing the IoT as proposed by other bodies. Section {{sec5-4}} analyzes status of other relevant standards, in particular, those by NIST regarding IoT and IoT security.

## IP-based IoT Protocols and Standards {#sec5-1}

Nowadays, there exists a multitude of control protocols for the IoT. For
BAC systems, the ZigBee standard {{ZB}}, BACNet {{BACNET}}, or DALI {{DALI}} play key roles. 
Recent trends, however, focus on an all-IP approach for system control.

In this setting, a number of IETF working groups are designing new protocols
for resource constrained networks of smart things. The 6LoWPAN working group
{{WG-6LoWPAN}} concentrates on the definition of methods and protocols for
the efficient transmission and adaptation of IPv6 packets over IEEE 802.15.4
networks {{RFC4944}}. 
The CoRE working group {{WG-CoRE}} provides a framework for resource-oriented applications intended to run on constrained IP network (6LoWPAN). 
One of its main tasks is the definition of a lightweight version of the HTTP protocol, the Constrained Application Protocol (CoAP) {{RFC7252}},that runs over UDP and enables efficient application-level communication
for things. 

ToDo: include other groups and internet drafts.

Also IRTF groups are actively contributing to improve IoT security. 


Additionally industry alliances are creating constrained IP protocol stacks based on the IETF work. 
Examples of this include: Thread {{Thread}}, 

ToDo: include other industry alliances.


## Existing IP-based Security Protocols and Solutions {#sec5-2}

In the context of the IP-based IoT solutions, consideration of TCP/IP security
protocols is important as these protocols are designed to fit the IP network
ideology and technology. There are a wide range of specialized as well as general-purpose key exchange and security solutions exist for the Internet domain such as IKEv2/IPsec {{RFC7296}}, TLS/SSL {{RFC5246}}, DTLS {{RFC5238}}, HIP {{RFC7401}}, PANA {{RFC5191}}, and EAP {{RFC3748}}. Some of these solutions are also been investigated now, such as, e.g., OSCOAP. {{fig3}} depicts the relationships between the discussed protocols in the context of the security terminology introduced in {{sec3}}.


~~~~
            ..........................
            :           +-----------+:
            :       *+*>|Application|*****     *** Bootstrapping
            :       *|  +-----------+:   *     ### Transport Security 
            :       *|  +-----------+:   *     === Network security
            :       *|->| Transport |:   *     ... Object security
            :    * _*|  +-----------+:   *
            :    *|  |  +-----------+:   *
            :    *|  |->|  Network  |:   *--> -PANA/EAP
            :    *|  |  +-----------+:   *    -HIP
            :    *|  |  +-----------+:   *
            :    *|  +->|     L2    |:   *     ## DTLS
            :    *|     +-----------+:   *     .. OSCOAP
            :+--------+              :   *
            :|Security| Configuration:   *     [] HIP,IKEv2
            :|Service |   Entity     :   *     [] ESP/AH
            :+--------+              :   *
            :........................:   *
                                         *
.........................                *    .........................
:+--------+             :                *    :             +--------+:
:|Security|   Node B    :    Secure      *    :   Node A    |Security|:
:|Service |             :    routing     *    :             |Service |:
:+--------+             :   framework    *    :             +--------+:
:    |     +-----------+:        |       **** :+-----------+     |*   :
:    |  +->|Application|:........|............:|Application|<*+* |*   :
:    |  |  +----##-----+:        |            :+----##-----+  |* |*   :
:    |  |  +----##-----+:        |            :+----##-----+  |* |*   :
:    |  |->| Transport |#########|#############| Transport |<-|* |*   :
:    |__|  +----[]-----+:  ......|..........  :+----[]-----+  |*_|*   :
:       |  +====[]=====+=====+===========+=====+====[]=====+  | *     :
:       |->|| Network  |:  : |  Network  | :  :|  Network ||<-|       :
:       |  +|----------+:  : +-----------+ :  :+----------|+  |       :
:       |  +|----------+:  : +-----------+ :  :+----------|+  |       :
:       +->||    L2    |:  : |     L2    | :  :|     L2   ||<-+       :
:          +===========+=====+===========+=====+===========+          :
:.......................:  :...............:  :.......................:
           Relationships between IP-based security protocols.
~~~~
{: #fig4}

The Internet Key Exchange (IKEv2)/IPsec and the Host Identity protocol (HIP)
reside at or above the network layer in the OSI model. Both protocols are
able to perform an authenticated key exchange and set up the IPsec transforms
for secure payload delivery. Currently, there are also ongoing efforts to
create a HIP variant coined Diet HIP {{ID-HIP}} that takes lossy low-power
networks into account at the authentication and key exchange level.

Transport Layer Security (TLS) and its datagram-oriented variant DTLS secure
transport-layer connections. TLS provides security for TCP and requires
a reliable transport, while DTLS secures and uses datagram-oriented protocols
such as UDP. Both protocols are intentionally kept similar and share the
same ideology and cipher suites.

The Extensible Authentication Protocol (EAP) is an authentication framework
supporting multiple authentication methods. EAP runs directly over the data
link layer and, thus, does not require the deployment of IP. It supports
duplicate detection and retransmission, but does not allow for packet fragmentation. The Protocol for Carrying Authentication for Network Access (PANA) is a network-layer transport for EAP that enables network access authentication between clients and the network infrastructure. In EAP terms, PANA is a UDP-based EAP lower layer that runs between the EAP peer and the EAP authenticator.

In addition, there is also new activities in IETF and W3C to define security protocols better tailored to IoT or for specific deployment situations. The ACE WG is designing an authorization mechanism based on OAuth for constrained devices. There is work on Object Security based CoAP protection mechanism being defined in OSCOAP. 


## IoT Security Guidelines {#sec5-3}

Recent large scale Denial of Service (DoS) Attacks on the Internet Infrastructure from compromised IoT devices has prompted many different standards bodies and consortia to provide guidelines for developers and the Internet community at large to build secure IoT devices and services. The different guidelines available are as follows:

1. GSMA IoT security guidelines {{GSMAsecurity}}: GSMA has published a set of security guidelines for the benefit of new IoT product and service providers. The guideline are aimed at device manufacturers, service providers, developers and network operators. An enterprise can complete IoT Security Self-Assessment to demonstrate that its products and services are aligned with the security guidelines of the GSMA. 

2. BITAG Internet of Things (IoT) Security and Privacy Recommendations {{BITAG}}: Broadband Internet Technical Advisory Group (BITAG) has also published recommendations for ensuring security and privacy of IoT device users. BITAG observes that many IoT devices are shipped from the factory with software that is already outdated and vulnerable. The report also states that many devices with vulnerabilities will not be fixed either because the manufacturer does not provide updates or because the user does not apply them. The recommendations include that IoT devices should function without cloud and Internet connectivity, and that all IoT devices should have methods for automatic secure software updates.

3. CSA New Security Guidance for Early Adopters of the IoT {{CSA}}: The Cloud Security Alliance (CSA) recommendations for early adopters of IoT encourages enterprises to implement security at different layers of the protocol stack. It also recommends implementation of an authentication/authorization framework for IoT deployments. A complete list of recommendations is available in the report {{CSA}}. 

4. U.S. Department of Homeland Security {{DHS}}: DHS has put forth six strategic principles that would enable IoT developers, manufacturers, service providers and consumers to maintain security as they develop, manufacture, implement or use network-connected IoT devices.

5. NIST {{NIST-Guide}}: The NIST special publication urges enterprise and US federal agencies to address security throughout the systems engineering process. The publication builds upon the ISO/IEC/IEEE 15288 standard and augments each process in the system lifecyle with security enhancements. 

6. OWASP {{OWASP}}: Open Web Application Security Project (OWASP) provides security guidance for IoT manufactures, developers and consumers. OWASP also includes guidelines for those who intend to test and analyze IoT devices and applications. 

7. IoT Security foundation {{IoTSecFoundation}}: IoT security foundation has published a document that enlists various considerations that need to be taken into account when developing IoT applications. For example, the document states that IoT device could use hardware-root of trust to ensure that only authorized software runs on the device. 

8. NHTSA {{NHTSA}}: The US National Highway Traffic Safety Administration  provides a set of non-binding guidance to the automotive industry for improving the cyber security of vehicles. While some of the guidelines are general, the document provides specific recommendations for the automotive industry such as how various automotive manufacturer can share cyber security vulnerabilities discovered. 

9. BCP for IoT devices {{ID-Moore}}: This Internet draft provides a list of minimum requirements that vendors of Internet of Things (IoT) devices should to take into account while developing applications, services and firmware updates in order to reduce the frequency and severity of security incidents that arise from compromised IoT devices. 

10. ENISA {{ENISA_ICS}}: The European Union Agency for Network and Information Security published a document on Communicaiton network dependencies for ICS/SCADA systems in which securty vulnerabilities, guidelines and general recommendations are summirized.

Other guideline and recommendation documents may exist or may later be published. This list should be considered non-exhaustive. 


## Guidelines and IoT Security Regulations {#sec5-4}

Despide the need for security in the Internet is nothing new and multiple guidelines exist, the fact is that many IoT devices and systems are not fully secure. There are multiple reasons for this. For instance, some manufactures focus on delivering a product without paying enough attention to the delivered security level. This can have multiple reasons, for instance, lack of expertise or budget. This, however, poses a severe threat when such devices are deployed. The vast amount of devices and their inherent mobile nature also implies that an initially secure system can become unsecure if a device gains access in some way at some point of time. Even if all devices in a given environment are secure, it does not prevent external (passive) attacks originated in unsecure devices. 

Recently {{FCC}} the FCC has been stated the need for higher regulation for IoT systems. In fact this might be a missing component, at least in Federal Information Systems (FIS). Today, security in US FIS is regulated according to Federal Information Security Management Act (FISMA). From this law, NIST derived a number of documents to establish how to categorize FIS and determine minimum security requirements (FIPS-PUB-199 and FIPS-PUB-200). Minimum security requirements for FIS are specified in NIST SP 800-53r4. However, it is very likely that existing regulations do not take into account the specific challenges of IoT devices and networks.

Even if such a regulation is put in place, the question is how such a regulation can be applied in practice to non-federal deployments, such as industrial, homes, offices, or smart cites. Each of them exhibits unique features, involves very diverse types of users, has different operational requirements, and combines IoT devices from multiple manufacturers. 

Thus, it seems that future regulations should consider such diverse deployment scenarios.


# IoT Security Profiles {#sec6}

here is a wide range of IoT applications including building automation systems, healthcare, smart cities, logistics, etc. For each of those applications, properties such as device capability, network infrastructure, or available security services can be completely different. Furthermore, each of those applications is featured by a different number of actors deployed in very different environments and with very different purposes.

Consequently, when a Business Impact Analysis or Risk Assessment are realized, not only the types of threats will change, but also their likelihood and potential impact. This determines that different applications tend to require different or complementary types of security mechanisms mitigating the identified risks.

For example, IoT applications may have different needs regarding authentication and confidentiality. While some application might not require any authentication at all, others might require strong end-to-end authentication. In terms of secure bootstrapping of keys, some applications might assume the existence and online availability of a central key-distribution-center (KDC) within the 6LoWPAN network to distribute and manage keys; while other applications cannot rely on such a central party or their availability.

This section defines security profiles fitting the security needs of applications with the same characteristics and requirements. 
This is done to (i) guide the design process of different application types by identifying open gaps; (ii) allow for later interoperability; and (iii) prevent possible security misconfigurations. 
Each security profile is identified by:

1. a short description,

2. an exemplary application that might use/require such a security profile,

3. the security requirements for each of the above security aspects according to our classification in {{sec3-2}}.

These security profiles can serve to guide the standardization process, since these explicitly describe the basic functionalities and protocols required to get different use cases up and running.  
They can allow for later interoperability since different manufacturers can describe the implemented security profile in their products. 
Finally, the security profiles can avoid possible security misconfigurations, since each security profile can be bound to a different application area so that it can be clearly defined which security protocols and approaches can be applied where and under which circumstances.

We compare the security capabilities in each of the security profiles according to security building blocks introduced {{sec3-2}}, namely:

1.   Security architecture,

2.   Security model,

3.   Security bootstrapping,

4.   Network security, and

5.   Application security.

IMPORTANT: Note that each of these security profiles aim at summarizing the required security requirements for different applications and at providing a set of initial security features. In other words, these profiles reflect the need for different security configurations, depending on the threat and trust models of the underlying applications. In this sense, this section does not provide an overview of existing protocols as done in previous sections of the Internet Draft, but it rather explicitly describes what should be in place to ensure secure system operation. Observe also that this list of security profiles is not exhaustive and that it should be considered just as an example not related to existing legal regulations for any existing application. 

The remainder of this section is organized as follows. Section {{sec6-1}} first describes four generic security profiles and discuss how different applications of IP networks, e.g., 6LoWPAN/CoAP networks, involve different security needs. The following five subsections summarize the expected security features or capabilities for each the security profile with regards to "Security Architecture", "Security Model", "Security Bootstrapping", "Network Security", and "Application Security".


## Profiles Security Profiles {#sec6-1}

We consider four generic security profiles as summarized in the table below:



~~~~
           +---------------------------------------------------------+
           | Exemnplary      |                                       |
           | Application     |          Description                  |
+----------+---------------------------------------------------------+
|SecProf_1 |Home usage       |Enables operation between home things  |
|          |                 |without interaction with central device|
+----------+-----------------+---------------------------------------+
|SecProf_2 |Managed Home     |Enables operation between home things. |
|          | usage           |Interaction with a central and local   |
|          |                 |device is possible                     |
+----------+-----------------+---------------------------------------+
|SecProf_3 |Industrial usage |Enables operation between things.      |
|          |                 |Relies on central (local or backend)   |
|          |                 |device for security                    |
+----------+-----------------+---------------------------------------+
|SecProf_4 |Advanced         |Enables ad-hoc operation between things|
|          |Industrial usage |and relies on central device or        |
|          |                 |on a collection of control devices     |
+----------+-----------------+---------------------------------------+
~~~~
{: #fig6 title="Security profiles and application areas."}

The classification in the table considers different potential applications in which security mechanism are chosen according to the operational features (network size, existence of a central device, connectivity to the Internet, importance of the exchanged information, etc) and threat model (what are the assets that an attacker looks for). As already pointed out, this set of scenarios is just exemplary and they should be further discussed based on a broader consensus.

The security suite (SecProf_1) is catered for environments in which IP protocols (e.g.,
6LoWPAN/CoAP) can be used to enable communication between things in an ad-hoc
manner and the security requirements are minimal. An example, is a home
application in which two devices should exchange information and no further
connection with other devices (local or with a backend) is required. In
this scenario, value of the exchanged information is low and that is usually
happen in a confined room, thus, it is possible to have a short period of
time during which initial secrets can be exchanged in the clear. Due to
this fact, there is no requirement to enable devices from different manufacturers to interoperate in a secure way (keys are just exchanged). 
The expected network size of applications using this profile is expected to be small such that the provision of network security, e.g., secure routing, is of low importance.

The next security suite (SecProf_2) represents an evolution of SecProf_1
in which, e.g., home devices, can be managed. A first possibility
for the securing domain management refers to the creation of a centrally
managed security domain without any connectivity to the Internet. The central
device used for management can serve as, e.g., a key distribution center
including policies for key update, storage, etc. The presence of a central
device can help in the management of larger networks. Network security becomes more relevant in this scenario since the IP network (e.g., 6LoWPAN/CoAP network) can be prone to Denial of Service attacks (e.g., flooding if L2 is not protected) or routing attacks.
Similarly, the network of devices could also be the source of a DDoS attack and a central device connecting to the Internet can block traffic of ongoing attaks.

SecProf_3 considers that a central device is always required for managing the system. 
Example applications of this profile include building control and automation, sensor networks for industrial use, environmental monitoring, etc. 
As before, the manager can be located in the same network (e.g., 6LoWPAN/CoAP network) and handle key management. 
In this case, the first association of devices to the network is required to be done in a secure way, i.e., requiring authentication and authorization. 
This step can involve the secure transmission of keying materials used for network security at different layers. 
The information exchanged in the network is considered to be valuable and it should be protected in the sense of pairwise links. 
Commands should be secured and broadcast should be secured with entity authentication {{RFC7390}}. 
Network should be protected from routing attacks. A further extension to this use case is to allow for remote management. A "backend manager" is in charge of securely managing SW or information exchanged or collected within the network, e.g., a 6LoWPAN/CoAP network. 
This requires connection of devices to the Internet over a 6LBR involving a number of new threats that were not present before. 
A list of potential attacks include: resource-exhaustion attacks from the Internet; amplification attacks; trust issues related a HTTP-CoAP proxy {{ID-proHTTPCoAP}}, etc. This use case requires protecting the communication from a device in the backend to a device in the IP network, e.g., a 6LoWPAN/CoAP network, end-to-end. This use case also requires measures to provide the 6LBR with the capability of dropping fake requests coming from the Internet. This becomes especially challenging when the 6LBR is not trusted and access to the exchanged information is limited; and even more in the case of a HTTP-CoAP proxy since protocol translation is required. This use case should take care of protecting information accessed from the backend due to privacy issues (e.g., information such as type of devices, location, usage, type and amount of exchanged information, or mobility patterns can be gathered at the backend threatening the privacy sphere of users) so that only required information is disclosed.

The last security suite (SecProf_4) essentially represents interoperability of all the security profiles defined previously. 
It considers applications with some additional requirements regarding operation such as: (i) ad-hoc establishment of security relationships between things (potentially from different manufacturers) in non- secure environments or (ii) dynamic roaming of things between different IP network security domains. 
Such operational requirements pose additional security requirements, e.g., in addition to secure bootstrapping of a device within an IP, e.g., 6LowPan/CoAP, security domain and the secure transfer of network operational key, there is a need to enable inter-domains secure communication to facilitate data sharing.
In this scenario, there is also a higher pressure to ensure that an attacker cannot compromise deployed devices and extract or modify any type of private data such as cryptographic keys, data, or propiertary algorithms. 

## Security Architecture {#sec6-2}

Most things might be required to support both centralized and distributed operation patterns. Distributed thing-to-thing communication might happen on demand, for instance, when two things form an ad-hoc security domain to cooperatively fulfill a certain task. 
Likewise, nodes may communicate with a backend service located in the Internet without a central security manager. 
The same nodes may also be part of a centralized architecture with a dedicated node being responsible for the security management for group communication between things in the IoT domain. 
In today's IoT, most common architectures are fully centralized in the sense that all the security relationships within a segment are handled by a central party. 
In the ZigBee standard, this entity is the trust center. 
Current proposals for 6LoWPAN/CoRE identify the 6LoWPAN Border Router (6LBR) as such a device.

A centralized architecture allows for central management of devices and keying materials as well as for the backup of cryptographic keys. 
However, it also imposes some limitations. 
First, it represents a single point of failure. 
This is a major drawback, e.g., when key agreement between two devices requires online connectivity to the central node. Second, it limits the possibility to create ad-hoc security domains without dedicated security infrastructure. 
Third, it codifies a more static world view, where device roles are cast in stone, rather than a more dynamic world view that recognizes that networks and devices, and their roles and ownership, may change over time (e.g., due to device replacement and hand-over of control).

Decentralized architectures, on the other hand, allow creating ad-hoc security domains that might not require a single online management entity and are operative in a much more stand-alone manner. 
The ad- hoc security domains can be added to a centralized architecture at a later point in time, allowing
for central or remote management.


The choice of security architecture has many implications regarding key management, access control, or security scope. 
A distributed (or ad-hoc) architecture means that security relationships between things are setup on the fly between a number of objects and kept in a decentralized fashion, i.e., there is no central authority that can interfere with the system operation. 
A locally centralized security architecture means that a central device, e.g., the 6LBR, handles the keys for all the devices in the security domain. 
Alternatively, a central security architecture could also refer to the fact that smart objects are managed from the backend. 
It can also refer to a public-key infrastructure used to manage identities and digital certificates associated to the different devices.

The security architecture for the different security profiles is classified as follows.



~~~~
           +---------------------------------------------------------+
           |                 Description                             |
+----------+---------------------------------------------------------+
|SecProf_1 |                Distributed                              |
+----------+---------------------------------------------------------+
|SecProf_2 |     Distributed able to move centralized (local)        |
+----------+---------------------------------------------------------+
|SecProf_3 |         Centralized (local &/or backend)                |
+----------+---------------------------------------------------------+
|SecProf_4 |      Distributed & centralized (local &/or backend)     |
+----------+---------------------------------------------------------+
~~~~
{: #fig7 title="Security architectures in different security profiles."}

In "SecProf_1", management mechanisms for the distributed assignment and management of keying materials is required. Since this is a very simple use case, access control to the formed security domain can be enabled by means of a common secret known to all devices. 
In the next security suite (SecProf_2), a central device can assume key management responsibilities and handle the
access to the network. 
The last two security suites (SecProf_3 and SecProf_4) further allow for the management of devices or some operational keying materials from the backend.
Identity and public-key management can be realized by means of a public-key infrastructure or a more decentralized solution based on block-chain.

## Security Model {#sec6-3}

While some applications might involve very resource-constrained things such as, e.g., a humidity, pollution sensor, other applications might target more powerful devices aimed at more exposed applications. 
Security parameters such as keying materials, certificates, etc must be protected in the thing, for example by means of tamper-resistant hardware. 
Keys may be shared across a thing's networking stack to provide authenticity and confidentiality in each networking layer. 
This would minimize the number of key establishment/agreement handshake and incurs less overhead for constrained thing. While more advance applications may require key separation at different networking layers, and possibly process separation and sandboxing to isolate one application from another. 
In this sense, this section reflects the fact that different applications require different sets of security mechanisms.
A very important requirement refers to the protection of application related parameters, data, and algorithms running on a smart object that should be proteced from extraction or manipulation.

~~~~
           +---------------------------------------------------------+
           |Description                                              |
+----------+---------------------------------------------------------+
|SecProf_1 |No tamper resistant                                      |
|          |Sharing keys between layers                              |
+----------+---------------------------------------------------------+
|SecProf_2 |No tamper resistant                                      |
|          |Sharing keys between layers                              |
+----------+---------------------------------------------------------+
|SecProf_3 |Tamper resistant                                         |
|          |Key and process separation                               |
|          |Data and algorithm protection from manipulation/copy     |
+----------+---------------------------------------------------------+
|SecProf_4 |(no) Tamper resistant                                    |
|          |Sharing keys between layers/Key and process separation   |
|          |Sandbox                                                  |
|          |Data and algorithm protection from manipulation/copy     |
+----------+---------------------------------------------------------+
~~~~
{: #fig8 title="Thing security models in different security profiles."}

## Security Bootstrapping and Management {#sec6-4}

Bootstrapping refers to the process by which a thing initiates its life within
a security domain and includes the initialization of secure and/or authentic
parameters bound to the thing and at least one other device in the network.
 Here, different mechanisms may be used to achieve confidentiality and/or
authenticity of these parameters, depending on deployment scenario assumptions
and the communication channel(s) used for passing these parameters. The
simplest mechanism for initial set-up of secure and authentic parameters
is via communication in the clear using a physical interface (USB, wire,
chip contact, etc.). Here, one commonly assumes this communication channel
is secure, since eavesdropping and/or manipulation of this interface would
generally require access to the physical medium and, thereby, to one or both
of the devices themselves. This mechanism was used with the so-called original "resurrecting duckling" model, as introduced in {{PROC-Stajano-99}}. This technique may also be used securely in wireless, rather than wired, set-ups, if the prospect of eavesdropping and/or manipulating this channel are dim (a so-called "location-limited" channel {{PROC-Smetters-04}}{{PROC-Smetters-02}}). Examples hereof include the communication of secret keys in the clear using near field communication (NFC) - where the physical channel is purported to have very limited range (roughly 10cm), thereby thwarting eavesdropping by far-away adversarial devices, and in-the-clear communication during a small time window (triggered by, e.g., a button-push) - where eavesdropping is presumed absent during this small time window. With the use of public-key based techniques, assumptions on the communication channel can be relaxed even further, since then the cryptographic technique itself provides for confidentiality of the channel set-up and the location-limited channel - or use of certificates - rules out man-in-the-middle attacks, thereby providing authenticity {{PROC-Smetters-02}}. The same result can be obtained using password-based
public-key protocols {{SPEKE}}, where authenticity depends on the (weak) password not being guessed during execution of the protocol. 

It should be noted that while most of these techniques realize a secure and authentic channel for passing parameters, these generally do not provide for explicit authorization. 
As an example, with use of certificate-based public-key based techniques, one may obtain hard evidence on whom one shares secret and/or authentic parameters with, but this does not answer the question as to whether one wishes to share this information at all with this specifically identified device (the latter usually involves a human-decision element). Thus, the bootstrapping mechanisms above should generally be complemented by mechanisms that regulate (security policies for) authorization. Furthermore, the type of bootstrapping is very related to the required type of security architecture. Distributed bootstrapping means that a pair of devices can setup a security relationship on the fly, without interaction with a central device elsewhere within the system. In many cases, it is handy to have a distributed bootstrapping protocol based on existing security protocols (e.g., DTLS in CoAP) required for other purposes: this reduces the amount of required software. A centralized bootstrapping protocol is one in which a central device manages the security relationships within a network. This can happen locally, e.g., handled by the 6LBR, or remotely, e.g., from a server connected via the Internet. The security bootstrapping for the different security profiles is as follows.

~~~~
           +---------------------------------------------------------+
           |Description                                              |
+----------+---------------------------------------------------------+
|SecProf_1 |* Distributed, (e.g., Resurrecting duckling)             |
|          |* First key distribution happens in the clear            |
+----------+---------------------------------------------------------+
|SecProf_2 |* Distributed, (e.g., Resurrecting duckling )            |
|          |* Centralized (local), 6LBR acts as KDC                  |
|          |* First key distribution occurs in the clear, if the KDC |
|          |  is available, the KDC can manage network access        |
+----------+---------------------------------------------------------+
|SecProf_3 |* 6LBR acts as KDC. It handles node joining, provides    |
|          |  them with keying material from L2 to application layers|
|          |* Bootstrapping occurs in a secure way - either in secure|
|          |  environment or the security mechanisms ensure that     |
|          |  eavesdropping is not possible.                         |
|          |* KDC and backend can implement secure methods for       |
|          |  network access                                         |
+----------+---------------------------------------------------------+
|SecProf_4 |* As in SecProf_3.                                       |
+----------+---------------------------------------------------------+
~~~~
{: #fig9 title="Security bootstrapping methods in different security profiles"}

## Network Security {#sec6-5}

Network security refers to the mechanisms used to ensure the secure transport
of network packets such as 6LoWPAN frames. This involves a multitude of issues ranging from secure
discovery, frame authentication, routing security, detection of replay, secure
group communication, etc. Network security is important to thwart potential
attacks such as denial-of-service (e.g., through message flooding) or routing
attacks.

The Internet Draft {{ID-Tsao}} presents a very good overview of attacks and
security needs classified according to the confidentiality, integrity, and
availability needs. A potential limitation is that there exist no differentiation in security between different use cases and the framework is limited to L3. The security suites gathered in the present ID aim at solving this by allowing for a more flexible selection of security needs at L2 and L3.

~~~~
           +---------------------------------------------------------+
           |Description                                              |
+----------+---------------------------------------------------------+
|SecProf_1 |* Network key creating a home security domain at L2      |
|          |  ensuring authentication and freshness of exchanged data|
|          |* Secure multicast does not ensure origin authentication |
|          |* No need for secure routing at L3                       |
+----------+---------------------------------------------------------+
|SecProf_2 |* Network key creating a home security domain at L2      |
|          |  ensuring authentication and freshness of exchanged data|
|          |* Secure multicast does not ensure origin authentication |
|          |* No need for secure routing at L3                       |
+----------+---------------------------------------------------------+
|SecProf_3 |* Network key creating an industry security domain at L2 |
|          |  ensuring authentication and freshness of exchanged data|
|          |* Secure routing needed (integrity & availability) at L3 |
|          |  within 6LoWPAN/CoAP                                    |
|          |* Secure multicast requires origin authentication        |
+----------+---------------------------------------------------------+
|SecProf_4 |* Network key creating an industry security domain at L2 |
|          |  ensuring authentication and freshness of exchanged data|
|          |* Inter-domain authentication/secure handoff             |
|          |* Secure routing needed at L3                            |
|          |* Secure multicast requires origin authentication        |
|          |* 6LBR (HTTP-CoAP proxy) requires verification of        |
|          |  forwarded messages and messages leaving or entering the|
|          |  6LoWPAN/CoAP network.                                  |
+----------+---------------------------------------------------------+
~~~~
{: #fig10 title="Network security needs in different security profiles"}

## Application Security {#sec6-6}

In the context of 6LoWPAN/CoAP networks, application security refers firstly
to the configuration of an application layer protocol, such as DTLS, to protect the exchanged information. 
It further refers to the measures required in potential translation points
(e.g., a (HTTP-CoAP) proxy) where information can be collected and the privacy
sphere of users in a given security domain is endangered. 
Application security for the different security profiles is as follows.



~~~~
           +---------------------------------------------------------+
           |Description                                              |
+----------+---------------------------------------------------------+
|SecProf_1 |  -                                                      |
+----------+---------------------------------------------------------+
|SecProf_2 |* DTLS is used for end-to-end application security       |
|          |  between management device and things and between things|
|          |* DTLS ciphersuites configurable to provide              |
|          |  confidentiality and/or authentication and/or freshness |
|          |* Key transport and policies for generation of session   |
|          |  keys are required                                      |
+----------+---------------------------------------------------------+
|SecProf_3 |* Requirements as in SecProf_2 and                       |
|          |* DTLS is used for end-to-end application security       |
|          |  between management device and things and between things|
|          |* Communication between KDC and each thing secured by    |
|          |  pairwise keys                                          |
|          |* Group keys for communication in a group distributed    |
|          |  by KDC                                                 |
|          |* Privacy protection should be provided in translation   |
|          |  points                                                 |
+----------+---------------------------------------------------------+
|SecProf_4 |* Requirements as in SecProf_3 and                       |
|          |* TLS or DTLS can be used to send commands from the      |
|          |  backend to the 6LBR or things in a 6LoWPAN/CoAP network|
|          |* End-to-end secure connectivity from backend required   |
|          |* Secure broadcast in a network from backend required    |
+----------+---------------------------------------------------------+
~~~~
{: #fig11 title="Application security methods in different security profiles"}

The first two security profiles do not include any security at the application
layer. The reason is that, in the first case, security is not provided and,
in the second case, it seems reasonable to provide basic security at L2.
 In the third security profile (SecProf_2), DTLS becomes the way of protecting
messages at application layer between things and with the KDC running on
a 6LBR. A key option refers to the capability of easily configuring DTLS
to provide a subset of security services (e.g., some applications do not
require confidentiality) to reduce the impact of security in the system operation of resource-constrained things. In addition to basic key management mechanisms running within the KDC, communication protocols for key transport or key update are required. These protocols could be based on DTLS. The next security suite (SecProf_3) requires pairwise keys for communication between things within the security domain. Furthermore, it can involve the usage of group keys for group communication. If secure multicast is implemented, it should provide origin authentication. Finally, privacy protection should be taken into account to limit access to valuable information --- such as identifiers, type of collected data, traffic patterns --- in potential translation points (proxies) or in the backend. The last security suite (SecProf_4) further extends the previous set of requirements considering security mechanisms to deal with translations between TLS and DTLS or for the provision of secure multicast within a 6LoWPAN/CoAP network from the backend.



# Challenges for a Secure IoT {#sec7}

In this section, we take a closer look at the various security challenges
in the operational and technical features of the IoT and then discuss how
existing Internet security protocols cope with these technical and conceptual
challenges through the lifecycle of a thing. Figure 2 summarizes which requirements need to be met in the lifecycle phases as well as some of the considered protocols. This discussion should neither be understood as a comprehensive evaluation of all protocols, nor can it cover all possible aspects of IoT security. Yet, it aims at showing concrete limitations of existing Internet security protocols in some areas rather than giving an abstract discussion about general properties of the protocols. In this regard, the discussion handles issues that are most important from the authors' perspectives.

## Constraints and Heterogeneous Communication {#sec7-1}

Coupling resource constrained networks and the powerful Internet is a challenge because the resulting heterogeneity of both networks complicates protocol design and system operation. In the following we briefly discuss the resource constraints of IoT devices and the consequences for the use of Internet Protocols in the IoT domain.

### Tight Resource Constraints {#sec7-1-1}

The IoT is a resource-constrained network that relies on lossy and low-bandwidth channels for communication between small nodes, regarding CPU, memory, and energy budget. These characteristics directly impact the threats to and the design of security protocols for the IoT domain. First, the use of small packets, e.g., IEEE 802.15.4 supports 127-byte sized packets at the physical layer, may result in fragmentation of larger packets of security protocols. This may open new attack vectors for state exhaustion DoS attacks, which is especially tragic, e.g., if the fragmentation is caused by large key exchange messages of security protocols. Moreover, packet fragmentation commonly downgrades the overall system performance due to fragment losses and the need for retransmissions. For instance, fate-sharing packet flight as implemented by DTLS might aggravate the resulting performance loss.


The size and number of messages should be minimized to reduce memory requirements and optimize bandwidth usage. In this context, layered approaches involving a number of protocols might lead to worse performance in resource-constrained devices since they combine the headers of the different protocols. In some settings, protocol negotiation can increase the number of exchanged messages. To improve performance during basic procedures such as, e.g., bootstrapping, it might be a good strategy to perform those procedures at a lower layer.

Small CPUs and scarce memory limit the usage of resource-expensive cryptoprimitives such as public-key cryptography as used in most Internet security standards. This is especially true, if the basic cryptoblocks need to be frequently used or the underlying application demands a low delay.

Independently from the development in the IoT domain, all discussed security protocols show efforts to reduce the cryptographic cost of the required public-key-based key exchanges and signatures with ECC{{RFC5246}}{{RFC5903}}{{RFC7401}}{{ID-HIP}}. Moreover, all protocols have been revised in the last years to enable crypto agility, making cryptographic primitives interchangeable. However, these improvements are only a first step in reducing the computation and communication overhead of Internet protocols. The question remains if other approaches can be applied to leverage key agreement in these heavily resource-constrained environments.

A further fundamental need refers to the limited energy budget available
to IoT nodes. Careful protocol (re)design and usage is required to reduce
not only the energy consumption during normal operation, but also under DoS
attacks. Since the energy consumption of IoT devices differs from other
device classes, judgments on the energy consumption of a particular protocol
cannot be made without tailor-made IoT implementations.

### Denial-of-Service Resistance {#sec7-1-2}

The tight memory and processing constraints of things naturally alleviate
resource exhaustion attacks. Especially in unattended T2T communication,
such attacks are difficult to notice before the service becomes unavailable
(e.g., because of battery or memory exhaustion). As a DoS countermeasure,
DTLS, IKEv2, HIP, and Diet HIP implement return routability checks based
on a cookie mechanism to delay the establishment of state at the responding
host until the address of the initiating host is verified. The effectiveness
of these defenses strongly depends on the routing topology of the network.
 Return routability checks are particularly effective if hosts cannot receive
packets addressed to other hosts and if IP addresses present meaningful information as is the case in today's Internet. However, they are less effective in broadcast media or when attackers can influence the routing and addressing of hosts (e.g., if hosts contribute to the routing infrastructure in ad-hoc networks and meshes).

In addition, HIP implements a puzzle mechanism that can force the initiator
of a connection (and potential attacker) to solve cryptographic puzzles with
variable difficulties. Puzzle-based defense mechanisms are less dependent
on the network topology but perform poorly if CPU resources in the network
are heterogeneous (e.g., if a powerful Internet host attacks a thing). Increasing the puzzle difficulty under attack conditions can easily lead to situations, where a powerful attacker can still solve the puzzle while weak IoT clients cannot and are excluded from communicating with the victim. Still, puzzle-based approaches are a viable option for sheltering IoT devices against unintended overload caused by misconfigured or malfunctioning things.

### Protocol Translation and End-to-End Security {#sec7-1-3}

Even though 6LoWPAN and CoAP progress towards reducing the gap between Internet protocols and the IoT, they do not target protocol specifications that are identical to their Internet counterparts due to performance reasons. Hence, more or less subtle differences between IoT protocols and Internet protocols will remain. While these differences can easily be bridged with protocol translators at gateways, they become major obstacles if end-to-end security measures between IoT devices and Internet hosts are used.

Cryptographic payload processing applies message authentication codes or
encryption to packets. These protection methods render the protected parts
of the packets immutable as rewriting is either not possible because a) the
relevant information is encrypted and inaccessible to the gateway or b) rewriting integrity-protected parts of the packet would invalidate the end-to-end integrity protection.

There are essentially four solutions for this problem:

1. Sharing credentials with gateways enables gateways to transform (e.g., de-compress, convert, etc.) packets and re-apply the security measures after transformation. This method abandons end-to-end security and is only applicable to simple scenarios with a rudimentary security model.

2. Reusing the Internet wire format in the IoT makes conversion between IoT and Internet protocols unnecessary. However, it leads to poor performance because IoT specific optimizations (e.g., stateful or stateless compression) are not possible.

3. Selectively protecting vital and immutable packet parts with a MAC or with encryption requires a careful balance between performance and security. Otherwise, this approach will either result in poor performance (protect as much as possible) or poor security (compress and transform as much as possible).

4. Message authentication codes that sustain transformation can be realized by considering the order of transformation and protection (e.g., by creating a signature before compression so that the gateway can decompress the packet without recalculating the signature). This enables IoT specific optimizations but is more complex and may require application-specific transformations before security is applied. Moreover, it cannot be used with encrypted data because the lack of cleartext prevents gateways from transforming packets.
 
5. Object security based mechanisms can bridge the protocol worlds, but still requires that the two worlds use the same object security formats. Currently the IoT based object security format based on COSE is different from the Internet based JOSE or CMS. Legacy devices on the Internet side will need to update to the newer IoT protocols to enable real end-to-end security.

To the best of our knowledge, none of the mentioned security protocols provides a fully customizable solution in this problem space. 

### New network architectures and paradigm {#sec7-1-4}

There is a multitude of new link layer protocols that aim to address the resource-constrained nature of IoT devices. For example, the IEEE 802.11 ah {{IEEE802ah}} has been specified for extended range and lower energy consumption to support Internet of Things (IoT) devices. Similary, Low-Power Wide-Area Network (LPWAN) protocols such as LoRa {{lora}}, Sigfox {{sigfox}}, NarrowBand IoT (NB-IoT) are all designed for resource-constrained devices that require long range and low bit rates. While these protocols allow the IoT devices to conserve energy and operate efficiently, they also add additional security challenges. For example, the relatively small MTU can make security handshakes with large X509 certificates a significant overhead. At the same time, new communication paradigms also allow IoT devices to communicate directly amongst themselves with or without support from the network. This communication paradigm is also referred to as Device-to-Device (D2D) or Machine-to-Machine (M2M) or Thing-to-Thing (T2T) communication. D2D is primarily driven by network operators that want to utilize short range communication to improve the network performance and for supporting proximity based service

## Bootstrapping of a Security Domain {#sec7-2}

Creating a security domain from a set of previously unassociated IoT devices
is a key operation in the lifecycle of a thing and in the IoT network. This aspect is further elaborated and discussed in the T2TRG draft on bootstrapping {{ID-bootstrap}}.


## Operation {#sec7-3}

After the bootstrapping phase, the system enters the operational phase. 
During the operational phase, things can relate to the state information
created during the bootstrapping phase in order to exchange information securely and in an authenticated fashion. In this section, we discuss aspects of communication patterns and network dynamics during this phase.

### End-to-End Security {#sec7-3-1}

Providing end-to-end security is of great importance to address and secure
individual T2T or H2T communication within one IoT domain. Moreover, end-to-end security associations are an important measure to bridge the gap between the IoT and the Internet. IKEv2 and HIP, TLS and DTLS provide end-to-end security services including peer entity authentication, end-to-end encryption and integrity protection above the network layer and the transport layer respectively. Once bootstrapped, these functions can be carried out without online connections to third parties, making the protocols applicable for decentralized use in the IoT. However, protocol translation by intermediary nodes may invalidate end-to-end protection measures (see {{sec5-1}}). Also these protocols require end-to-end connectivity between the devices and do not support store-and-forward scenarios. Object security is an option for such scenarios and the work on OSCOAP {{ID-OSCOAP}} is a potential solution in this space, in particular, in the context of forwarding proxies.

### Group Membership and Security {#sec7-3-2}

In addition to end-to-end security, group key negotiation is an important
security service for the T2Ts and Ts2T communication patterns in the IoT
as efficient local broadcast and multicast relies on symmetric group keys.

All discussed protocols only cover unicast communication and therefore do
not focus on group-key establishment. However, the Diffie-Hellman keys that
are used in IKEv2 and HIP could be used for group Diffie-Hellman key-negotiations. Conceptually, solutions that provide secure group communication at the network layer (IPsec/IKEv2, HIP/Diet HIP) may have an advantage regarding the cryptographic overhead compared to application-focused security solutions (TLS/ DTLS or OSCOAP). This is due to the fact that application-focused solutions require cryptographic operations per group application, whereas network layer approaches may allow to share secure group associations between multiple applications (e.g., for neighbor discovery and routing or service discovery). Hence, implementing shared features lower in the communication stack can avoid redundant security measures.

A number of group key solutions have been developed in the context of the
IETF working group MSEC in the context of the MIKEY architecture {{WG-MSEC}}{{RFC4738}}. These are specifically tailored for multicast and group broadcast applications in the Internet and should also be considered as candidate solutions for group key agreement in the IoT. The MIKEY architecture describes a coordinator entity that disseminates symmetric keys over pair-wise end-to-end secured channels. However, such a centralized approach may not be applicable in a distributed environment, where the choice of one or several coordinators and the management of the group key is not trivial.

### Mobility and IP Network Dynamics {#sec7-3-3}

It is expected that many things (e.g., wearable sensors, and user devices) will be mobile in the sense that they are attached to different networks
during the lifetime of a security association. Built-in mobility signaling can greatly reduce the overhead of the cryptographic protocols because unnecessary and costly re- establishments of the session (possibly including handshake and key agreement) can be avoided. IKEv2 supports host mobility with the MOBIKE {{RFC4555}}{{RFC4621}} extension. MOBIKE refrains from applying heavyweight cryptographic extensions for mobility. However, MOBIKE mandates the use of IPsec tunnel mode which requires to transmit an additional IP header in each packet. This additional overhead could be alleviated by using header compression methods or the Bound End- to-End Tunnel (BEET) mode {{ID-Nikander}}, a hybrid of tunnel and transport mode with smaller packet headers.

HIP offers a simple yet effective mobility management by allowing hosts to signal changes to their associations {{RFC5206}}. However, slight adjustments
might be necessary to reduce the cryptographic costs, for example, by making the public-key signatures in the mobility messages optional. Diet HIP does
not define mobility yet but it is sufficiently similar to HIP to employ the same mechanisms. TLS and DTLS do not have standards for mobility support, however, work on DTLS mobility exists in the form of an Internet draft {{ID-Williams}}. The specific need for IP-layer mobility mainly depends on the scenario in which nodes operate. In many cases, mobility support by means of a mobile gateway may suffice to enable mobile IoT networks, such as body sensor networks. However, if individual things change their point of network attachment while communicating, mobility support may gain importance.

## Software update {#sec7-4}

IoT devices have a reputation for being insecure at the time of manufacture. Yet they are often expected to stay functional in live deployments for years and even decades. Additionally, these devices typically operate unattended with direct Internet connectivity. Therefore, a remote software update mechanism to fix vulnerabilities, to update configuration settings, and for adding new functionality is needed. 

Schneier {{SchneierSecurity}} in his essay expresses concerns about the status of software and firmware update mechanisms for Internet of Things (IoT) devices. He highlights several challenges that hinder mechanisms for secure software update of IoT devices. First, there is a lack of incentives for manufactures, vendors and others on the supply chain to issue updates for their devices. Second, parts of the software running on the IoT devices is simply a binary blob without any source code available. Since the complete source code isn not available, no patches can be written for that piece of code. Third, even when updates are available, users generally have to manually download and install those updates. However, users are never alerted about security updates and many times do not have the necessary expertise to manually administer the required updates.

The FTC staff report on Internet of Things - Privacy & Security in a Connected World {{FTCreport}} and the Article 29 Working Party Opinion 8/2014 on the on Recent Developments on the Internet of Things {{Article29}} also document the challenges for secure remote software update of IoT devices. They note that even providing such a software update capability may add new vulnerabilities for constrained devices. For example, a buffer overflow vulnerability in the implementation of a software update protocol (TR69) {{TR69}} and an expired certificate in a hub device {{wink}} demonstrate how the software update process itself can introduce vulnerabilities. 

While powerful IoT devices that run general purpose operating systems can make use of sophisticated software update mechanisms known from the desktop world, a more considerate effort is needed for resource-constrained devices that don't have any operating system and are typically not equipped with a memory management unit or similar tools. The IAB also organized a workshop to understand the challenges for secure software update of IoT devices. A summary of the workshop and the proposed next steps have been documented {{iotsu}}. 

## Verifying device behavior {#sec7-5}

Users often have a false sense of privacy when using new Internet of Things (IoT) appliances such as Internet-connected smart televisions, speakers and cameras. Recent revelations have shown that this user belief is often unfounded. Many IoT device vendors have been caught collecting sensitive private data through these connected appliances with or without appropriate user warnings {{cctv}}.

An IoT device user/owner would like to monitor and know if the device is calling home (i.e. verify its operational behavior). The calling home feature may be necessary in some scenarios, such as during the initial configuration of the device. However, the user should be kept aware of the data that the device is sending back to the vendor. For example, the user should be ensured that his/her TV is not sending data when he/she inserts a new USB stick. 

Providing such information to the users in an understandable fashion is challenging. This is because the IoT devices are not only resource-constrained in terms of their computational capability, but also in terms of the user interface available. Also, the network infrastructure where these devices are deployed will vary significantly from one user environment to another. Therefore, where and how this monitoring feature is implemented still remains an open question. 

## End-of-life {#sec7-6}
Like all commercial devices, most IoT devices will be end-of-lifed by vendors or even network operators. This may be planned or unplanned (for example when the vendor or manufacturer goes bankrupt or when a network operator moves to a different type of networking technology). A user should still be able to use and perhaps even update the device. This requires for some form of authorization handover.

Although this may seem far fetched given the commercial interests and market dynamics, we have examples from the mobile world where the devices have been functional and up-to-date long after the original vendor stopped supporting the device. CyanogenMod for Android devices and OpenWrt for home routers are two such instances where users have been able to use and update their devices even after they were end-of-lifed. Admittedly these are not easy for an average users to install and configure on their devices. With the deployment of millions of IoT devices, simpler mechanisms are needed to allow users to add new root-of-trusts and install software and firmware from other sources once the device has been end-of-lifed.


## Testing: bug hunting and vulnerabilities {#sec7-7}
Given that the IoT devices often have inadvertent vulnerabilities, both users and developers would want to perform extenshive testing on their IoT devices, networks, and systems. Nonetheless, since the devices are  resource-constrained and manufactured by multiple ventors, some of them very small, devices might be shipped with very limited testing, so that bugs can remain and can be exploited at a later stage.
This leads to two main types of challenges:
1. It remains to be seen how the software testing and quality assurance mechanisms used from the desktop and mobile world will be applied to IoT devices to give end users the confidence that the purchased devices are robust.
2. It is also an open question how combination of devices of multiple vendors might actually lead to dangerous network configurations, e.g., if combination of specific devices can trigger unexpected behaiviours.

## Quantum-resistance {#sec7-8}

Many IoT systems that are being deployed today will remain operational for many years. With the advancements made in the field of quantum computers, it is possible that large-scale quantum computers are available in the future for performing cryptanalysis on existing cryptographic algorithms and cipher suites. If this happened, it would have two consequences. First, functionalities enabled by means of RSA/ECC - namely key exchange, public-key encryption and signature - would not be secure anymore due to Shor's algorithm. Second, the security level of symmetric algorithms will decrease, e.g., the security of a block cipher with a key size of b bits will only offer b/2 bits of security due to Grover's algorithm.

This would require to move to quantum-resistant alternatives, in particular, for those functionalities involving key exchange, public-key encryption and signatures. While such future planning is hard, it may be a necessity in certain critical IoT deployments which are expected to last decades or more. Although increasing the key-size of the different algorithms is definitely an
option, it would also incur additional computation overhead and network traffic. This would be undesirable in most scenarios. There have been recent advancements in quantum-resistant cryptography.

We refer to {{ETSI_GR_QSC_001}} for an extensive overview of existing quantum-resistant cryptography.
RFC7696 provides guidelines for cryptographic algorithm agility.

## Privacy protection {#sec7-9}

Users will be surrounded by tens of connected devices. Even if the communication links are encrypted and protected, information about the users might be collected for different purposes affecting their privacy. 
In {{Ziegeldorf}}, privacy in the IoT is defined as the threefold guarantee to the user for:
1. awareness of privacy risks imposed by smart things and services surrounding the data subject,
2. individual control over the collection and processing of personal information bz the surrounding smart things
3. awareness and control of subsequent use and dissemination of personal information by those entities to any entity outside the subject's personal control sphere.

Based on this definition, several privacy threats and challenges are identified in the work of Ziegeldorf:

1. Identification - refers to the identification of the users and their objects.
2. Localization - relates to the capability of locating a user and even tracking him.
3. Profiling - is about creating a profile of the user and her preferences.
4. Interaction - occurs when a user has been profiled and a given interaction is preferered, presenting (e.g., visually) some information that discloses private information. 
5. Lifecycle transitions - take place when devices are, e.g., sold without properly removing private data.
6. Inventory attacks - happen if specific information about (smart) objects in posession of a user is disclosed.
7. Linkage - is about when information of two of more IoT systems is combined so that a broader view on the personal data is created.

When IoT systes are deployed, the above issues should be considered to ensure that private data remains private. How this is achieved remains an open issue.

## Data leakage {#sec7-10}

IoT devices are resource contrained and often deployed in unattended environments or can just be bought in the Internet. Therefore, an attacker can have direct access to the device and apply more advance techniques that a traditional black box model does not consider such as side-channel attacks or code disassembly. By doing this, the attacker can try to retrieve data such as:

1. long term keys that might be used perform attacks on devices deployed in other locations. 
2. source code that might let the user determine bugs or find exploits to perform other types of attacks, or just sell it,
3. propiertary algorithms that could be counterfeited or modified to perform advanced attacks.

Protection against such data leakage patterns is not trivial since devices are inherently resource-constrained.
An open question is which techniques can be used to protect IoT devices in such a strong attack model.

## Trustworthy IoT Operation {#sec7-11}

Flaws in the design and implementation of a secure IoT device and network can lead to secure vulnerabilities. An example is a flaw is the distribution of an Internet-connected IoT device in which a default password is used in all devices. Many IoT devices can be found in the Internet by means of tools such as Shodan, and if they have any vulnerability, it can then be exploited at scale, e.g., to launch DDoS attacks. This is not fiction but reality as Dyn, a mayor DNS was attacked by means of a DDoS attack originated from a large IoT botnet composed of thousands of compromised IP-cameras. Open questions in this area are:

1. How to prevent large scale vulnerabilties in IoT devices?
2. How to prevent attackers from exploiting vulnerabilities in IoT devices at large scale?
3. If the vulnerability has been exploited, how do we stop a large scale attack before any damage is caused?


# Conclusions and Next Steps {#sec8}

This Internet Draft provides an overview of both operational and security requirements in the IP-based Internet of Things. We discuss a general threat model, security issues, and state of the art. We further introduce a number of potential security profiles fitting different types of IoT deployments and discuss key security challenges.

# Security Considerations {#sec9}

This document reflects upon the requirements and challenges of the security
architectural framework for the Internet of Things.

# IANA Considerations {#sec10}

This document contains no request to IANA.

# Acknowledgements {#sec11}

We gratefully acknowledge feedback and fruitful discussion with Tobias Heer
and Robert Moskowitz. Acknowledge the additional authors of the previous version of this document Sye Loong Keoh, Rene Hummen and Rene Struik.

