---
abbrev: IoT Security
title: State of the Art and Challenges for the Internet of Things Security
docname: draft-irtf-t2trg-iot-seccons
cat: info
stand_alone: true
informative:
  ID-dietesp: I-D.mglt-6lo-diet-esp
  ID-senml: I-D.ietf-core-senml
  ID-rd: I-D.ietf-core-resource-directory
  ID-cose: I-D.ietf-cose-msg
  ID-6lodect: I-D.ietf-6lo-dect-ule
  RFC8105: ID-6lodect
  ID-6lonfc: I-D.ietf-6lo-nfc
  ID-6tisch: I-D.ietf-6tisch-architecture
  ID-aceoauth: I-D.ietf-ace-oauth-authz
  ID-Daniel: I-D.daniel-6lowpan-security-analysis
  ID-HIP: I-D.moskowitz-hip-rg-dex
  RFC7401:
  ID-Nikander: I-D.nikander-esp-beet-mode
  ID-Tsao: I-D.ietf-roll-security-framework
  ID-Moore: I-D.moore-iot-security-bcp
  ID-MUD: I-D.ietf-opsawg-mud
  ID-Williams: I-D.barrett-mobile-dtls
  ID-OSCOAP: I-D.selander-ace-object-security
  ENISA_ICS:
    title: "Communication network dependencies for ICS/SCADA Systems"
    date: 2017-02
    seriesinfo: European Union Agency For Network And Information Security
  ID-bootstrap: I-D.sarikaya-t2trg-sbootstrapping
  RFC2818: 
  RFC3261: 
  RFC3748: 
  RFC3756: 
  RFC3833: 
  RFC4016:
  RFC4555: 
  RFC4621: 
  RFC4738: 
  RFC4919: 
  RFC4944: 
  RFC5191: 
  RFC8046: 
  RFC5246:
  RFC5713: 
  RFC5903: 
  RFC6347:
  RFC6550:
  RFC6551:
  RFC6568:
  RFC6690:
  RFC6749:
  RFC6973:
  RFC7049:
  RFC7159:
  RFC7228:
  RFC7252:
  RFC7296:
  RFC7515:
  RFC7517:
  RFC7519:
  RFC7668:
  RFC7696:
  RFC7815:
  RFC7925: 
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
  WG-6LoWPAN:
    title: IETF 6Lo Working Group
    date: 2011-02
    seriesinfo:
      Web: http://tools.ietf.org/wg/6lowpan/
  WG-CoRE:
    title: IETF Constrained RESTful Environment (CoRE) Working Group
    date: 2011-02
    seriesinfo:
      Web: https://datatracker.ietf.org/wg/core/charter/
  WG-LWIG:
    title: IETF Light-Weight Implementation Guidance (LWIG) Working Group
    date: 2011-03
    seriesinfo:
      Web: https://datatracker.ietf.org/wg/lwig/charter/   
  RG-T2TRG:
    title: IRTF Thing-to-Thing (T2TRG) Research Group
    date: 2015-12
    seriesinfo:
      Web: https://datatracker.ietf.org/rg/t2trg/charter/
  WG-ACE:
    title: IETF Authentication and Authorization for Constrained Environments (ACE) Working Group
    date: 2014-06
    seriesinfo:
      Web: https://datatracker.ietf.org/wg/ace/charter/
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
  nist_lightweight_project:
    title: 'NIST lightweight Project'
    seriesinfo:
      Web: www.nist.gov/programs-projects/lightweight-cryptography, www.nist.gov/sites/default/files/documents/2016/10/17/sonmez-turan-presentation-lwc2016.pdf      
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
    title: Thread Group
    seriesinfo:
      Web: http://threadgroup.org/
  Fairhair:
    title: Fairhair Alliance
    seriesinfo:
      Web: https://www.fairhair-alliance.org/
  LWM2M:
    title: OMA LWM2M
    seriesinfo:
      Web: http://openmobilealliance.org/iot/lightweight-m2m-lwm2m
  IIoT:
    title: Industrial Internet Consortium
    seriesinfo:
      Web: http://www.iiconsortium.org/      
  IPSO:
    title: IPSO Alliance
    seriesinfo:
      Web: http://www.ipso-alliance.org
  OneM2M:
    title: OneM2M
    seriesinfo:
      Web: http://www.onem2m.org/
  OCF:
    title: Open Connectivity Foundation
    seriesinfo:
      Web: https://openconnectivity.org/      
  NHTSA:
    title: Cybersecurity Best Practices for Modern Vehicles
    seriesinfo:
      Web: https://www.nhtsa.gov/staticfiles/nvs/pdf/812333_CybersecurityForModernVehicles.pdf     
  NIST-FIS:
    title: Security and Privacy Controls for Federal Information Systems and Organizations
    seriesinfo:
      Web: http://dx.doi.org/10.6028/NIST.SP.800-53r4        
  NIST-Guide:
    title: Systems Security Engineering
    author:
    - ins: R. Ross
    - ins: M. McEvilley
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
  org: Philips IP&S
  street: High Tech Campus 5
  city: Eindhoven,   5656 AA
  country: The Netherlands
  email: oscar.garcia-morchon@philips.com
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
pi:
- toc
- sortrefs
- symrefs
- compact
- comments


--- abstract

The Internet of Things (IoT) concept refers to the usage of standard Internet protocols to allow for human-to-thing and thing-to-thing communication. The security needs are well-recognized and and many standardization steps for providing security have been taken, for example, the specification of Constrained Application Protocol (CoAP) over Datagram Transport Layer Security (DTLS). However, security challenges still exist and there are some use cases that lack a suitable solution. In this document, we first discuss the various stages in the lifecycle of a thing. We then look at the security building blocks available for securing the different layers of the Internet protocol suite. Next, we document the various security threats to a thing and the challenges that one might face in order to protect against these threats. Lastly, we discuss the next steps needed to ensure roll out of secure Internet of Things services.

This document is a product of the IRTF Thing-to-Thing Research Group (T2TRG).


--- middle

# Introduction {#sec2}

The Internet of Things (IoT) denotes the interconnection of highly heterogeneous networked entities and networks following a number of communication patterns such as: human-to-human (H2H), human-to-thing (H2T), thing-to-thing (T2T), or thing-to-things (T2Ts). The term IoT was first coined by the Auto-ID center {{AUTO-ID}} in 1999. Since then, the development of the underlying concepts and technologies has ever increased the pace of its adoption. It is not surprising that IoT has received significant attention from the research community to (re)design, apply, and use of standard Internet technology and protocols for IoT.

The introduction of IPv6 and web services as fundamental building blocks for IoT applications {{RFC6568}} promises to bring a number of basic advantages including: (i) a homogeneous protocol ecosystem that allows simple integration with Internet hosts; (ii) simplified development for devices that significantly vary in their capabilities; (iii) an unified interface for applications, removing the need for application-level proxies. These building blocks greatly simplify the deployment of the envisioned scenarios ranging from building automation to production environments to personal area networks, in which very different things such as a temperature sensor, a luminaire, or an RFID tag might interact with each other, with a human carrying a smart phone, or with backend services.

This Internet Draft presents an overview of the security aspects of the envisioned all-IP architecture as well as of the lifecycle of an IoT device, a "thing", within this architecture. In particular, we review the most crucial aspects and functionalities that are required for a secure all-IP solution in the IoT.
Thus, when we talk about IoT protocols in this document we will refer to IP protocols that have been or are being standardized to run in constrained environments. 

With this, this Internet-Draft pursues several goals. First, we aim at presenting a comprehensive view of the interactions and relationships between an IoT application and security. Second, we aim at describing challenges for a secure IoT in the specific context of the lifecycle of a resource-constrained device. The final goal of this draft is to discuss the security considerations that are necessary for deploying secure IoT services.

The first draft version of this document was submitted in March 2011. Initial draft versions of this document were presented and discussed during the CORE meetings at IETF 80 and later. Discussions on security lifecycle at IETF 92 (March 2015) evolved into more general security considerations. Thus, the draft was selected to address the T2TRG work item on the security considerations and challenges for the Internet of Things. Further updates of the draft were presented and    discussed during the T2TRG meetings at IETF 96 (July 2016) and IETF 97 (November 2016) and at the joint interim in Amsterdam (March 2017). This document has been reviewed, commented, and  discussed extensively for a period of nearly six years by the vast majority of T2TRG members and related groups such as CORE, which certainly exceeds 100 individuals. It is the consensus of T2TRG that the baseline scenarios described in this document should be published in the IRTF Stream of the RFC series. This document does not constitute a standard.

The rest of the Internet-Draft is organized as follows. {{sec3}} depicts the lifecycle of a thing and gives general definitions for the main security building blocks within the IoT domain. In {{sec4}}, we discuss threats and methodologies for managing risks when designing a secure IoT system. {{sec5}} reviews existing IP-based (security) protocols for the IoT and briefly summarizes existing guidelines and regulations in IoT security. {{sec6}} identifies remaining challenges for a secure IoT and discusses potential solutions. {{sec7}} includes final remarks and conclusions.


# Motivation and background {#sec3}


## The Thing Lifecycle {#sec3-1}

The lifecycle of a thing refers to the operational phases of a thing in the context of a given application or use case. {{fig1}} shows the generic phases of the lifecycle of a thing. This generic lifecycle is applicable to very different IoT applications and scenarios.

We consider for example, a Building Automation and Control (BAC) system, to illustrate the lifecycle and the meaning of these different phases. 
A BAC system consists of a network of interconnected nodes that performs various functions in the domains of HVAC (Heating, Ventilating, and Air Conditioning), lighting, safety etc. The nodes vary in functionality and a majority of them represent resource-constrained devices such as sensors and luminaries. Some devices may be battery operated or may rely on energy harvesting. This requires us to also consider devices that that sleep during their operation to save energy. In our example, the life of a thing starts when it is manufactured. Due to the different application areas (i.e., HVAC, lighting, safety) nodes are tailored to a specific task. It is therefore unlikely that one single manufacturer will create all nodes in a building. Hence, interoperability as well as trust bootstrapping between nodes of different vendors is important. The thing is later installed and commissioned within a network by an installer during the bootstrapping phase. Specifically, the device identity and the secret keys used during normal operation are provided to the device during this phase. Different subcontractors may install different IoT devices for different purposes. Furthermore, the installation and bootstrapping procedures may not be a defined event but may stretch over an extended period of time. After being bootstrapped, the device and the system of things are in operational mode and execute the functions of the BAC system. During this operational phase, the device is under the control of the system owner. For devices with lifetimes spanning several years, occasional maintenance cycles may be required. During each maintenance phase, the software on the device can be upgraded or applications running on the device can be reconfigured. The maintenance tasks can thereby be performed either locally or from a backend system by means of an end-to-end connection. Depending on the operational changes of the device, it may be required to re-bootstrap at the end of a maintenance cycle. The device continues to loop through the operational phase and the eventual maintenance phase until the device is decommissioned at the end of its lifecycle. However, the end-of-life of a device does not necessarily mean that it is defective but rather denotes a need to replace and upgrade the network to next-generation devices in order to provide additional  functionality. Therefore the device can be removed and re-commissioned to be used in a different system under a different owner by starting the lifecycle all over again. 




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
First, an IoT systems enable very specific applications in which users are involved. A broken IoT system means that the privacy and safety of the users is endangered. This privacy and safety of users is however a key requirement in application areas such as critical infrastructure or health care. Second, a compromised IoT system means that if an attacker alters the functionality of a device of a given manufacturer, this not only affects the manufacturer's brand image in a negative way but can also leak information that is very valuable for the manufacturer (such as proprietary algorithms). Third, the impact of attacking the IoT goes beyond a specific device or isolated systems since compromised IoT systems can be misused at scale, e.g., performing a Distribute Denial of Service (DDoS) attack that limits the availability of the compromised system or even other IT networks. The fact that many IoT systems rely on standard IP protocols allows for easier system integration increasing the value of the realized use cases, but this also makes standard attacks applicable to a wide number of devices deployed in multiple systems. This results in new requirements regarding the implementation of security.

The term security subsumes a wide range of primitives, protocols, and procedures. In the first place, it includes the basic provision of security services including confidentiality, authentication, integrity, authorization, non-repudiation, and availability, and some augmented services, such as duplicate detection and detection of stale packets (timeliness). These security services can be implemented by a combination of cryptographic mechanisms, such as block ciphers, hash functions, or signature algorithms, and non-cryptographic mechanisms, which implement authorization and other security policy enforcement aspects. For each of the cryptographic mechanisms, a secure key management infrastructure is fundamental to handling the required cryptographic keys, whereas for security policy enforcement, one needs to properly codify authorizations as a function of device roles and a security policy engine that implements these authorization checks and that can implement changes hereto throughout the system's lifecycle.

In the particular context of the IoT, security must not only focus on the required security services, but also pay special attention to how these are realized in the overall system and how the security functionalities are executed. To this end, we consider five major "building blocks" to analyze and classify security aspects in the IoT:

1. The IoT security architecture: refers to the system elements involved in the management of the security relationships between things and the way these security interactions are handled (e.g., centralized or distributed) during the lifecycle of a thing. For instance, a smart home could rely on a centralized key distribution center in charge of managing cryptographic keys, devices & users, access control and privacy policies. 

2. The security model within a smart object: describes the way security parameters, keys, processes, and applications are managed within a smart object. This includes aspects such as application process separation, secure storage of key materials, protection of algorithms, etc. For instance, some smart objects might have extremely limited resources and have limited capabilities to protect secret keys; in contrast, other devices used in critical applications, e.g., a pacemaker, would rely on methods to securely protect cryptographic keys and functionality making sure that an attacker having physical access to the device cannot modify its operation.

3. Security bootstrapping: denotes the process by which a thing securely joins an IoT system at a given location and point in time. For instance, bootstrapping of a connected camera can include the authentication and authorization of a device as well as the transfer of security parameters allowing for its trusted operation in a given network.  

4. Network security: describes the mechanisms applied within a network to ensure trusted operation of the IoT. Specifically, it prevents attackers from endangering or modifying the expected operation of an smart object, it also protects the network itself from malicious things. For instance, network security can include a number of mechanisms ranging from data link layer security, secure routing, and network layer security.

5. Application security: describes mechanisms to allow transfer of application data at the transport or upper layers (object security). For instance, assuming an smart object such as an environmental sensor connected to a backend system, it can mean the exchange of secure blocks of data such as measurements by the sensor or a software update. This data is exchanged end-to-end independently of communication pattern, for e.g through proxies or other store-and-forward mechanisms.


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

We now discuss an exemplary security architecture relying on a configuration entity for the management of the system with regard to the introduced security aspects (see {{fig2}}). Inspired by the security framework for routing over low power and lossy network {{ID-Tsao}}, we show an example of the security model of a smart object and illustrates how different security concepts and the lifecycle phases map to the Internet communication stack. 

In our example, we consider a centralized architecture in which a configuration entity stores and manages the identities of the things associated with BAC system along with their cryptographic keys. During the bootstrapping phase, each thing executes the bootstrapping protocol with the configuration entity, thus obtaining the required device identities and some operational keying material. The security service on a thing in turn stores the received keying material for the network layer and application security mechanisms for secure communication. The criticality of the application requires an implementation of cryptographic algorithms that is resistant to side-channel attacks and the protection of the proprietary application-related algorithms executed in the device. Things can then securely communicate with each other during their operational phase by means of the employed network and application security mechanisms. Within the network, communication is protected by the network provider at MAC and network layer. At application layer, the communication between any smart object and the application server is protected end-to-end, ensuring the forward secrecy of the communication.

# Managing Threats and Risks {#sec4}

This section explores security threats and vulnerabilities in the IoT and discusses how to manage risks.

Security threats have been analyzed in related IP protocols including HTTPS {{RFC2818}}, COAP{{RFC7252}} 6LoWPAN {{RFC4919}}, ANCP {{RFC5713}}, DNS security threats {{RFC3833}}, IPv6 ND {{RFC3756}}, and PANA {{RFC4016}}. Nonetheless, the challenge is understanding and mitigating the impact of these security threats on the various IoT deployment scenarios. In this section, we specifically discuss the threats that could compromise an individual thing, or network as a whole. Note that these set of threats might go beyond the scope of Internet protocols but we gather them here for the sake of completeness. We also note that these threats can be classified according to either (i) the thing's lifecycle phases (when does the threat occur?) or (ii) the security building blocks (which functionality is affected by the threat?). All these threats are summarized in Table 2.

1. Cloning of things: During the manufacturing process of a thing, an untrusted factory can easily clone the physical characteristics, firmware/software, or security configuration of the thing. Deployed things might also be compromised and their software reserve engineered allowing for cloning or software modifications. Such a cloned thing may be sold at a cheaper price in the market, and yet be able to function normally, as a genuine thing. For example, two cloned devices can still be associated and work with each other. In the worst case scenario, a cloned device can be used to control a genuine device or perform an attack. One should note here, that an untrusted factory may also change functionality of the cloned thing, resulting in degraded functionality with respect to the genuine thing (thereby, inflicting potential damage to the reputation of the original thing manufacturer). Moreover, additional functionality can be implemented within the cloned thing, such as a backdoor.

2. Malicious substitution of things: During the installation of a thing, a genuine thing may be substituted with a similar variant of lower quality without being detected. The main motivation may be cost savings, where the installation of lower-quality things (e.g., non-certified products) may significantly reduce the installation and operational costs. The installers can subsequently resell the genuine things in order to gain further financial benefits. Another motivation may be to inflict damage to the reputation of a competitor's offerings.

3. Eavesdropping attack: During the commissioning of a thing into a network, it may be susceptible to eavesdropping, especially if operational keying materials, security parameters, or configuration settings, are exchanged in clear using a wireless medium or if used cryptographic algorithms are not suitable for the envisioned lifetime of the device and the system. After obtaining the keying material, the attacker might be able to recover the secret keys established between the communicating entities, thereby compromising the authenticity and confidentiality of the communication channel, as well as the authenticity of commands and other traffic exchanged over this communication channel. When the network is in operation, T2T communication may be eavesdropped upon if the communication channel is not sufficiently protected or in the event of session key compromise due to a long period of usage without key renewal or updates.

4. Man-in-the-middle attack: Both the commissioning phase and operational phases may also be vulnerable to man-in-the-middle attacks, e.g., when keying material between communicating entities are exchanged in the clear and the security of the key establishment protocol depends on the tacit assumption that no third party is able to eavesdrop during the execution of this protocol. Additionally, device authentication or device authorization may be non-trivial, or may need support of a human decision process, since things usually do not have a-priori knowledge about each other and cannot always be able to differentiate friends and foes via completely automated mechanisms. Thus, even if the key establishment protocol provides cryptographic device authentication, this knowledge on device identities may still need complementing with a human-assisted authorization step (thereby, presenting a weak link and offering the potential of man-in-the-middle attacks this way).

5. Firmware Replacement attack: When a thing is in operation or maintenance phase, its firmware or software may be updated to allow for new functionality or new features. An attacker may be able to exploit such a firmware upgrade by replacing the thing's software with malicious software, thereby influencing the operational behavior of the thing. For example, an attacker could add a piece of malicious code to the firmware that will cause it to periodically report the energy usage of the lamp to a data repository for analysis. Similarly, devices whose software has not been properly maintained and updated might contain vulnerabilities that might be exploited by attackers.

6. Extraction of private information: in the ambient environment the things (such as sensors, actuators, etc.) are usually physically unprotected and could easily be captured by an attacker. Such an attacker may then attempt to extract private information such as keys (e.g., device's key, private-key, group key), sensed data (e.g., healthcare status of a user), configuration parameters (e.g., the WiFi key), or proprietary algorithms (e.g., algorithm performing some data analytic task) from this thing. Compromise of a thing's unique key compromises communication channels of this particular thing and also compromise all data communicated over this channel.  

7. Routing attack: As highlighted in {{ID-Daniel}}, routing information in IoT can be spoofed, altered, or replayed, in order to create routing loops, attract/repel network traffic, extend/shorten source routes, etc. Other relevant routing attacks include 1) Sinkhole attack (or blackhole attack), where an attacker declares himself to have a high-quality route/path to the base station, thus allowing him to do manipulate all packets passing through it. 2) Selective forwarding, where an attacker may selectively forward packets or simply drop a packet. 3) Wormhole attack, where an attacker may record packets at one location in the network and tunnel them to another location, thereby influencing perceived network behavior and potentially distorting statistics, thus greatly impacting the functionality of routing. 4) Sybil attack, whereby an attacker presents multiple identities to other things in the network.

8. Privacy threat: The tracking of a thing's location and usage may pose a privacy risk to its users. For instance, an attacker can infer information based on the information gathered about individual things, thus deducing behavioral patterns of the user of interest to him. Such information can subsequently be sold to interested parties for marketing purposes and targeted advertising. In extreme cases, such information might be used to track dissidents in oppressive regimes. 

9. Denial-of-Service attack: Often things have very limited memory and computation capabilities. Therefore, they are vulnerable to resource exhaustion attack. Attackers can continuously send requests to be processed by specific things so as to deplete their resources. This is especially dangerous in the IoT since an attacker might be located in the backend and target resource-constrained devices that are part of a Low-power and Lossy Network (LLN) {{RFC7228}}. Additionally, DoS attack can also be launched by physically jamming the communication channel, thus breaking down the T2T communication channel. Network availability can also be disrupted by flooding the network with a large number of packets. On the other hand, things compromised by attackers can be used to disrupt the operation of other networks or systems by means of a Distributed DoS attack.

The following table summarizes the above generic security threats and the potential point of vulnerabilities at different layers of the communication stack. We also include related RFCs and ongoing standardization efforts that include a threat model that might apply to the IoT.


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

Dealing with above threats and finding suitable security mitigations is challenging: there are very sophisticated threats that a very powerful attacker could use; also, new threats and exploits appear in a daily basis. Therefore, the existence of proper secure product creation processes that allow managing and minimizing risks during the lifecycle of the IoT devices is at least as important as being aware of the threats. A non-exhaustive list of relevant processes include: 

1. A Business Impact Analysis (BIA) assesses the consequences of loss of basic security attributes, namely, confidentiality, integrity and availability in an IoT system. These consequences might include impact on data lost, sales lost, increased expenses, regulatory fines, customer dissatisfaction, etc. Performing a business impact analysis allow determining the business relevance of having a proper security design placing security in the focus.

2. A Risk Assessment (RA) analyzes security threats to the IoT system, considering their likelihood and impact, and deriving for each of them a risk level. Risks classified as moderate or high must be mitigated, i.e., security architecture should be able to deal with that threat bringing the risk to a low level. Note that threats are usually classified according to their goal: confidentiality, integrity, and availability. For instance, a specific threat to recover a symmetric-key used in the system relates to confidentiality.

3. A privacy impact assessment (PIA) aims at assessing Personal Identifiable Information (PII) that is collected, processed, or used in the IoT system. By doing so, the goals is to fulfill applicable legal requirements, determine risks and effects of the manipulation of PII, and evaluate proposed protections. 

4. Procedures for incident reporting and mitigation refer to the methodologies that allow becoming aware of any security issues that affect an IoT system. Furthermore, this includes steps towards the actual deployment of patches that mitigate the identified vulnerabilities.

BIA, RA, and PIA are usually to be realized during the creation of a new IoT system, introduction of new technologies in the IoT system, or deployment of significant system upgrades. In general, it is recommended to re-assess them on a regular basis taking into account new use cases or threats. 


# State of the Art {#sec5}

This section is organized as follows. {{sec5-1}} summarizes state of the art on IP-based systems, within IETF and in other standardization bodies. {{sec5-2}} summarizes state of the art on IP-based security protocols and their usage. {{sec5-3}} discusses guidelines for securing the IoT as proposed by other bodies. {{sec5-4}} analyzes status of other relevant standards, in particular, those by NIST regarding IoT and IoT security.

## IP-based IoT Protocols and Standards {#sec5-1}

Nowadays, there exists a multitude of control protocols for the IoT. For BAC systems, the ZigBee standard {{ZB}}, BACNet {{BACNET}}, or DALI {{DALI}} play key roles. Recent trends, however, focus on an all-IP approach for system control.

In this setting, a number of IETF working groups are designing new protocols for resource-constrained networks of smart things. The 6LoWPAN working group
{{WG-6LoWPAN}} for example has defined methods and protocols for the efficient transmission and adaptation of IPv6 packets over IEEE 802.15.4 networks {{RFC4944}}. 

The CoRE working group {{WG-CoRE}} among other things has specified the Constrained Application Protocol (CoAP) {{RFC7252}}. CoAP is a RESTful protocol for constrained devices that is modelled after HTTP and typically runs over UDP to enable efficient application-level communication for things. 

In many smart object networks, the smart objects are dispersed and have intermittent reachability either because of network outages or because they sleep during their operational phase to save energy. In such scenarios, direct discovery of resources hosted on the constrained server might not be possible. To overcome this barrier, the CoRE working group is specifying the concept of a Resource Directory (RD) {{ID-rd}}. The Resource Directory hosts descriptions of resources which are located on other nodes. These resource descriptions are specified as CoRE link format {{RFC6690}} URIs.

While CoAP defines a standard communication protocol, a format for representing sensor measurements and parameters over CoAP is required. The Sensor Measurement Lists (SenML) {{ID-senml}} is a specification that is currently being written to define media types for simple sensor measurements and parameters. It has a minimalistic design so that constrained devices with limited computational capabilities can easily encode their measurements and, at the same time, servers can efficiently collect large number of measurements.

In many IoT deployments, the resource-constrained smart objects are connected to the Internet via a gateway that is directly reachable. For example, an IEEE 802.11 Access Point (AP) typically connects the client devices to the Internet over just one wireless hop. However, some deployments of smart object networks require routing between the smart objects themselves. The IETF has therefore defined the IPv6 Routing Protocol for Low-Power and Lossy Networks (RPL) {{RFC6550}}. RPL provides support for multipoint-to-point traffic from resource-constrained smart objects towards a more resourceful central control point, as well as point-to-multipoint traffic in the reverse direction. It also supports point-to-point traffic between the resource-constrained devices. A set of routing metrics and constraints for path calculation in RPL are also specified {{RFC6551}}.


In addition to defining a routing protocol, the IETF has also specified how IPv6 packets can be transmitted over various link layer protocols that are commonly employed for resource-constrained smart object networks. There is also ongoing work to specify IPv6 connectivity for a Non-Broadcast Multi-Access (NBMA) mesh network that is formed by IEEE 802.15.4 TimeSlotted Channel Hopping (TSCH} links {{ID-6tisch}}. Other link layer protocols for which IETF has specified or is currently specifying IPv6 support include Bluetooth {{RFC7668}}, Digital Enhanced Cordless Telecommunications (DECT) Ultra Low Energy (ULE) air interface {{-6lodect}}, and Near Field Communication (NFC) {{ID-6lonfc}}.


JavaScript Object Notation (JSON) is a lightweight text representation format for structured data {{RFC7159}}. It is often used for transmitting serialized structured data over the network. IETF has defined specifications for encoding public keys, signed content, and claims to be transferred between two parties as JSON objects. They are referred to as JSON Web Keys (JWK) {{RFC7517}}, JSON Web Signatures (JWS) {{RFC7515}} and JSON Web Token (JWT) {{RFC7519}}.


An alternative to JSON, Concise Binary Object Representation (CBOR) {{RFC7049}} is a concise binary data format that is used for serialization of structured data. It is designed for extremely resource-constrained nodes and therefore it aims to provide a fairly small message size with minimal implementation code, and extensibility without the need for version negotiation. There is ongoing work to specify CBOR Object Signing and Encryption (COSE) {{ID-cose}}, which would provide services similar to JWS and JWT.

The Light-Weight Implementation Guidance (LWIG) working group {{WG-LWIG}} is collecting experiences from implementers of IP stacks in constrained devices. The working group has already produced documents such as RFC7815 {{RFC7815}} which defines how a minimal Internet Key Exchange Version 2 (IKEv2) initiator can be implemented.

The Thing-2-Thing Research Group (T2TRG) {{RG-T2TRG}} is investigating the remaining research issues that need to be addressed in order to quickly turn the vision of IoT into a reality where resource-constrained nodes can communicate with each other and with other more capable nodes on the Internet.

Additionally industry alliances and other standardization bodies are creating constrained IP protocol stacks based on the IETF work. Some important examples of this include: 

1. Thread {{Thread}}: Specifies the Thread protocol that is intended for a variety of IoT devices. It is an IPv6-based network protocol that runs over IEEE 802.15.4.

2. Industrial Internet Consortium {{IIoT}}: The consortium defines reference architectures and security frameworks for development, adoption and widespread use of Industrial Internet technologies based on existing IETF standards.

3. Internet Protocol for Smart Objects IPSO {{IPSO}}: The alliance specifies  a common object model that would enable application software any device to interoperate with other conforming devices.

4. OneM2M {{OneM2M}}: The standards body defines technical and API specifications for IoT devices. It aims to create a service layer that can run on any IoT device hardware and software.

5. Open Connectivity Foundation (OCF) {{OCF}}: The foundation develops standards and certifications primarily for IoT devices that use Constrained Application Protocol (CoAP) as the application layer protocol. 

6. Fairhair Alliance {{Fairhair}}: Specifies a middle-ware for IoT based Building Automation and Lighting System that can interoperate with different application standards for the professional domain.

7. OMA LWM2M {{LWM2M}}: OMA Lightweight M2M is a protocol from the Open Mobile Alliance for M2M or IoT device management. Lightweight M2M enabler defines the application layer communication protocol between a LWM2M Server and a LWM2M Client, which is located in a LWM2M Device.


## Existing IP-based Security Protocols and Solutions {#sec5-2}

In the context of the IP-based IoT solutions, consideration of TCP/IP security protocols is important. There are a wide range of specialized as well as general-purpose key exchange and security solutions  for the Internet domain such as IKEv2/IPsec {{RFC7296}}, TLS {{RFC5246}}, DTLS {{RFC6347}}, HIP {{RFC7401}}, PANA {{RFC5191}}, and EAP {{RFC3748}}. 

There is ongoing work to define an authorization and access-control framework for resource-constrained nodes. The Authentication and Authorization for Constrained Environments (ACE) {{WG-ACE}} working group is defining a solution to allow only authorized access to resources that are hosted on a smart object server and are identified by a URI. The current proposal {{ID-aceoauth}} is based on the OAuth 2.0 framework {{RFC6749}}. 

The CoAP base specification {{RFC7252}} provides a description of how DTLS can be used for securing CoAP. It proposes three different modes for using DTLS: the PreSharedKey mode, where nodes have pre-provisioned keys for initiating a DTLS session with another node, RawPublicKey mode, where nodes have asymmetric-key pairs but no certificates to verify the ownership, and Certificate mode, where public keys are certified by a certification authority. An IoT implementation profile {{RFC7925}} is defined for TLS version 1.2 and DTLS version 1.2 that offers communications security for resource-constrained nodes. 

There is also work on Object Security based CoAP protection mechanism being defined in OSCOAP {{ID-OSCOAP}}. 

Migault et al. {{ID-dietesp}} are working on a compressed version of IPsec so that it can easily be used by resource-constrained IoT devices. They rely on the Internet Key Exchange Protocol version 2 (IKEv2) for negotiating the compression format.


{{fig3}} depicts the relationships between the discussed protocols in the context of the security terminology introduced in {{sec3}}.


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

The Internet Key Exchange (IKEv2)/IPsec and the Host Identity protocol (HIP) reside at or above the network layer in the OSI model. Both protocols are able to perform an authenticated key exchange and set up the IPsec transforms for secure payload delivery. Currently, there are also ongoing efforts to create a HIP variant coined Diet HIP {{ID-HIP}} that takes lossy low-power networks into account at the authentication and key exchange level.

Transport Layer Security (TLS) and its datagram-oriented variant DTLS secure transport-layer connections. TLS provides security for TCP and requires a reliable transport, while DTLS secures and uses datagram-oriented protocols such as UDP. Both protocols are intentionally kept similar and share the same ideology and cipher suites.

The Extensible Authentication Protocol (EAP) is an authentication framework supporting multiple authentication methods. EAP runs directly over the data
link layer and, thus, does not require the deployment of IP. It supports duplicate detection and retransmission, but does not allow for packet fragmentation. The Protocol for Carrying Authentication for Network Access (PANA) is a network-layer transport for EAP that enables network access authentication between clients and the network infrastructure. In EAP terms, PANA is a UDP-based EAP lower layer that runs between the EAP peer and the EAP authenticator.

In addition, there is also new activities in IETF and W3C to define security protocols better tailored to IoT or for specific deployment situations. 

## IoT Security Guidelines {#sec5-3}

Recent large scale Denial of Service (DoS) Attacks on the Internet Infrastructure from compromised IoT devices has prompted many different standards bodies and consortia to provide guidelines for developers and the Internet community at large to build secure IoT devices and services. A subset of the different guidelines and ongoing projects are as follows:

1. GSMA IoT security guidelines {{GSMAsecurity}}: GSMA has published a set of security guidelines for the benefit of new IoT product and service providers. The guideline are aimed at device manufacturers, service providers, developers and network operators. An enterprise can complete an IoT Security Self-Assessment to demonstrate that its products and services are aligned with the security guidelines of the GSMA. 

2. BITAG Internet of Things (IoT) Security and Privacy Recommendations {{BITAG}}: Broadband Internet Technical Advisory Group (BITAG) has also published recommendations for ensuring security and privacy of IoT device users. BITAG observes that many IoT devices are shipped from the factory with software that is already outdated and vulnerable. The report also states that many devices with vulnerabilities will not be fixed either because the manufacturer does not provide updates or because the user does not apply them. The recommendations include that IoT devices should function without cloud and Internet connectivity, and that all IoT devices should have methods for automatic secure software updates.

3. CSA New Security Guidance for Early Adopters of the IoT {{CSA}}: The Cloud Security Alliance (CSA) recommendations for early adopters of IoT encourages enterprises to implement security at different layers of the protocol stack. It also recommends implementation of an authentication/authorization framework for IoT deployments. A complete list of recommendations is available in the report {{CSA}}. 

4. U.S. Department of Homeland Security {{DHS}}: DHS has put forth six strategic principles that would enable IoT developers, manufacturers, service providers and consumers to maintain security as they develop, manufacture, implement or use network-connected IoT devices.

5. NIST {{NIST-Guide}}: The NIST special publication urges enterprise and US federal agencies to address security throughout the systems engineering process. The publication builds upon the ISO/IEC/IEEE 15288 standard and augments each process in the system lifecyle with security enhancements. 

6. NIST {{nist_lightweight_project}}: NIST is running a project on lightweight cryptography with the purpose of: (i) identifying application areas for which standard cryptographic algorithms are too heavy, classifying them according to some application profiles to be determined; (ii) determining limitations in those existing cryptographic standards; and (iii) standardizing lightweight algorithms that can be used in specific application profiles. 

7. OWASP {{OWASP}}: Open Web Application Security Project (OWASP) provides security guidance for IoT manufactures, developers and consumers. OWASP also includes guidelines for those who intend to test and analyze IoT devices and applications. 

8. IoT Security foundation {{IoTSecFoundation}}: IoT security foundation has published a document that enlists various considerations that need to be taken into account when developing IoT applications. For example, the document states that IoT device could use hardware-root of trust to ensure that only authorized software runs on the device. 

9. NHTSA {{NHTSA}}: The US National Highway Traffic Safety Administration provides a set of non-binding guidance to the automotive industry for improving the cyber security of vehicles. While some of the guidelines are general, the document provides specific recommendations for the automotive industry such as how various automotive manufacturer can share cyber security vulnerabilities discovered. 

10. BCP for IoT devices {{ID-Moore}}: This Internet draft provides a list of minimum requirements that vendors of Internet of Things (IoT) devices should to take into account while developing applications, services and firmware updates in order to reduce the frequency and severity of security incidents that arise from compromised IoT devices. 

11. ENISA {{ENISA_ICS}}: The European Union Agency for Network and Information Security published a document on communication network dependencies for ICS/SCADA systems in which security vulnerabilities, guidelines and general recommendations are summarized.

Other guideline and recommendation documents may exist or may later be published. This list should be considered non-exhaustive. 


## Guidelines and IoT Security Regulations {#sec5-4}

Despite the acknowledgement that security in the Internet is needed and multiple guidelines exist, the fact is that many IoT devices and systems have very limited security. There are multiple reasons for this. For instance, some manufactures focus on delivering a product without paying enough attention to the delivered security level, lack of expertise or budget. This, however, poses a severe threat when such devices are deployed. The vast amount of devices and their inherent mobile nature also implies that an initially secure system can become insecure if a compromised device gains access to the system at some point in time. Even if all other devices in a given environment are secure, it does not prevent external (passive) attacks originating due to insecure devices. 

Recently {{FCC}} the FCC has stated the need for higher regulation for IoT systems. In fact this might be a missing component, at least in Federal Information Systems (FIS). Today, security in US FIS is regulated according to Federal Information Security Management Act (FISMA). From this law, NIST derived a number of documents to establish how to categorize FIS and determine minimum security requirements (FIPS-PUB-199 and FIPS-PUB-200). Minimum security requirements for FIS are specified in NIST SP 800-53r4 {{NIST-FIS}}. However, it is very likely that existing regulations do not take into account the specific challenges of IoT devices and networks.

Even if such a regulation is put in place, the question is how such a regulation can be applied in practice to non-federal deployments, such as industrial, homes, offices, or smart cites. Each of them exhibits unique features, involves very diverse types of users, has different operational requirements, and combines IoT devices from multiple manufacturers. 
Therefore future regulations should consider such diverse deployment scenarios.


# Challenges for a Secure IoT {#sec6}

In this section, we take a closer look at the various security challenges
in the operational and technical features of the IoT and then discuss how
existing Internet security protocols cope with these technical and conceptual
challenges through the lifecycle of a thing. Figure 2 summarizes which requirements need to be met in the lifecycle phases as well as some of the considered protocols. This discussion should neither be understood as a comprehensive evaluation of all protocols, nor can it cover all possible aspects of IoT security. Yet, it aims at showing concrete limitations of existing Internet security protocols in some areas rather than giving an abstract discussion about general properties of the protocols. In this regard, the discussion handles issues that are most important from the authors' perspectives.

## Constraints and Heterogeneous Communication {#sec6-1}

Coupling resource-constrained networks and the powerful Internet is a challenge because the resulting heterogeneity of both networks complicates protocol design and system operation. In the following we briefly discuss the resource constraints of IoT devices and the consequences for the use of Internet Protocols in the IoT domain.

### Resource Constraints {#sec6-1-1}

The IoT often relies on resource-constrained networks featured by lossy and low-bandwidth channels. IoT devices are also frequently small nodes, regarding CPU, memory, and energy budget. These characteristics directly impact the threats to and the design of security protocols for the IoT domain. First, the use of small packets, e.g., IEEE 802.15.4 supports 127-byte sized packets at the physical layer, may result in fragmentation of larger packets of security protocols. This may open new attack vectors for state exhaustion DoS attacks, which is especially tragic, e.g., if the fragmentation is caused by large key exchange messages of security protocols. Moreover, packet fragmentation commonly downgrades the overall system performance due to fragment losses and the need for retransmissions. For instance, fate-sharing packet flight as implemented by DTLS might aggravate the resulting performance loss.


The size and number of messages should be minimized to reduce memory requirements and optimize bandwidth usage. In this context, layered approaches involving a number of protocols might lead to worse performance in resource-constrained devices since they combine the headers of the different protocols. In some settings, protocol negotiation can increase the number of exchanged messages. To improve performance during basic procedures such as, e.g., bootstrapping, it might be a good strategy to perform those procedures at a lower layer.

Small CPUs and scarce memory limit the usage of resource-expensive crypto primitives such as public-key cryptography as used in most Internet security standards. This is especially true, if the basic crypto blocks need to be frequently used or the underlying application demands a low delay.

Independently from the development in the IoT domain, all discussed security protocols show efforts to reduce the cryptographic cost of the required public-key-based key exchanges and signatures with ECC {{RFC5246}}{{RFC5903}}{{RFC7401}}{{ID-HIP}}. Moreover, all protocols have been revised in the last years to enable crypto agility, making cryptographic primitives interchangeable. However, these improvements are only a first step in reducing the computation and communication overhead of Internet protocols. The question remains if other approaches can be applied to leverage key agreement in these heavily resource-constrained environments.

A further fundamental need refers to the limited energy budget available
to IoT nodes. Careful protocol (re)design and usage is required to reduce
not only the energy consumption during normal operation, but also under DoS
attacks. Since the energy consumption of IoT devices differs from other
device classes, judgements on the energy consumption of a particular protocol
cannot be made without tailor-made IoT implementations.

### Denial-of-Service Resistance {#sec6-1-2}

The tight memory and processing constraints of things naturally alleviate
resource exhaustion attacks. Especially in unattended T2T communication,
such attacks are difficult to notice before the service becomes unavailable
(e.g., because of battery or memory exhaustion). As a DoS countermeasure,
DTLS, IKEv2, HIP, and Diet HIP implement return routability checks based
on a cookie mechanism to delay the establishment of state at the responding
host until the address of the initiating host is verified. The effectiveness
of these defenses strongly depends on the routing topology of the network. Return routability checks are particularly effective if hosts cannot receive packets addressed to other hosts and if IP addresses present meaningful information as is the case in today's Internet. However, they are less effective in broadcast media or when attackers can influence the routing and addressing of hosts (e.g., if hosts contribute to the routing infrastructure in ad-hoc networks and meshes).

In addition, HIP implements a puzzle mechanism that can force the initiator
of a connection (and potential attacker) to solve cryptographic puzzles with
variable difficulties. Puzzle-based defense mechanisms are less dependent
on the network topology but perform poorly if CPU resources in the network
are heterogeneous (e.g., if a powerful Internet host attacks a thing). Increasing the puzzle difficulty under attack conditions can easily lead to situations, where a powerful attacker can still solve the puzzle while weak IoT clients cannot and are excluded from communicating with the victim. Still, puzzle-based approaches are a viable option for sheltering IoT devices against unintended overload caused by misconfiguration or malfunctioning things.

### End-to-End Security, protocol translation, and the role of middleboxes {#sec6-1-3}

The term end-to-end security often has multiple interpretations.
Here, we consider end-to-end security in the context end-to-end IP connectivity, from a sender to a receiver.
Note that this does not necessarily mean from sensor to actuator. 

Regarding end-to-end security in the context of confidentiality and integrity protection, the packets are processed by applying message authentication codes or encryption. These protection methods render the protected parts of the packets immutable as rewriting is either not possible because a) the relevant information is encrypted and inaccessible to the gateway or b) rewriting integrity-protected parts of the packet would invalidate the end-to-end integrity protection. 

IoT protocols, i.e., Internet protocols for constrained IoT networks, do not target protocol specifications that are identical to their Internet counterparts due to performance reasons. Hence, more or less subtle differences between constrained Internet protocols and Internet protocols will remain. While these differences can easily be bridged with protocol translators at middleboxes, they become major obstacles if end-to-end security measures between IoT devices and Internet hosts are used.

If access by the middleboxes is required, there are diverse approaches to handle such a connection.
Note that some of the approaches affect the meaning of end-to-end security in terms of integrity and confidentiality since the middleboxes will be able to either decrypt or modify partially the exchanged messages:

1. Sharing credentials with middleboxes enables middleboxes to transform (e.g., decompress, convert, etc.) packets and re-apply the security measures after transformation. This method abandons end-to-end security and is only applicable to simple scenarios with a rudimentary security model.

2. Reusing the Internet wire format in the IoT makes conversion between IoT and Internet protocols unnecessary. However, it can lead to poor performance in some use cases because IoT specific optimizations (e.g., stateful or stateless compression) are not possible.

3. Selectively protecting vital and immutable packet parts with a MAC or with encryption requires a careful balance between performance and security. Otherwise, this approach will either result in poor performance (protect as much as possible) or poor security (compress and transform as much as possible).

4. Homomorphic encryption techniques can be used in the middlebox to perform certain operations. However, this is limited to data processing involving arithmetic operations. Furthermore, performance of existing libraries, e.g., SEAL {{SEAL}} is still limited to be widely applicable.

5. Message authentication codes that sustain transformation can be realized by considering the order of transformation and protection (e.g., by creating a signature before compression so that the gateway can decompress the packet without recalculating the signature). {{ID-OSCOAP}} proposes a solution in this direction, also preventing proxies from changing relevant CoAP fields. Such an approach enables IoT specific optimizations but is more complex and may require application-specific transformations before security is applied. Moreover, the usage of encrypted data prevents gateways from transforming packets.

6. Object security based mechanisms can bridge the protocol worlds, but still require that the two worlds use the same object security formats. Currently the object security format based on COSE {{ID-cose}} (IoT protocol) is different from JOSE or CMS (traditional Internet protocol). Legacy devices relying on traditional Internet protocols will need to update to the newer protocols thought for constrained environments to enable real end-to-end security. Furthermore, middleboxes do not have any access to the data and this approach does not prevent an attacker from modifying relevant fields in CoAP.

To the best of our knowledge, none of the mentioned security approaches that focus on the confidentiality and integrity of the communication exchange between two IP end-points provides the perfect solution in this problem space. 

We finally note that end-to-end security can also be considered in the context of availability: making sure that the messages are delivered.
In this case, the end-points cannot control this, but the middleboxes play a fundamental role to make sure that exchanged messages are not dropped, e.g., due to a DDoS attack.

### New network architectures and paradigm {#sec6-1-4}

There is a multitude of new link layer protocols that aim to address the resource-constrained nature of IoT devices. For example, the IEEE 802.11 ah {{IEEE802ah}} has been specified for extended range and lower energy consumption to support Internet of Things (IoT) devices. Similarly, Low-Power Wide-Area Network (LPWAN) protocols such as LoRa {{lora}}, Sigfox {{sigfox}}, NarrowBand IoT (NB-IoT) {{nbiot}} are all designed for resource-constrained devices that require long range and low bit rates. While these protocols allow the IoT devices to conserve energy and operate efficiently, they also add additional security challenges. For example, the relatively small MTU can make security handshakes with large X509 certificates a significant overhead. At the same time, new communication paradigms also allow IoT devices to communicate directly amongst themselves with or without support from the network. This communication paradigm is also referred to as Device-to-Device (D2D) or Machine-to-Machine (M2M) or Thing-to-Thing (T2T) communication. D2D is primarily driven by network operators that want to utilize short range communication to improve the network performance and for supporting proximity based service

## Bootstrapping of a Security Domain {#sec6-2}

Creating a security domain from a set of previously unassociated IoT devices
is a key operation in the lifecycle of a thing and in the IoT network. This aspect is further elaborated and discussed in the T2TRG draft on bootstrapping {{ID-bootstrap}}.


## Operation {#sec6-3}

After the bootstrapping phase, the system enters the operational phase. 
During the operational phase, things can relate to the state information
created during the bootstrapping phase in order to exchange information securely and in an authenticated fashion. In this section, we discuss aspects of communication patterns and network dynamics during this phase.

### End-to-End Security {#sec6-3-1}

Providing end-to-end IP security is of great importance to address and secure individual T2T or H2T communication within one IoT domain. Moreover, end-to-end security associations are an important measure to bridge the gap between contrained and unconstrained environments. IKEv2, TLS and DTLS provide end-to-end security services including peer entity authentication, end-to-end encryption and integrity protection above the network layer and the transport layer respectively. Once bootstrapped, these functions can be carried out without online connections to third parties, making the protocols applicable for decentralized use in the IoT. However, protocol translation by intermediary nodes may invalidate end-to-end protection measures (see {{sec6-1-3}}). Also these protocols require end-to-end connectivity between the devices and do not support store-and-forward scenarios. Object security is an option for such scenarios and the work on OSCOAP {{ID-OSCOAP}} is a potential solution in this space, in particular, in the context of forwarding proxies.

### Group Membership and Security {#sec6-3-2}

In addition to end-to-end security, group key negotiation is an important
security service for the T2Ts and Ts2T communication patterns in the IoT
as efficient local broadcast and multicast relies on symmetric group keys.

All discussed protocols only cover unicast communication and therefore do not focus on group-key establishment.
This applies in particular to (D)TLS and IKEv2.
However, the Diffie-Hellman keys that
are used in IKEv2 and HIP could be used for group Diffie-Hellman key-negotiations. Conceptually, solutions that provide secure group communication at the network layer (IPsec/IKEv2, HIP/Diet HIP) may have an advantage regarding the cryptographic overhead compared to application-focused security solutions (TLS/ DTLS or OSCOAP). This is due to the fact that application-focused solutions require cryptographic operations per group application, whereas network layer approaches may allow to share secure group associations between multiple applications (e.g., for neighbor discovery and routing or service discovery). Hence, implementing shared features lower in the communication stack can avoid redundant security measures.

A number of group key solutions have been developed in the context of the
IETF working group MSEC in the context of the MIKEY architecture {{WG-MSEC}}{{RFC4738}}. These are specifically tailored for multicast and group broadcast applications in the Internet and should also be considered as candidate solutions for group key agreement in the IoT. The MIKEY architecture describes a coordinator entity that disseminates symmetric keys over pair-wise end-to-end secured channels. However, such a centralized approach may not be applicable in a distributed environment, where the choice of one or several coordinators and the management of the group key is not trivial.

### Mobility and IP Network Dynamics {#sec6-3-3}

It is expected that many things (e.g., wearable sensors, and user devices) will be mobile in the sense that they are attached to different networks
during the lifetime of a security association. Built-in mobility signaling can greatly reduce the overhead of the cryptographic protocols because unnecessary and costly re- establishments of the session (possibly including handshake and key agreement) can be avoided. IKEv2 supports host mobility with the MOBIKE {{RFC4555}}{{RFC4621}} extension. MOBIKE refrains from applying heavyweight cryptographic extensions for mobility. However, MOBIKE mandates the use of IPsec tunnel mode which requires to transmit an additional IP header in each packet. This additional overhead could be alleviated by using header compression methods or the Bound End- to-End Tunnel (BEET) mode {{ID-Nikander}}, a hybrid of tunnel and transport mode with smaller packet headers.

HIP offers a simple yet effective mobility management by allowing hosts to signal changes to their associations {{RFC8046}}. However, slight adjustments
might be necessary to reduce the cryptographic costs, for example, by making the public-key signatures in the mobility messages optional. Diet HIP does
not define mobility yet but it is sufficiently similar to HIP to employ the same mechanisms. TLS and DTLS do not have standards for mobility support, however, work on DTLS mobility exists in the form of an Internet draft {{ID-Williams}}. The specific need for IP-layer mobility mainly depends on the scenario in which nodes operate. In many cases, mobility support by means of a mobile gateway may suffice to enable mobile IoT networks, such as body sensor networks. However, if individual things change their point of network attachment while communicating, mobility support may gain importance.

## Software update {#sec6-4}

IoT devices have a reputation for being insecure, and yet, they are expected to stay functional in live deployments for years and even decades. Additionally, these devices typically operate unattended with direct Internet connectivity. Therefore, a remote software update mechanism to fix vulnerabilities, to update configuration settings, and for adding new functionality is needed. 

Schneier {{SchneierSecurity}} in his essay expresses concerns about the status of software and firmware update mechanisms for Internet of Things (IoT) devices. He highlights several challenges that hinder mechanisms for secure software update of IoT devices. First, there is a lack of incentives for manufactures, vendors and others on the supply chain to issue updates for their devices. Second, parts of the software running on the IoT devices is simply a binary blob without any source code available. Since the complete source code is not available, no patches can be written for that piece of code. Third, even when updates are available, users generally have to manually download and install those updates. However, users are never alerted about security updates and many times do not have the necessary expertise to manually administer the required updates.

The FTC staff report on Internet of Things - Privacy & Security in a Connected World {{FTCreport}} and the Article 29 Working Party Opinion 8/2014 on the on Recent Developments on the Internet of Things {{Article29}} also document the challenges for secure remote software update of IoT devices. They note that even providing such a software update capability may add new vulnerabilities for constrained devices. For example, a buffer overflow vulnerability in the implementation of a software update protocol (TR69) {{TR69}} and an expired certificate in a hub device {{wink}} demonstrate how the software update process itself can introduce vulnerabilities. 

While powerful IoT devices that run general purpose operating systems can make use of sophisticated software update mechanisms known from the desktop world, a more considerate effort is needed for resource-constrained devices that don't have any operating system and are typically not equipped with a memory management unit or similar tools. The IAB also organized a workshop to understand the challenges for secure software update of IoT devices. A summary of the workshop and the proposed next steps have been documented {{iotsu}}. 

## Verifying device behavior {#sec6-5}

Users often have a false sense of privacy when using new Internet of Things (IoT) appliances such as Internet-connected smart televisions, speakers and cameras. Recent revelations have shown that this user belief is often unfounded. Many IoT device vendors have been caught collecting sensitive private data through these connected appliances with or without appropriate user warnings {{cctv}}.

An IoT device user/owner would like to monitor and verify its operational behavior. For instance, the user might want to know if the device is connecting to the server of the manufacturer for any reason. This feature -- connected to the manufacturer's server -- may be necessary in some scenarios, such as during the initial configuration of the device. However, the user should be kept aware of the data that the device is sending back to the vendor. For example, the user should be ensured that his/her TV is not sending data when he/she inserts a new USB stick. 

Providing such information to the users in an understandable fashion is challenging. This is because the IoT devices are not only resource-constrained in terms of their computational capability, but also in terms of the user interface available. Also, the network infrastructure where these devices are deployed will vary significantly from one user environment to another. Therefore, where and how this monitoring feature is implemented still remains an open question. 

## End-of-life {#sec6-6}
Like all commercial devices, most IoT devices will be end-of-lifed by vendors or even network operators. This may be planned or unplanned (for example when the vendor or manufacturer goes bankrupt or when a network operator moves to a different type of networking technology). A user should still be able to use and perhaps even update the device. This requires for some form of authorization handover.

Although this may seem far fetched given the commercial interests and market dynamics, we have examples from the mobile world where the devices have been functional and up-to-date long after the original vendor stopped supporting the device. CyanogenMod for Android devices and OpenWrt for home routers are two such instances where users have been able to use and update their devices even after they were end-of-lifed. Admittedly these are not easy for an average users to install and configure on their devices. With the deployment of millions of IoT devices, simpler mechanisms are needed to allow users to add new root-of-trusts and install software and firmware from other sources once the device has been end-of-lifed.


## Testing: bug hunting and vulnerabilities {#sec6-7}
Given that the IoT devices often have inadvertent vulnerabilities, both users and developers would want to perform extensive testing on their IoT devices, networks, and systems. Nonetheless, since the devices are resource-constrained and manufactured by multiple vendors, some of them very small, devices might be shipped with very limited testing, so that bugs can remain and can be exploited at a later stage. This leads to two main types of challenges:

1. It remains to be seen how the software testing and quality assurance mechanisms used from the desktop and mobile world will be applied to IoT devices to give end users the confidence that the purchased devices are robust.
2. It is also an open question how combination of devices of multiple vendors might actually lead to dangerous network configurations, e.g., if combination of specific devices can trigger unexpected behavior.

## Quantum-resistance {#sec6-8}

Many IoT systems that are being deployed today will remain operational for many years. With the advancements made in the field of quantum computers, it is possible that large-scale quantum computers are available in the future for performing cryptanalysis on existing cryptographic algorithms and cipher suites. If this happens, it will have two consequences. First, functionalities enabled by means of RSA/ECC - namely key exchange, public-key encryption and signature - would not be secure anymore due to Shor's algorithm. Second, the security level of symmetric algorithms will decrease, e.g., the security of a block cipher with a key size of b bits will only offer b/2 bits of security due to Grover's algorithm.

The above scenario becomes more urgent when we consider the so called "harvest and decrypt" attack in which an attacker can start to harvest (store) encrypted data today, before a quantum-computer is available, and decrypt it years later, once a quantum computer is available.

This situation would require us to move to quantum-resistant alternatives, in particular, for those functionalities involving key exchange, public-key encryption and signatures. While such future planning is hard, it may be a necessity in certain critical IoT deployments which are expected to last decades or more. Although increasing the key-size of the different algorithms is definitely an
option, it would also incur additional computational overhead and network traffic. This would be undesirable in most scenarios. There have been recent advancements in quantum-resistant cryptography.

We refer to {{ETSI_GR_QSC_001}} for an extensive overview of existing quantum-resistant cryptography. {{RFC7696}} provides guidelines for cryptographic algorithm agility.

## Privacy protection {#sec6-9}

Users will be surrounded by hundreds of connected devices. Even if the communication links are encrypted and protected, information about the users might be collected for different purposes affecting their privacy. In {{Ziegeldorf}}, privacy in the IoT is defined as the threefold guarantee to the user for:
1. awareness of privacy risks imposed by smart things and services surrounding the data subject,
2. individual control over the collection and processing of personal information by the surrounding smart things,
3. awareness and control of subsequent use and dissemination of personal information by those entities to any entity outside the subject's personal control sphere.

Based on this definition, several privacy threats and challenges have been documented {{Ziegeldorf}} and {{RFC6973}}:

1. Identification - refers to the identification of the users and their objects.
2. Localization - relates to the capability of locating a user and even tracking him.
3. Profiling - is about creating a profile of the user and her preferences.
4. Interaction - occurs when a user has been profiled and a given interaction is preferred, presenting (e.g., visually) some information that discloses private information. 
5. Lifecycle transitions - take place when devices are, e.g., sold without properly removing private data.
6. Inventory attacks - happen if specific information about (smart) objects in possession of a user is disclosed.
7. Linkage - is about when information of two of more IoT systems is combined so that a broader view on the personal data is created.

When IoT systems are deployed, the above issues should be considered to ensure that private data remains private. How to achieve this in practice is still an area of ongoing research.

## Data leakage {#sec6-10}

IoT devices are resource-constrained and often deployed in unattended environments. Some of these devices can also be purchased off-the-shelf or online without any credential-provisioning process. Therefore, an attacker can have direct access to the device and apply more advance techniques that a traditional black box model does not consider such as side-channel attacks or code disassembly. By doing this, the attacker can try to retrieve data such as:

1. long term keys that might be used perform attacks on devices deployed in other locations. 
2. source code that might let the user determine bugs or find exploits to perform other types of attacks, or just sell it,
3. proprietary algorithms that could be counterfeited or modified to perform advanced attacks.

Protection against such data leakage patterns is not trivial since devices are inherently resource-constrained. An open question is which techniques can be used to protect IoT devices in such an adversarial model.

## Trustworthy IoT Operation {#sec6-11}

Flaws in the design and implementation of a secure IoT device and network can lead to secure vulnerabilities. An example is a flaw is the distribution of an Internet-connected IoT device in which a default password is used in all devices. Many IoT devices can be found in the Internet by means of tools such as Shodan, and if they have any vulnerability, it can then be exploited at scale, e.g., to launch DDoS attacks. This is not fiction but reality as Dyn, a mayor DNS was attacked by means of a DDoS attack originated from a large IoT botnet composed of thousands of compromised IP-cameras. Open questions in this area are:

1. How to prevent large scale vulnerabilities in IoT devices?
2. How to prevent attackers from exploiting vulnerabilities in IoT devices at large scale?
3. If the vulnerability has been exploited, how do we stop a large scale attack before any damage is caused?

Some ideas are being explored to address this issue. One of this approaches refers to the specification of Manufacturer Usage Description (MUD) files {{ID-MUD}}. 
The idea behind MUD files is simple: devices would disclose the location of its MUD file to the network during installation.
The network can then (i) retrieve those files, (ii) learn from the manufacturers the intended usage of the devices, e.g., which services they require to access, and then (iii) create suitable filters such as firewall rules. 

# Conclusions and Next Steps {#sec7}

This Internet Draft provides IoT security researchers, system designers and implements with an overview of both operational and security requirements in the IP-based Internet of Things. We discuss a general threat model, security issues, and state of the art to mitigate security threats. We further analyze key security challenges.

Although plenty of steps have been realized during the last few years ( summarized in {{sec5-1}}) and many organizations are publishing general recommendations ({{sec5-3}}) describing how the IoT should be secured, there are many challenges ahead that require further attention. Challenges of particular importance are bootstrapping of security, group security, secure software updates, long-term security and quantum-resistance, privacy protection, data leakage prevention -- where data could be cryptographic keys, personal data, or even algorithms -- and ensuring trustworthy IoT operation. All these problems are important; however, different deployment environments have different operational and security demands. Thus, a potential approach is the definition and standardization of security profiles, each with specific mitigation strategies according to the risk assessment associated with the security profile. Such an approach would ensure minimum security capabilities in different environments while ensuring interoperability.


# Security Considerations {#sec8}

This document reflects upon the requirements and challenges of the security
architectural framework for the Internet of Things.

# IANA Considerations {#sec9}

This document contains no request to IANA.

# Acknowledgments {#sec10}

We gratefully acknowledge feedback and fruitful discussion with Tobias Heer, Robert Moskowitz, Thorsten Dahm, Hannes Tschofenig, Barry Raveendran and Eliot Lear. We acknowledge the additional authors of the previous version of this document Sye Loong Keoh, Rene Hummen and Rene Struik. 

