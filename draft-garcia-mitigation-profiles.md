---
abbrev: IoT Security
title: IoT Security - Threats, Security mitigations and Profiles
docname: draft-garcia-security-mitigations-and-profiles
cat: info
stand_alone: true
informative:
  ID-dietesp:
    title: "Diet-ESP: a flexible and compressed format for IPsec/ESP"
    author:
    - ins: D. Migault
    - ins: T. Guggemos
    - ins: C. Bormann
    date: 2016-08
    seriesinfo:
       draft-mglt-6lo-diet-esp-02
  ID-senml:
    title: "Media Types for Sensor Measurement Lists (SenML)"
    author:
    - ins: C. Jennings
    - ins: Z. Shelby
    - ins: J. Arkko
    - ins: A. Keranen
    - ins: C. Bormann
    date: 2016-10
    seriesinfo:
      draft-ietf-core-resource-directory-09
  ID-rd:
    title: "CoRE Resource Directory"
    author:
    - ins: Z. Shelby
    - ins: M. Koster
    - ins: C. Bormann
    - ins: P. Stok
    date: 2016-10
    seriesinfo:
      draft-ietf-core-resource-directory-09
  ID-cose:
    title: "CBOR Object Signing and Encryption (COSE)"
    author:
    - ins: J. Schaad
    date: 2016-11
    seriesinfo:
      draft-ietf-cose-msg-24
  ID-6lodect:
    title: "Transmission of IPv6 Packets over DECT Ultra Low Energy"
    author:
    - ins: P. Mariager
    - ins: J. Petersen
    - ins: Z. Shelby
    - ins: M. Logt
    - ins: D. Barthel
    date: 2016-12
    seriesinfo:
      draft-ietf-6lo-dect-ule-09
  ID-6lonfc:
    title: "Transmission of IPv6 Packets over Near Field Communication"
    author:
    - ins: Y. Choi
    - ins: Y. Hong
    - ins: J. Youn
    - ins: D. Kim
    - ins: J. Choi
    date: 2016-10
    seriesinfo:
      draft-ietf-6lo-nfc-05  
  ID-6tisch:
    title: "An Architecture for IPv6 over the TSCH mode of IEEE 802.15.4"
    author:
    - ins: P. Thubert
    date: 2017-01
    seriesinfo:
      draft-ietf-6tisch-architecture-11  
  ID-aceoauth:
    title: Authentication and Authorization for Constrained Environments (ACE)
    author:
    - ins: L. Seitz
    - ins: G. Selander
    - ins: E. Wahlstroem
    - ins: S. Erdtman
    - ins: H. Tschofenig
    date: 2011-03
    seriesinfo:
      draft-ietf-ace-oauth-authz-05
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
      draft-daniel-6lowpan-security-analysis-05
  ID-HIP:
    title: HIP Diet EXchange (DEX)
    author:
    - ins: R. Moskowitz
    date: 2012-05
    seriesinfo:
      draft-moskowitz-hip-rg-dex-06
  ID-Hartke:
    title: Datagram Transport Layer Security in Constrained Environments
    author:
    - ins: K. Hartke
    - ins: O. Bergmann
    date: 2012-07
    seriesinfo:
      draft-hartke-core-codtls-02
  RFC7401:
  ID-Nikander:
    title: A Bound End-to-End Tunnel(BEET) mode for ESP
    author:
    - ins: P. Nikander
    - ins: J. Melen
    date: 2008-08
    seriesinfo:
      draft-nikander-esp-beet-mode-09
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
      draft-oflynn-core-bootstrapping-03
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
      draft-ietf-roll-security-framework-07
  ID-Moore:
    title: Best Current Practices for Securing Internet of Things (IoT) Devices
    author:
    - ins: K. Moore
    - ins: R. Barnes
    - ins: H. Tschofenig
    date: 2016-10
    seriesinfo:
      draft-moore-iot-security-bcp-00
  ID-MUD:
    title: Manufacturer Usage Description Specification
    author:
    - ins: E. Lear
    - ins: R. Droms
    - ins: D. Domascanu
    date: 2017-03
    seriesinfo:
  ID-Williams:
    title: Mobile DTLS
    author:
    - ins: M. Williams
    - ins: J. Barrett
    date: 2009-03
    seriesinfo:
      draft-barrett-mobile-dtls-00
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
      draft-castellani-core-http-mapping-07
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
  RFC2119:
  RFC2818: 
  RFC3261: 
  RFC3748: 
  RFC3756: 
  RFC3833: 
  RFC4016:  
  RFC4251: 
  RFC4555: 
  RFC4621: 
  RFC4738: 
  RFC4919: 
  RFC4944: 
  RFC5191: 
  RFC5206: 
  RFC5246:
  RFC5713: 
  RFC5903: 
  RFC6345: 
  RFC6347:
  RFC6550:
  RFC6551:
  RFC6568:
  RFC6690: 
  RFC6749:
  RFC7049:
  RFC7158:
  RFC7252:
  RFC7296:
  RFC7390:
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

The Internet of Things (IoT) concept refers to the usage of standard Internet protocols to allow for human-to-thing and thing-to-thing communication. 
The security needs are well-recognized and and many standardization steps for providing security have been taken, for example, the specification of Constrained Application Protocol (CoAP) over Datagram Transport Layer Security (DTLS). 
However, the design space of IoT applications and systems is complex and exposed to multiple types of threats.

This document summarizes key security threats and suitable mitigation strategies to protect against these threats. 
We introduce the concept of security profiles, sets of security mitigations applicable to IoT applications and systems exposed to similar security threats.


--- middle

# Conventions and Terminology Used in this Document {#sec1}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to
be interpreted as described in "Key words for use in RFCs to Indicate Requirement
Levels" {{RFC2119}}.

# Introduction {#sec2}

The Internet of Things (IoT) denotes the interconnection of highly heterogeneous networked entities and networks following a number of communication patterns such as: human-to-human (H2H), human-to-thing (H2T), thing-to-thing (T2T), or thing-to-things (T2Ts). The term IoT was first coined by the Auto-ID center {{AUTO-ID}} in 1999. Since then, the development of the underlying concepts has ever increased its pace. Nowadays, the IoT presents a strong focus of research with various initiatives working on the (re)design, application, and usage of standard Internet technology in the IoT.

The IoT is exposed to a high number of attack vectors, that if sucessfully exploited by an attacker can have severe consequences.
This document summarizes threats and existing mitigation strategies to overcome those threats.
Which mitigation strategies are most suitable to and required in an IoT system depends on several factors, including, the operational features of the IoT system or the threats that are applicable to that system.
Thus, this document further discusses processes that can facilitate the proper design and operation of secure IoT systems.
Finally, this document proposes diffent security profiles, i.e., sets of mitigation strategies, that address typical threats in different IoT environments.

The rest of the Internet-Draft is organized as follows. 
Section {{sec3}} summarizes the design space of secure IoT systems, including lifecycle, device capabilities, and operational features.
This section further gives general definitions for the main security building blocks within the IoT domain. 
Section {{sec4}} discusses threats that should be considered when designing and operating an IoT system. 
In {{sec5}}, mitigation strategies to the identified threats are listed.
Choosing which mitigation strategies apply to which use cases is not trivial since it is required to find a proper balance between security, cost and usuability. 
Thus, the following section details methodologies for managing risks when designing a secure IoT system and dealing with vulnerabilities when operating the system. 
Finally, {{sec7}} proposes a number of illustrative security profiles applicable to different illustrative clases of IoT systems. 
Each security profile comprises a set of mitigation strategies and security processes that can provide a suitable security level while matching the cost and usuability goals of the corresponding class of IoT systems.
{{sec8}} includes final remarks and conclusions.

# The design space of secure IoT systems {#sec3}

ToDo: write intro for this section whose goal is to describe 'general' aspects to consider when designing/operating/maintaining an IoT system.

## The Thing Lifecycle {#sec3-1}

ToDo: describe IoT lifecycle and how that impacts security design.

The text below is old and belongs to the old draft. Part of the text could be reused.

------------


The lifecycle of a thing refers to the operational phases of a thing in the context of a given application or use case. {{fig1}} shows the generic phases of the lifecycle of a thing. This generic lifecycle is applicable to very different IoT applications and scenarios.

We consider an example, a Building Automation and Control (BAC) system, to illustrate the lifecycle and the meaning of these different phases. 
A BAC system consists of a network of interconnected nodes that performs various functions in the domains of HVAC (Heating, Ventilating, and Air Conditioning), lighting, safety etc. The nodes vary in functionality and a majority of them represent resource constrained devices such as sensors and luminaries. Some devices may also be battery operated or battery-less nodes, demanding for a focus on low energy consumption and on sleeping devices.
In our example, the life of a thing starts when it is manufactured. Due to the different application areas (i.e., HVAC, lighting, safety) nodes are tailored to a specific task. It is therefore unlikely that one single manufacturer will create all nodes in a building. Hence, interoperability as well as trust bootstrapping between nodes of different vendors is important. The thing is later installed and commissioned within a network by an installer during the bootstrapping phase. Specifically, the device identity and the secret keys used during normal operation are provided to the device during this phase. Different subcontractors may install different IoT devices for different purposes. Furthermore, the installation and bootstrapping procedures may not be a defined event but may stretch over an extended period of time. After being bootstrapped, the device and the system of things are in operational mode and execute the functions of the BAC system. During this operational phase, the device is under the control of the system owner. For devices with lifetimes spanning several years, occasional maintenance cycles may be required. During each maintenance phase, the software on the device can be upgraded or applications running on the device can be reconfigured. The maintenance tasks can thereby be performed either locally or from a backend system by means of an end-to-end connection. Depending on the operational changes of the device, it may be required to re-bootstrap at the end of a maintenance cycle. The device continues to loop through the operational phase and the eventual maintenance phase until the device is decommissioned at the end of its lifecycle. However, the end-of-life of a device does not necessarily mean that it is defective but rather denotes a need to replace and upgrade the network to next-generation devices in order to provide additional  functionality. Therefore the device can be removed and re-commissioned to be used in a different system under a different owner by starting the lifecycle all over again. 

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

## Classes of IoT device {#sec3-2}

ToDo: describe classes of IoT devices and how that impacts security design.

## Classes of IoT systems {#sec3-3}

ToDo: describe classes of IoT systems and how that impacts security design.


# Security Threats {#sec4}

ToDo: This section should summarize threats. The list below is from the old draft and it is not complete or very detailed. This shold be improved.

-------------------------

This section explores security threats and vulnerabilities in the IoT and discusses how to manage risks.

Security threats have been analyzed in related IP protocols including HTTPS {{RFC2818}}, COAP{{RFC7252}} 6LoWPAN {{RFC4919}}, ANCP {{RFC5713}}, DNS security threats {{RFC3833}}, SIP {{RFC3261}}, IPv6 ND {{RFC3756}}, and PANA {{RFC4016}}. Nonetheless, the challenge is about their impacts on scenarios of the IoTs. In this section, we specifically discuss the threats that could compromise an individual thing, or network as a whole. Note that these set of threats might go beyond the scope of Internet protocols but we gather them here for the sake of completeness. We also note that these threats can be classified according to either (i) the thing's lifecycle phases (when does the threat occur?) or (ii) the security building blocks (which functionality is affected by the threat?). All these threats are summarized in Table 2.

1. Cloning of things: During the manufacturing process of a thing, an untrusted factory can easily clone the physical characteristics, firmware/software, or security configuration of the thing. Deployed things might also be compromised and their software reserve engineered allowing for cloning or software modifications. Such a cloned thing may be sold at a cheaper price in the market, and yet be able to function normally, as a genuine thing. For example, two cloned devices can still be associated and work with each other. In the worst case scenario, a cloned device can be used to control a genuine device or perform an attack. One should note here, that an untrusted factory may also change functionality of the cloned thing, resulting in degraded functionality with respect to the genuine thing (thereby, inflicting potential damage to the reputation of the original thing manufacturer). Moreover, additional functionality can be implemented within the cloned thing, such as a backdoor.

2. Malicious substitution of things: During the installation of a thing, a genuine thing may be substituted with a similar variant of lower quality without being detected. The main motivation may be cost savings, where the installation of lower-quality things (e.g., non-certified products) may significantly reduce the installation and operational costs. The installers can subsequently resell the genuine things in order to gain further financial benefits. Another motivation may be to inflict damage to the reputation of a competitor's offerings.

3. Eavesdropping attack: During the commissioning of a thing into a network, it may be susceptible to eavesdropping, especially if operational keying materials, security parameters, or configuration settings, are exchanged in clear using a wireless medium or if used cryptographic algorithms are not suitable for the envisioned lifetime of the device and the system. After obtaining the keying material, the attacker might be able to recover the secret keys established between the communicating entities (e.g., H2T, T2Ts, or Thing to the backend management system), thereby compromising the authenticity and confidentiality of the communication channel, as well as the authenticity of commands and other traffic exchanged over this communication channel. When the network is in operation, T2T communication may be eavesdropped upon if the communication channel is not sufficiently protected or in the event of session key compromise due to a long period of usage without key renewal or updates.

4. Man-in-the-middle attack: Both the commissioning phase and operational phases may also be vulnerable to man-in-the-middle attacks, e.g., when keying material between communicating entities are exchanged in the clear and the security of the key establishment protocol depends on the tacit assumption that no third party is able to eavesdrop during the execution of this protocol. Additionally, device authentication or device authorization may be non-trivial, or may need support of a human decision process, since things usually do not have a-priori knowledge about each other and cannot always be able to differentiate friends and foes via completely automated mechanisms. Thus, even if the key establishment protocol provides cryptographic device authentication, this knowledge on device identities may still need complementing with a human-assisted authorization step (thereby, presenting a weak link and offering the potential of man-in-the-middle attacks this way).

5. Firmware Replacement attack: When a thing is in operation or maintenance phase, its firmware or software may be updated to allow for new functionality or new features. An attacker may be able to exploit such a firmware upgrade by replacing the thing's software with malicious software, thereby influencing the operational behavior of the thing. For example, an attacker could add a piece of malicious code to the firmware that will cause it to periodically report the energy usage of the lamp to a data repository for analysis. Similarly, devices whose software has not been properly maintained and updated might contain vulnerabilities that might be exploited by attackers.

6. Extraction of private information: in the ambient environment the things (such as sensors, actuators, etc.) are usually physically unprotected and could easily be captured by an attacker. Such an attacker may then attempt to extract private information such as keys (e.g., device's key, private-key, group key), sensed data (e.g., healthcare status of a user), configuration parameters (e.g., the WiFi key), or proprietary algorithms (e.g., algorithm performing some data analytic task) from this thing. Compromise of a thing's unique key compromises communication channels of this particular thing and also compromise all data communicated over this channel.  

7. Routing attack: As highlighted in {{ID-Daniel}}, routing information in IoT can be spoofed, altered, or replayed, in order to create routing loops, attract/repel network traffic, extend/shorten source routes, etc. Other relevant routing attacks include 1) Sinkhole attack (or blackhole attack), where an attacker declares himself to have a high-quality route/path to the base station, thus allowing him to do manipulate all packets passing through it. 2) Selective forwarding, where an attacker may selectively forward packets or simply drop a packet. 3) Wormhole attack, where an attacker may record packets at one location in the network and tunnel them to another location, thereby influencing perceived network behavior and potentially distorting statistics, thus greatly impacting the functionality of routing. 4) Sybil attack, whereby an attacker presents multiple identities to other things in the network.

8. Privacy threat: The tracking of a thing's location and usage may pose a privacy risk to its users. An attacker can infer information based on the information gathered about individual things, thus deducing behavioral patterns of the user of interest to him. Such information can subsequently be sold to interested parties for marketing purposes and targeted advertising.

9. Denial-of-Service attack: Typically, things have tight memory and limited computation, they are thus vulnerable to resource exhaustion attack. Attackers can continuously send requests to be processed by specific things so as to deplete their resources. This is especially dangerous in the IoTs since an attacker might be located in the backend and target resource-constrained devices in an Low-Latency Network (LLN). Additionally, DoS attack can be launched by physically jamming the communication channel, thus breaking down the T2T communication channel. Network availability can also be disrupted by flooding the network with a large number of packets. On the other hand, things compromised by attackers can be used to disrupt the operation of other networks or systems by means of a Distributed DoS attack.

The following table summarizes the above generic security threats and the potential point of vulnerabilities at different layers of the communication stack. We also include related RFCs and ongoing standardization efforts that include a threat model that might apply to the IoTs.


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

# Security Mitigations {#sec5}

ToDo: this section should contain mitigation strategies to deal with threats.

------------


# Designing and operating secure IoT systems {#sec6}

[ToDo: This section should describe how an IoT system should be designed/operated. The text below is from the old draft and it should be further improved.]


Dealing with above threats and finding suitable security mitigations is challenging: there are very sophisticated threats that a very powerful attacker could use; also, new threats and exploits appear in a daily basis. Therefore, the existence of proper secure product creation processes that allow managing and minimizing risks during the lifecycle of the IoT devices is at least as important as being aware of the threats. A non-exhaustive list of relevant processes include: 

1. A Business Impact Analysis (BIA) assesses the consequences of loss of basic security attributes, namely, confidentiality, integrity and availability in an IoT system. These consequences might include impact on data lost, sales lost, increased expenses, regulatory fines, customer dissatisfaction, etc. Performing a business impact analysis allow determining the business relevance of having a proper security design placing security in the focus.

2. A Risk Assessment (RA) analyzes security threats to the IoT system, considering their likelihood and impact, and deriving for each of them a risk level. Risks classified as moderate or high must be mitigated, i.e., security architecture should be able to deal with that threat bringing the risk to a low level. Note that threats are usually classified according to their goal: confidentiality, integrity, and availability. For instance, a specific threat to recover a symmetric-key used in the system relates to confidentiality.

3. A privacy impact assessment (PIA) aims at assessing Personal Identifiable Information (PII) that is collected, processed, or used in the IoT system. By doing so, the goals is to fulfill applicable legal requirements, determine risks and effects of the manipulation of PII, and evaluate proposed protections. 

4. Procedures for incident reporting and mitigation refer to the methodologies that allow becoming aware of any security issues that affect an IoT system. Furthermore, this includes steps towards the actual deployment of patches that mitigate the identified vulnerabilities.

BIA, RA, and PIA are usually to be realized during the creation of a new IoT system, introduction of new technologies in the IoT system, or deployment of significant system upgrades. In general, it is recommended to re-assess them on a regular basis taking into account new use cases or threats. 


# Security Profiles {#sec7}


ToDo: this section should contain the security profiles. My thinking is to (i) define some classes of IoT systems that are illustrative of real-world scenarios describing the features of those (lifecycle, device capabilities, IoT system). Then, (ii) describe the types of threats that would be typically applicable to them. And finally, (iii) describe mitigation strategies that should be used to deal with those threats while taking into account the features of the IoT system. 

NOTE THAT THE 4 PROFILES ARE MERE PLACEHOLDERS.

The text below is old and belongs to the old draft. Part of the text could be reused.

------------

There is a wide range of IoT applications including building automation systems, healthcare, smart cities, logistics, etc. For each of these applications, properties such as device capability, network infrastructure, or available security services can be completely different. Furthermore, each of those applications is featured by a different number of actors deployed in very different environments and with very different purposes.

Consequently, when a Business Impact Analysis or Risk Assessment is performed, not only the types of threats will be different, but also their likelihood and potential impact. 
This determines that different applications tend to require different or complementary types of security mechanisms mitigating the identified risks.

For example, IoT applications may have different needs regarding authentication and confidentiality. While some application might not require any confidentiality at all, others might require strong end-to-end confidentiality. In terms of secure bootstrapping of keys, some applications might assume the existence and online availability of a central key-distribution-center (KDC) within the network to distribute and manage keys; while other applications cannot rely on such a central party or on their availability.

This section describes some exemplary security profiles fitting the security needs of applications with the same characteristics and requirements. 
This approach is similar to that in the security profiles in {{nist_lightweight_project}}.
Such security profiles can help to (i) guide the design process of different application types by identifying open gaps; (ii) allow for later interoperability; and (iii) prevent possible security misconfiguration. 
Each security profile is identified by:

1. a short description,

2. an exemplary application that might use/require such a security profile,

3. the security requirements for each of the above security aspects according to our classification.

These security profiles can serve to guide the standardization process, since these explicitly describe the basic functionalities and protocols required to get different use cases up and running. They can allow for later interoperability since different manufacturers can describe the implemented security profile in their products. Finally, the security profiles can avoid possible security misconfiguration, since each security profile can be bound to a different application domain so that security protocols are clearly defined and under which circumstances they are applied.

We compare the security capabilities in each of the security profiles according to security building blocks, namely:

1. Security architecture,

2. Security model,

3. Security bootstrapping,

4. Network security, and

5. Application security.

IMPORTANT: Note that each of these exemplary profiles aims at summarizing the required security requirements for different exemplary application areas and at providing a set of initial security features. In other words, these profiles reflect the need for different security configurations, depending on the threat and trust models of the underlying applications. In this sense, this section does not provide an overview of existing protocols as done in previous sections, but it rather explicitly describes what should be in place to ensure secure system operation. Observe also that this list of security profiles is not exhaustive and that it should be considered just as an example not related to existing legal regulations for any existing application. 

The remainder of this section is organized as follows. The following section first describes four generic security profiles and discuss how different applications of IP networks, e.g., 6LoWPAN/CoAP networks, involve different security needs. The following five subsections summarize the expected security features or capabilities for each the security profile with regards to "Security Architecture", "Security Model", "Security Bootstrapping", "Network Security", and "Application Security".

## Classes of IoT Systems {#sec7-1}

ToDo: This section should describe some exemplary classes of IoT systems. As already said above, my thinking would be to describe the features of those systems and also the typical threat model for each of those classes of IoT systems. With this, we can also 'assign' mitigation strategies to each of the classes of IoT systems and that set of mitigation strategies would be the security profile.

The text below is from the old draft.

------------

We consider four generic security profiles as summarized in the table below:

~~~~
           +---------------------------------------------------------+
           | Exemplary       |                                       |
           | IoT Application |          Description                  |
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

The classification in the table considers different potential applications in which security mechanism are chosen according to the operational features (network size, existence of a central device, connectivity to the Internet, importance of the exchanged information, etc.) and threat model (what are the assets that an attacker looks for). As already pointed out, this set of scenarios is just exemplary and they should be further discussed based on a broader consensus.

The security suite (SecProf_1) is catered for environments in which IP protocols (e.g.,
6LoWPAN/CoAP) can be used to enable communication between things in an ad-hoc
manner and the security requirements are minimal. An example, is a home
application in which two devices should exchange information and no further
connection with other devices (local or with a backend) is required. In
this scenario, value of the exchanged information is low and usually
happens in a confined room, thus, it is possible to have a short period of
time during which initial secrets can be exchanged in the clear. Due to
this fact, there is no requirement to enable devices from different manufacturers to inter operate in a secure way (keys are just exchanged). 
The expected network size of applications using this profile is expected to be small such that the provision of network security, e.g., secure routing, is of low importance.

The next security suite (SecProf_2) represents an evolution of SecProf_1
in which, e.g., home devices, can be managed. A first possibility
for the securing domain management refers to the creation of a centrally
managed security domain without any connectivity to the Internet. The central
device used for management can serve as, e.g., a key distribution center
including policies for key update, storage, etc. The presence of a central
device can help in the management of larger networks. Network security becomes more relevant in this scenario since the IP network (e.g., 6LoWPAN/CoAP network) can be prone to Denial of Service attacks (e.g., flooding if L2 is not protected) or routing attacks. Similarly, the network of devices could also be the source of a DDoS attack and a central device connecting to the Internet can block traffic of ongoing attacks.

SecProf_3 considers that a central device is always required for managing the system. Example applications of this profile include building control and automation, sensor networks for industrial use, environmental monitoring, etc. As before, the manager can be located in the same network (e.g., 6LoWPAN/CoAP network) and handle key management. In this case, the first association of devices to the network is required to be done in a secure way, i.e., requiring authentication and authorization. This step can involve the secure transmission of keying materials used for network security at different layers. The information exchanged in the network is considered to be valuable and it should be protected in the sense of pairwise links. Commands should be secured and broadcast should be secured with entity authentication {{RFC7390}}. Network should be protected from routing attacks. A further extension to this use case is to allow for remote management. A "backend manager" is in charge of securely managing SW or information exchanged or collected within the network, e.g., a 6LoWPAN/CoAP network. This requires connection of devices to the Internet over a 6LBR involving a number of new threats that were not present before. A list of potential attacks include: resource-exhaustion attacks from the Internet; amplification attacks; trust issues related a HTTP-CoAP proxy {{ID-proHTTPCoAP}}, etc. This use case requires protecting the communication from a device in the backend to a device in the IP network, e.g., a 6LoWPAN/CoAP network, end-to-end. This use case also requires measures to provide the 6LBR with the capability of dropping fake requests coming from the Internet. This becomes especially challenging when the 6LBR is not trusted and access to the exchanged information is limited; and even more in the case of a HTTP-CoAP proxy since protocol translation is required. This use case should take care of protecting information accessed from the backend due to privacy issues (e.g., information such as type of devices, location, usage, type and amount of exchanged information, or mobility patterns can be gathered at the backend threatening the privacy sphere of users) so that only required information is disclosed.

The last security suite (SecProf_4) essentially represents interoperability of all the security profiles defined previously. It considers applications with some additional requirements regarding operation such as: (i) ad-hoc establishment of security relationships between things (potentially from different manufacturers) in non-secure environments or (ii) dynamic roaming of things between different IP network security domains. Such operational requirements pose additional security requirements, e.g., in addition to secure bootstrapping of a device within an IP, e.g., 6LowPan/CoAP, security domain and the secure transfer of network operational key, there is a need to enable inter-domains secure communication to facilitate data sharing.
In this scenario, there is also a higher pressure to ensure that an attacker cannot compromise deployed devices and extract or modify any type of private data such as cryptographic keys, data, or proprietary algorithms. 

## Security Profile 1: Home usage {#sec7-2}

ToDo: include typical threats and mitigation strategies for this scenario. Describe why that set of mitigation strategies would lead to a good trade-off between security/cost/usuability.


## Security Profile 2: Managed Home usage {#sec7-3}

ToDo: include typical threats and mitigation strategies for this scenario. Describe why that set of mitigation strategies would lead to a good trade-off between security/cost/usuability.


## Security Profile 3: Industrial usage {#sec7-4}

ToDo: include typical threats and mitigation strategies for this scenario. Describe why that set of mitigation strategies would lead to a good trade-off between security/cost/usuability.


## Security Profile 4: Managed Industrial usage {#sec7-5}

ToDo: include typical threats and mitigation strategies for this scenario. Describe why that set of mitigation strategies would lead to a good trade-off between security/cost/usuability.

# Conclusions {#sec8}

ToDo

# Security Considerations {#sec9}

This document reflects upon the requirements and challenges of the security
architectural framework for the Internet of Things.

# IANA Considerations {#sec10}

This document contains no request to IANA.

# Acknowledgments {#sec11}

We gratefully acknowledge feedback and fruitful discussion with Tobias Heer, Robert Moskowitz, and Thorsten Dahm. We acknowledge the additional authors of the previous version of this document Sye Loong Keoh, Rene Hummen and Rene Struik. 

