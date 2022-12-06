from shiny import App, render, ui, types
from pathlib import Path
from ecpy.curves import Curve
from ecpy.keys import ECPublicKey
from ecpy.ecdsa import ECDSA
from ecpy.eddsa import EDDSA
from base64 import b64decode
import asn1tools
import binascii
import hashlib
import zipfile
import asyncio

ASSINATURA = """
ModuloAssinaturaResultado DEFINITIONS IMPLICIT TAGS ::= BEGIN

EXPORTS ALL;

-- TIPOS
DataHoraJE ::= GeneralString(SIZE(15))  -- Data e hora utilizada pela Justiça Eleitoral no formato YYYYMMDDThhmmss.

-- ENUMS
--Tipos de algoritmos de assinatura (cepesc é o algoritmo padrão (ainda não há previsão de uso dos demais)).
AlgoritmoAssinatura ::= ENUMERATED {
    rsa(1),
    ecdsa(2),
    cepesc(3)
}

-- Tipos de algoritmos de hash (Todos os algoritmos devem ser suportados, mas sha512 é o padrão).
AlgoritmoHash ::= ENUMERATED {
    sha1(1),
    sha256(2),
    sha384(3),
    sha512(4)
}

-- Tipos de modelos de urna eletrônica.
ModeloUrna ::= ENUMERATED {
    ue2009(9),  -- Urna modelo 2009.
    ue2010(10), -- Urna modelo 2010.
    ue2011(11), -- Urna modelo 2011.
    ue2013(13), -- Urna modelo 2013.
    ue2015(15), -- Urna modelo 2015.
    ue2020(20)  -- Urna modelo 2020.
}

-- ENVELOPE
-- Entidade que engloba a lista de assinaturas utilizadas para assinar os arquivos para manter a integridade e segurança dos dados.
EntidadeAssinatura ::= SEQUENCE {
    dataHoraCriacao         DataHoraJE,                         -- Data e Hora da criacao do arquivo.
    versao                  INTEGER (2..99999999),              -- Versao do protocolo (Alterações devem gerar novo valor. Nas eleições de 2012 foi utilizado o enumerado de valor 1, a partir de 2014 utilizar o valor 2).
    autoAssinado            AutoAssinaturaDigital,              -- Informações da auto assinatura digital.
    conteudoAutoAssinado    OCTET STRING,                       -- Conteúdo da assinatura do próprio arquivo.
    certificadoDigital      OCTET STRING OPTIONAL,              -- Certificado digital da urna eletrônica.
    conjuntoChave           GeneralString(SIZE(1..15)) OPTIONAL -- Identificador do conjunto de chaves usado para assinar o pacote.
}

-- Entidade responsável por gerar o arquivo de assinatura de todos os arquivos de resultados da urna.
-- Podendo ter dois tipos de assinatura (Hardware (HW) e Software (SW)).
-- Esses arquivos são informados na Mídia de Resultado quando a urna eletrônica é encerrada.
EntidadeAssinaturaResultado ::= SEQUENCE {
    modeloUrna      ModeloUrna,         -- Modelo da urna eletrônica.
    assinaturaSW    EntidadeAssinatura, -- Assinatura realizada via software (normalmente CEPESC).
    assinaturaHW    EntidadeAssinatura  -- Assinatura realizada via hardware de segurança da urna eletrônica.
}

-- Demais SEQUENCES
-- Informações do algoritmo de hash.
-- Informações do algoritmo de assinatura .
AlgoritmoAssinaturaInfo ::= SEQUENCE {
    algoritmo   AlgoritmoAssinatura,    -- Tipo do algoritmo de assinatura.
    bits        INTEGER                 -- Tamanho da assinatura.
}

AlgoritmoHashInfo ::= SEQUENCE {
    algoritmo AlgoritmoHash -- Tipo do algoritmo de hash.
}

-- Informações dos arquivos assinados.
Assinatura ::= SEQUENCE {
    arquivosAssinados SEQUENCE OF AssinaturaArquivo -- Lista com Informações dos arquivos assinados.
}

--Informações do arquivo e da assinatura.
AssinaturaArquivo ::= SEQUENCE {
    nomeArquivo GeneralString,      -- Nome do arquivo.
    assinatura  AssinaturaDigital   -- Assinatura digital do arquivo.
}

-- Informações da assinatura digital
AssinaturaDigital ::= SEQUENCE {
    tamanho     INTEGER,        -- Tamanho da assinatura.
    hash        OCTET STRING,   -- Hash da assinatura (Deve ser calculado uma única vez e ser utilizado também para o cálculo da assinatura).
    assinatura  OCTET STRING    -- Assinatura (Gerado/verificado a partir do hash acima).
}

-- Informações da auto assinatura digital.
AutoAssinaturaDigital ::= SEQUENCE {
    usuario             DescritorChave,             -- Nome do usuário (Geralmente uma seção) que realizou a assinatura do arquivo.
    algoritmoHash       AlgoritmoHashInfo,          -- Algoritmo de hash utilizado para realizar a assinatura (Será o mesmo para as assinaturas de arquivos).
    algoritmoAssinatura AlgoritmoAssinaturaInfo,    -- Algoritmo utilizado para realizar a assinatura (Será o mesmo para as assinaturas de arquivos).
    assinatura          AssinaturaDigital           -- Informações da assinatura digital.
}

-- Identificador com informações da assinatura.
DescritorChave ::= SEQUENCE {
    nomeUsuario GeneralString,  -- Nome do usuário (Geralmente uma seção) que realizou a assinatura no arquivo.
    serial      INTEGER         -- Data em que foi gerado o conjunto de chaves.
}

END

"""

conv = asn1tools.compile_string(ASSINATURA, codec='ber', numeric_enums=True)

X509 = '''
PKIX1Explicit88 { iso(1) identified-organization(3) dod(6) internet(1)
  security(5) mechanisms(5) pkix(7) id-mod(0) id-pkix1-explicit(18) }

DEFINITIONS EXPLICIT TAGS ::=

BEGIN

-- EXPORTS ALL --

-- IMPORTS NONE --

-- UNIVERSAL Types defined in 1993 and 1998 ASN.1
-- and required by this specification

-- UniversalString ::= [UNIVERSAL 28] IMPLICIT OCTET STRING
        -- UniversalString is defined in ASN.1:1993

-- BMPString ::= [UNIVERSAL 30] IMPLICIT OCTET STRING
      -- BMPString is the subtype of UniversalString and models
      -- the Basic Multilingual Plane of ISO/IEC 10646

-- UTF8String ::= [UNIVERSAL 12] IMPLICIT OCTET STRING
      -- The content of this type conforms to RFC 3629.

-- PKIX specific OIDs

id-pkix  OBJECT IDENTIFIER  ::=
         { iso(1) identified-organization(3) dod(6) internet(1)
                    security(5) mechanisms(5) pkix(7) }

-- PKIX arcs

id-pe OBJECT IDENTIFIER ::= { id-pkix 1 }
        -- arc for private certificate extensions
id-qt OBJECT IDENTIFIER ::= { id-pkix 2 }
        -- arc for policy qualifier types
id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
        -- arc for extended key purpose OIDS
id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }
        -- arc for access descriptors

-- policyQualifierIds for Internet policy qualifiers

id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
      -- OID for CPS qualifier
id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
      -- OID for user notice qualifier

-- access descriptor definitions

id-ad-ocsp         OBJECT IDENTIFIER ::= { id-ad 1 }
id-ad-caIssuers    OBJECT IDENTIFIER ::= { id-ad 2 }
id-ad-timeStamping OBJECT IDENTIFIER ::= { id-ad 3 }
id-ad-caRepository OBJECT IDENTIFIER ::= { id-ad 5 }

-- attribute data types

Attribute               ::= SEQUENCE {
      type             AttributeType,
      values    SET OF AttributeValue }
            -- at least one value is required

AttributeType           ::= OBJECT IDENTIFIER

AttributeValue          ::= ANY -- DEFINED BY AttributeType

AttributeTypeAndValue   ::= SEQUENCE {
        type    AttributeType,
        value   AttributeValue }

-- suggested naming attributes: Definition of the following
--   information object set may be augmented to meet local
--   requirements.  Note that deleting members of the set may
--   prevent interoperability with conforming implementations.
-- presented in pairs: the AttributeType followed by the
--   type definition for the corresponding AttributeValue

-- Arc for standard naming attributes

id-at OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) ds(5) 4 }

-- Naming attributes of type X520name

id-at-name                AttributeType ::= { id-at 41 }
id-at-surname             AttributeType ::= { id-at  4 }
id-at-givenName           AttributeType ::= { id-at 42 }
id-at-initials            AttributeType ::= { id-at 43 }
id-at-generationQualifier AttributeType ::= { id-at 44 }

-- Naming attributes of type X520Name:
--   X520name ::= DirectoryString (SIZE (1..ub-name))
--
-- Expanded to avoid parameterized type:
X520name ::= CHOICE {
      teletexString     TeletexString   (SIZE (1..ub-name)),
      printableString   PrintableString (SIZE (1..ub-name)),
      universalString   UniversalString (SIZE (1..ub-name)),
      utf8String        UTF8String      (SIZE (1..ub-name)),
      bmpString         BMPString       (SIZE (1..ub-name)) }

-- Naming attributes of type X520CommonName

id-at-commonName        AttributeType ::= { id-at 3 }

-- Naming attributes of type X520CommonName:
--   X520CommonName ::= DirectoryName (SIZE (1..ub-common-name))
--
-- Expanded to avoid parameterized type:
X520CommonName ::= CHOICE {
      teletexString     TeletexString   (SIZE (1..ub-common-name)),
      printableString   PrintableString (SIZE (1..ub-common-name)),
      universalString   UniversalString (SIZE (1..ub-common-name)),
      utf8String        UTF8String      (SIZE (1..ub-common-name)),
      bmpString         BMPString       (SIZE (1..ub-common-name)) }

-- Naming attributes of type X520LocalityName

id-at-localityName      AttributeType ::= { id-at 7 }

-- Naming attributes of type X520LocalityName:
--   X520LocalityName ::= DirectoryName (SIZE (1..ub-locality-name))
--
-- Expanded to avoid parameterized type:
X520LocalityName ::= CHOICE {
      teletexString     TeletexString   (SIZE (1..ub-locality-name)),
      printableString   PrintableString (SIZE (1..ub-locality-name)),
      universalString   UniversalString (SIZE (1..ub-locality-name)),
      utf8String        UTF8String      (SIZE (1..ub-locality-name)),
      bmpString         BMPString       (SIZE (1..ub-locality-name)) }

-- Naming attributes of type X520StateOrProvinceName

id-at-stateOrProvinceName AttributeType ::= { id-at 8 }

-- Naming attributes of type X520StateOrProvinceName:
--   X520StateOrProvinceName ::= DirectoryName (SIZE (1..ub-state-name))
--
-- Expanded to avoid parameterized type:
X520StateOrProvinceName ::= CHOICE {
      teletexString     TeletexString   (SIZE (1..ub-state-name)),
      printableString   PrintableString (SIZE (1..ub-state-name)),
      universalString   UniversalString (SIZE (1..ub-state-name)),
      utf8String        UTF8String      (SIZE (1..ub-state-name)),
      bmpString         BMPString       (SIZE (1..ub-state-name)) }

-- Naming attributes of type X520OrganizationName

id-at-organizationName  AttributeType ::= { id-at 10 }

-- Naming attributes of type X520OrganizationName:
--   X520OrganizationName ::=
--          DirectoryName (SIZE (1..ub-organization-name))
--
-- Expanded to avoid parameterized type:
X520OrganizationName ::= CHOICE {
      teletexString     TeletexString
                          (SIZE (1..ub-organization-name)),
      printableString   PrintableString
                          (SIZE (1..ub-organization-name)),
      universalString   UniversalString
                          (SIZE (1..ub-organization-name)),
      utf8String        UTF8String
                          (SIZE (1..ub-organization-name)),
      bmpString         BMPString
                          (SIZE (1..ub-organization-name))  }

-- Naming attributes of type X520OrganizationalUnitName

id-at-organizationalUnitName AttributeType ::= { id-at 11 }

-- Naming attributes of type X520OrganizationalUnitName:
--   X520OrganizationalUnitName ::=
--          DirectoryName (SIZE (1..ub-organizational-unit-name))
--
-- Expanded to avoid parameterized type:
X520OrganizationalUnitName ::= CHOICE {
      teletexString     TeletexString
                          (SIZE (1..ub-organizational-unit-name)),
      printableString   PrintableString
                          (SIZE (1..ub-organizational-unit-name)),
      universalString   UniversalString
                          (SIZE (1..ub-organizational-unit-name)),
      utf8String        UTF8String
                          (SIZE (1..ub-organizational-unit-name)),
      bmpString         BMPString
                          (SIZE (1..ub-organizational-unit-name)) }

-- Naming attributes of type X520Title

id-at-title             AttributeType ::= { id-at 12 }

-- Naming attributes of type X520Title:
--   X520Title ::= DirectoryName (SIZE (1..ub-title))
--
-- Expanded to avoid parameterized type:
X520Title ::= CHOICE {
      teletexString     TeletexString   (SIZE (1..ub-title)),
      printableString   PrintableString (SIZE (1..ub-title)),
      universalString   UniversalString (SIZE (1..ub-title)),
      utf8String        UTF8String      (SIZE (1..ub-title)),
      bmpString         BMPString       (SIZE (1..ub-title)) }

-- Naming attributes of type X520dnQualifier

id-at-dnQualifier       AttributeType ::= { id-at 46 }

X520dnQualifier ::=     PrintableString

-- Naming attributes of type X520countryName (digraph from IS 3166)

id-at-countryName       AttributeType ::= { id-at 6 }

X520countryName ::=     PrintableString (SIZE (2))

-- Naming attributes of type X520SerialNumber

id-at-serialNumber      AttributeType ::= { id-at 5 }

X520SerialNumber ::=    PrintableString (SIZE (1..ub-serial-number))

-- Naming attributes of type X520Pseudonym

id-at-pseudonym         AttributeType ::= { id-at 65 }

-- Naming attributes of type X520Pseudonym:
--   X520Pseudonym ::= DirectoryName (SIZE (1..ub-pseudonym))
--
-- Expanded to avoid parameterized type:
X520Pseudonym ::= CHOICE {
   teletexString     TeletexString   (SIZE (1..ub-pseudonym)),
   printableString   PrintableString (SIZE (1..ub-pseudonym)),
   universalString   UniversalString (SIZE (1..ub-pseudonym)),
   utf8String        UTF8String      (SIZE (1..ub-pseudonym)),
   bmpString         BMPString       (SIZE (1..ub-pseudonym)) }

-- Naming attributes of type DomainComponent (from RFC 4519)

id-domainComponent   AttributeType ::= { 0 9 2342 19200300 100 1 25 }

DomainComponent ::=  IA5String

-- Legacy attributes

pkcs-9 OBJECT IDENTIFIER ::=
       { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 }

id-emailAddress      AttributeType ::= { pkcs-9 1 }

EmailAddress ::=     IA5String (SIZE (1..ub-emailaddress-length))

-- naming data types --

Name ::= CHOICE { -- only one possibility for now --
      rdnSequence  RDNSequence }

RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

DistinguishedName ::=   RDNSequence

RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue

-- Directory string type --

DirectoryString ::= CHOICE {
      teletexString       TeletexString   (SIZE (1..MAX)),
      printableString     PrintableString (SIZE (1..MAX)),
      universalString     UniversalString (SIZE (1..MAX)),
      utf8String          UTF8String      (SIZE (1..MAX)),
      bmpString           BMPString       (SIZE (1..MAX)) }

-- certificate and CRL specific structures begin here

Certificate  ::=  SEQUENCE  {
     tbsCertificate       TBSCertificate,
     signatureAlgorithm   AlgorithmIdentifier,
     signature            BIT STRING  }

TBSCertificate  ::=  SEQUENCE  {
     version        [0] Version DEFAULT v1,
     serialNumber         CertificateSerialNumber,
     signature            AlgorithmIdentifier,
     issuer               Name,
     validity             Validity,
     subject              Name,
     subjectPublicKeyInfo SubjectPublicKeyInfo,
     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                          -- If present, version MUST be v2 or v3
     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                          -- If present, version MUST be v2 or v3
     extensions      [3]  Extensions OPTIONAL
                          -- If present, version MUST be v3 -- }

Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

CertificateSerialNumber  ::=  INTEGER

Validity ::= SEQUENCE {
     notBefore      Time,
     notAfter       Time  }

Time ::= CHOICE {
     utcTime        UTCTime,
     generalTime    GeneralizedTime }

UniqueIdentifier  ::=  BIT STRING

SubjectPublicKeyInfo  ::=  SEQUENCE  {
     algorithm            AlgorithmIdentifier,
     subjectPublicKey     BIT STRING  }

Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

Extension  ::=  SEQUENCE  {
     extnID      OBJECT IDENTIFIER,
     critical    BOOLEAN DEFAULT FALSE,
     extnValue   OCTET STRING
                 -- contains the DER encoding of an ASN.1 value
                 -- corresponding to the extension type identified
                 -- by extnID
     }

-- CRL structures

CertificateList  ::=  SEQUENCE  {
     tbsCertList          TBSCertList,
     signatureAlgorithm   AlgorithmIdentifier,
     signature            BIT STRING  }

TBSCertList  ::=  SEQUENCE  {
     version                 Version OPTIONAL,
                                   -- if present, MUST be v2
     signature               AlgorithmIdentifier,
     issuer                  Name,
     thisUpdate              Time,
     nextUpdate              Time OPTIONAL,
     revokedCertificates     SEQUENCE OF SEQUENCE  {
          userCertificate         CertificateSerialNumber,
          revocationDate          Time,
          crlEntryExtensions      Extensions OPTIONAL
                                   -- if present, version MUST be v2
                               }  OPTIONAL,
     crlExtensions           [0] Extensions OPTIONAL }
                                   -- if present, version MUST be v2

-- Version, Time, CertificateSerialNumber, and Extensions were
-- defined earlier for use in the certificate structure

AlgorithmIdentifier  ::=  SEQUENCE  {
     algorithm               OBJECT IDENTIFIER,
     parameters              ANY DEFINED BY algorithm OPTIONAL  }
                                -- contains a value of the type
                                -- registered for use with the
                                -- algorithm object identifier value

-- X.400 address syntax starts here

ORAddress ::= SEQUENCE {
   built-in-standard-attributes BuiltInStandardAttributes,
   built-in-domain-defined-attributes
                   BuiltInDomainDefinedAttributes OPTIONAL,
   -- see also teletex-domain-defined-attributes
   extension-attributes ExtensionAttributes OPTIONAL }

-- Built-in Standard Attributes

BuiltInStandardAttributes ::= SEQUENCE {
   country-name                  CountryName OPTIONAL,
   administration-domain-name    AdministrationDomainName OPTIONAL,
   network-address           [0] IMPLICIT NetworkAddress OPTIONAL,
     -- see also extended-network-address
   terminal-identifier       [1] IMPLICIT TerminalIdentifier OPTIONAL,
   private-domain-name       [2] PrivateDomainName OPTIONAL,
   organization-name         [3] IMPLICIT OrganizationName OPTIONAL,
     -- see also teletex-organization-name
   numeric-user-identifier   [4] IMPLICIT NumericUserIdentifier
                                 OPTIONAL,
   personal-name             [5] IMPLICIT PersonalName OPTIONAL,
     -- see also teletex-personal-name
   organizational-unit-names [6] IMPLICIT OrganizationalUnitNames
                                 OPTIONAL }
     -- see also teletex-organizational-unit-names

CountryName ::= [APPLICATION 1] CHOICE {
   x121-dcc-code         NumericString
                           (SIZE (ub-country-name-numeric-length)),
   iso-3166-alpha2-code  PrintableString
                           (SIZE (ub-country-name-alpha-length)) }

AdministrationDomainName ::= [APPLICATION 2] CHOICE {
   numeric   NumericString   (SIZE (0..ub-domain-name-length)),
   printable PrintableString (SIZE (0..ub-domain-name-length)) }

NetworkAddress ::= X121Address  -- see also extended-network-address

X121Address ::= NumericString (SIZE (1..ub-x121-address-length))

TerminalIdentifier ::= PrintableString (SIZE (1..ub-terminal-id-length))

PrivateDomainName ::= CHOICE {
   numeric   NumericString   (SIZE (1..ub-domain-name-length)),
   printable PrintableString (SIZE (1..ub-domain-name-length)) }

OrganizationName ::= PrintableString
                            (SIZE (1..ub-organization-name-length))
  -- see also teletex-organization-name

NumericUserIdentifier ::= NumericString
                            (SIZE (1..ub-numeric-user-id-length))

PersonalName ::= SET {
   surname     [0] IMPLICIT PrintableString
                    (SIZE (1..ub-surname-length)),
   given-name  [1] IMPLICIT PrintableString
                    (SIZE (1..ub-given-name-length)) OPTIONAL,
   initials    [2] IMPLICIT PrintableString
                    (SIZE (1..ub-initials-length)) OPTIONAL,
   generation-qualifier [3] IMPLICIT PrintableString
                    (SIZE (1..ub-generation-qualifier-length))
                    OPTIONAL }
  -- see also teletex-personal-name

OrganizationalUnitNames ::= SEQUENCE SIZE (1..ub-organizational-units)
                             OF OrganizationalUnitName
  -- see also teletex-organizational-unit-names

OrganizationalUnitName ::= PrintableString (SIZE
                    (1..ub-organizational-unit-name-length))

-- Built-in Domain-defined Attributes

BuiltInDomainDefinedAttributes ::= SEQUENCE SIZE
                    (1..ub-domain-defined-attributes) OF
                    BuiltInDomainDefinedAttribute

BuiltInDomainDefinedAttribute ::= SEQUENCE {
   type PrintableString (SIZE
                   (1..ub-domain-defined-attribute-type-length)),
   value PrintableString (SIZE
                   (1..ub-domain-defined-attribute-value-length)) }

-- Extension Attributes

ExtensionAttributes ::= SET SIZE (1..ub-extension-attributes) OF
               ExtensionAttribute

ExtensionAttribute ::=  SEQUENCE {
   extension-attribute-type [0] IMPLICIT INTEGER
                   (0..ub-extension-attributes),
   extension-attribute-value [1]
                   ANY DEFINED BY extension-attribute-type }

-- Extension types and attribute values

common-name INTEGER ::= 1

CommonName ::= PrintableString (SIZE (1..ub-common-name-length))

teletex-common-name INTEGER ::= 2

TeletexCommonName ::= TeletexString (SIZE (1..ub-common-name-length))

teletex-organization-name INTEGER ::= 3

TeletexOrganizationName ::=
                TeletexString (SIZE (1..ub-organization-name-length))

teletex-personal-name INTEGER ::= 4

TeletexPersonalName ::= SET {
   surname     [0] IMPLICIT TeletexString
                    (SIZE (1..ub-surname-length)),
   given-name  [1] IMPLICIT TeletexString
                    (SIZE (1..ub-given-name-length)) OPTIONAL,
   initials    [2] IMPLICIT TeletexString
                    (SIZE (1..ub-initials-length)) OPTIONAL,
   generation-qualifier [3] IMPLICIT TeletexString
                    (SIZE (1..ub-generation-qualifier-length))
                    OPTIONAL }

teletex-organizational-unit-names INTEGER ::= 5

TeletexOrganizationalUnitNames ::= SEQUENCE SIZE
      (1..ub-organizational-units) OF TeletexOrganizationalUnitName

TeletexOrganizationalUnitName ::= TeletexString
                  (SIZE (1..ub-organizational-unit-name-length))

pds-name INTEGER ::= 7

PDSName ::= PrintableString (SIZE (1..ub-pds-name-length))

physical-delivery-country-name INTEGER ::= 8

PhysicalDeliveryCountryName ::= CHOICE {
   x121-dcc-code NumericString (SIZE (ub-country-name-numeric-length)),
   iso-3166-alpha2-code PrintableString
                               (SIZE (ub-country-name-alpha-length)) }

postal-code INTEGER ::= 9

PostalCode ::= CHOICE {
   numeric-code   NumericString (SIZE (1..ub-postal-code-length)),
   printable-code PrintableString (SIZE (1..ub-postal-code-length)) }

physical-delivery-office-name INTEGER ::= 10

PhysicalDeliveryOfficeName ::= PDSParameter

physical-delivery-office-number INTEGER ::= 11

PhysicalDeliveryOfficeNumber ::= PDSParameter

extension-OR-address-components INTEGER ::= 12

ExtensionORAddressComponents ::= PDSParameter

physical-delivery-personal-name INTEGER ::= 13

PhysicalDeliveryPersonalName ::= PDSParameter

physical-delivery-organization-name INTEGER ::= 14

PhysicalDeliveryOrganizationName ::= PDSParameter

extension-physical-delivery-address-components INTEGER ::= 15

ExtensionPhysicalDeliveryAddressComponents ::= PDSParameter

unformatted-postal-address INTEGER ::= 16

UnformattedPostalAddress ::= SET {
   printable-address SEQUENCE SIZE (1..ub-pds-physical-address-lines)
        OF PrintableString (SIZE (1..ub-pds-parameter-length)) OPTIONAL,
   teletex-string TeletexString
        (SIZE (1..ub-unformatted-address-length)) OPTIONAL }

street-address INTEGER ::= 17

StreetAddress ::= PDSParameter

post-office-box-address INTEGER ::= 18

PostOfficeBoxAddress ::= PDSParameter

poste-restante-address INTEGER ::= 19

PosteRestanteAddress ::= PDSParameter

unique-postal-name INTEGER ::= 20

UniquePostalName ::= PDSParameter

local-postal-attributes INTEGER ::= 21

LocalPostalAttributes ::= PDSParameter

PDSParameter ::= SET {
   printable-string PrintableString
                (SIZE(1..ub-pds-parameter-length)) OPTIONAL,
   teletex-string TeletexString
                (SIZE(1..ub-pds-parameter-length)) OPTIONAL }

extended-network-address INTEGER ::= 22

ExtendedNetworkAddress ::= CHOICE {
   e163-4-address SEQUENCE {
      number      [0] IMPLICIT NumericString
                       (SIZE (1..ub-e163-4-number-length)),
      sub-address [1] IMPLICIT NumericString
                       (SIZE (1..ub-e163-4-sub-address-length))
                       OPTIONAL },
   psap-address   [0] IMPLICIT PresentationAddress }

PresentationAddress ::= SEQUENCE {
    pSelector     [0] EXPLICIT OCTET STRING OPTIONAL,
    sSelector     [1] EXPLICIT OCTET STRING OPTIONAL,
    tSelector     [2] EXPLICIT OCTET STRING OPTIONAL,
    nAddresses    [3] EXPLICIT SET SIZE (1..MAX) OF OCTET STRING }

terminal-type  INTEGER ::= 23

TerminalType ::= INTEGER {
   telex        (3),
   teletex      (4),
   g3-facsimile (5),
   g4-facsimile (6),
   ia5-terminal (7),
   videotex     (8) } (0..ub-integer-options)

-- Extension Domain-defined Attributes

teletex-domain-defined-attributes INTEGER ::= 6

TeletexDomainDefinedAttributes ::= SEQUENCE SIZE
   (1..ub-domain-defined-attributes) OF TeletexDomainDefinedAttribute

TeletexDomainDefinedAttribute ::= SEQUENCE {
        type TeletexString
               (SIZE (1..ub-domain-defined-attribute-type-length)),
        value TeletexString
               (SIZE (1..ub-domain-defined-attribute-value-length)) }

--  specifications of Upper Bounds MUST be regarded as mandatory
--  from Annex B of ITU-T X.411 Reference Definition of MTS Parameter
--  Upper Bounds

-- Upper Bounds
ub-name INTEGER ::= 32768
ub-common-name INTEGER ::= 64
ub-locality-name INTEGER ::= 128
ub-state-name INTEGER ::= 128
ub-organization-name INTEGER ::= 64
ub-organizational-unit-name INTEGER ::= 64
ub-title INTEGER ::= 64
ub-serial-number INTEGER ::= 64
ub-match INTEGER ::= 128
ub-emailaddress-length INTEGER ::= 255
ub-common-name-length INTEGER ::= 64
ub-country-name-alpha-length INTEGER ::= 2
ub-country-name-numeric-length INTEGER ::= 3
ub-domain-defined-attributes INTEGER ::= 4
ub-domain-defined-attribute-type-length INTEGER ::= 8
ub-domain-defined-attribute-value-length INTEGER ::= 128
ub-domain-name-length INTEGER ::= 16
ub-extension-attributes INTEGER ::= 256
ub-e163-4-number-length INTEGER ::= 15
ub-e163-4-sub-address-length INTEGER ::= 40
ub-generation-qualifier-length INTEGER ::= 3
ub-given-name-length INTEGER ::= 16
ub-initials-length INTEGER ::= 5
ub-integer-options INTEGER ::= 256
ub-numeric-user-id-length INTEGER ::= 32
ub-organization-name-length INTEGER ::= 64
ub-organizational-unit-name-length INTEGER ::= 32
ub-organizational-units INTEGER ::= 4
ub-pds-name-length INTEGER ::= 16
ub-pds-parameter-length INTEGER ::= 30
ub-pds-physical-address-lines INTEGER ::= 6
ub-postal-code-length INTEGER ::= 16
ub-pseudonym INTEGER ::= 128
ub-surname-length INTEGER ::= 40
ub-terminal-id-length INTEGER ::= 24
ub-unformatted-address-length INTEGER ::= 180
ub-x121-address-length INTEGER ::= 16

-- Note - upper bounds on string types, such as TeletexString, are
-- measured in characters.  Excepting PrintableString or IA5String, a
-- significantly greater number of octets will be required to hold
-- such a value.  As a minimum, 16 octets, or twice the specified
-- upper bound, whichever is the larger, should be allowed for

-- TeletexString.  For UTF8String or UniversalString at least four
-- times the upper bound should be allowed.

END

PKIX1Implicit88 { iso(1) identified-organization(3) dod(6) internet(1)
  security(5) mechanisms(5) pkix(7) id-mod(0) id-pkix1-implicit(19) }

DEFINITIONS IMPLICIT TAGS ::=

BEGIN

-- EXPORTS ALL --

IMPORTS
      id-pe, id-kp, id-qt-unotice, id-qt-cps,
      -- delete following line if "new" types are supported --
      BMPString, UTF8String,  -- end "new" types --
      ORAddress, Name, RelativeDistinguishedName,
      CertificateSerialNumber, Attribute, DirectoryString
      FROM PKIX1Explicit88 { iso(1) identified-organization(3)
            dod(6) internet(1) security(5) mechanisms(5) pkix(7)
            id-mod(0) id-pkix1-explicit(18) };

-- ISO arc for standard certificate and CRL extensions

id-ce OBJECT IDENTIFIER  ::=  {joint-iso-ccitt(2) ds(5) 29}

-- authority key identifier OID and syntax

id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }

AuthorityKeyIdentifier ::= SEQUENCE {
    keyIdentifier             [0] KeyIdentifier            OPTIONAL,
    authorityCertIssuer       [1] GeneralNames             OPTIONAL,
    authorityCertSerialNumber [2] CertificateSerialNumber  OPTIONAL }
    -- authorityCertIssuer and authorityCertSerialNumber MUST both
    -- be present or both be absent

KeyIdentifier ::= OCTET STRING

-- subject key identifier OID and syntax

id-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 14 }

SubjectKeyIdentifier ::= KeyIdentifier

-- key usage extension OID and syntax

id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }

KeyUsage ::= BIT STRING {
     digitalSignature        (0),
     nonRepudiation          (1),  -- recent editions of X.509 have
                                -- renamed this bit to contentCommitment
     keyEncipherment         (2),
     dataEncipherment        (3),
     keyAgreement            (4),
     keyCertSign             (5),
     cRLSign                 (6),
     encipherOnly            (7),
     decipherOnly            (8) }

-- private key usage period extension OID and syntax

id-ce-privateKeyUsagePeriod OBJECT IDENTIFIER ::=  { id-ce 16 }

PrivateKeyUsagePeriod ::= SEQUENCE {
     notBefore       [0]     GeneralizedTime OPTIONAL,
     notAfter        [1]     GeneralizedTime OPTIONAL }
     -- either notBefore or notAfter MUST be present

-- certificate policies extension OID and syntax

id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 }

anyPolicy OBJECT IDENTIFIER ::= { id-ce-certificatePolicies 0 }

CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation

PolicyInformation ::= SEQUENCE {
     policyIdentifier   CertPolicyId,
     policyQualifiers   SEQUENCE SIZE (1..MAX) OF
             PolicyQualifierInfo OPTIONAL }

CertPolicyId ::= OBJECT IDENTIFIER

PolicyQualifierInfo ::= SEQUENCE {
     policyQualifierId  PolicyQualifierId,
     qualifier          ANY DEFINED BY policyQualifierId }

-- Implementations that recognize additional policy qualifiers MUST
-- augment the following definition for PolicyQualifierId

PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )

-- CPS pointer qualifier

CPSuri ::= IA5String

-- user notice qualifier

UserNotice ::= SEQUENCE {
     noticeRef        NoticeReference OPTIONAL,
     explicitText     DisplayText OPTIONAL }

NoticeReference ::= SEQUENCE {
     organization     DisplayText,
     noticeNumbers    SEQUENCE OF INTEGER }

DisplayText ::= CHOICE {
     ia5String        IA5String      (SIZE (1..200)),
     visibleString    VisibleString  (SIZE (1..200)),
     bmpString        BMPString      (SIZE (1..200)),
     utf8String       UTF8String     (SIZE (1..200)) }

-- policy mapping extension OID and syntax

id-ce-policyMappings OBJECT IDENTIFIER ::=  { id-ce 33 }

PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
     issuerDomainPolicy      CertPolicyId,
     subjectDomainPolicy     CertPolicyId }

-- subject alternative name extension OID and syntax

id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 }

SubjectAltName ::= GeneralNames

GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

GeneralName ::= CHOICE {
     otherName                 [0]  AnotherName,
     rfc822Name                [1]  IA5String,
     dNSName                   [2]  IA5String,
     x400Address               [3]  ORAddress,
     directoryName             [4]  Name,
     ediPartyName              [5]  EDIPartyName,
     uniformResourceIdentifier [6]  IA5String,
     iPAddress                 [7]  OCTET STRING,
     registeredID              [8]  OBJECT IDENTIFIER }

-- AnotherName replaces OTHER-NAME ::= TYPE-IDENTIFIER, as
-- TYPE-IDENTIFIER is not supported in the '88 ASN.1 syntax

AnotherName ::= SEQUENCE {
     type-id    OBJECT IDENTIFIER,
     value      [0] EXPLICIT ANY DEFINED BY type-id }

EDIPartyName ::= SEQUENCE {
     nameAssigner              [0]  DirectoryString OPTIONAL,
     partyName                 [1]  DirectoryString }

-- issuer alternative name extension OID and syntax

id-ce-issuerAltName OBJECT IDENTIFIER ::=  { id-ce 18 }

IssuerAltName ::= GeneralNames

id-ce-subjectDirectoryAttributes OBJECT IDENTIFIER ::=  { id-ce 9 }

SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute

-- basic constraints extension OID and syntax

id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }

BasicConstraints ::= SEQUENCE {
     cA                      BOOLEAN DEFAULT FALSE,
     pathLenConstraint       INTEGER (0..MAX) OPTIONAL }

-- name constraints extension OID and syntax

id-ce-nameConstraints OBJECT IDENTIFIER ::=  { id-ce 30 }

NameConstraints ::= SEQUENCE {
     permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
     excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }

GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree

GeneralSubtree ::= SEQUENCE {
     base                    GeneralName,
     minimum         [0]     BaseDistance DEFAULT 0,
     maximum         [1]     BaseDistance OPTIONAL }

BaseDistance ::= INTEGER (0..MAX)

-- policy constraints extension OID and syntax

id-ce-policyConstraints OBJECT IDENTIFIER ::=  { id-ce 36 }

PolicyConstraints ::= SEQUENCE {
     requireExplicitPolicy   [0]     SkipCerts OPTIONAL,
     inhibitPolicyMapping    [1]     SkipCerts OPTIONAL }

SkipCerts ::= INTEGER (0..MAX)

-- CRL distribution points extension OID and syntax

id-ce-cRLDistributionPoints     OBJECT IDENTIFIER  ::=  {id-ce 31}

CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint

DistributionPoint ::= SEQUENCE {
     distributionPoint       [0]     DistributionPointName OPTIONAL,
     reasons                 [1]     ReasonFlags OPTIONAL,
     cRLIssuer               [2]     GeneralNames OPTIONAL }

DistributionPointName ::= CHOICE {
     fullName                [0]     GeneralNames,
     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }

ReasonFlags ::= BIT STRING {
     unused                  (0),
     keyCompromise           (1),
     cACompromise            (2),
     affiliationChanged      (3),
     superseded              (4),
     cessationOfOperation    (5),
     certificateHold         (6),
     privilegeWithdrawn      (7),
     aACompromise            (8) }

-- extended key usage extension OID and syntax

id-ce-extKeyUsage OBJECT IDENTIFIER ::= {id-ce 37}

ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId

KeyPurposeId ::= OBJECT IDENTIFIER

-- permit unspecified key uses

anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }

-- extended key purpose OIDs

id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
id-kp-codeSigning            OBJECT IDENTIFIER ::= { id-kp 3 }
id-kp-emailProtection        OBJECT IDENTIFIER ::= { id-kp 4 }
id-kp-timeStamping           OBJECT IDENTIFIER ::= { id-kp 8 }
id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }

-- inhibit any policy OID and syntax

id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::=  { id-ce 54 }

InhibitAnyPolicy ::= SkipCerts

-- freshest (delta)CRL extension OID and syntax

id-ce-freshestCRL OBJECT IDENTIFIER ::=  { id-ce 46 }

FreshestCRL ::= CRLDistributionPoints

-- authority info access

id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }

AuthorityInfoAccessSyntax  ::=
        SEQUENCE SIZE (1..MAX) OF AccessDescription

AccessDescription  ::=  SEQUENCE {
        accessMethod          OBJECT IDENTIFIER,
        accessLocation        GeneralName  }

-- subject info access

id-pe-subjectInfoAccess OBJECT IDENTIFIER ::= { id-pe 11 }

SubjectInfoAccessSyntax  ::=
        SEQUENCE SIZE (1..MAX) OF AccessDescription

-- CRL number extension OID and syntax

id-ce-cRLNumber OBJECT IDENTIFIER ::= { id-ce 20 }

CRLNumber ::= INTEGER (0..MAX)

-- issuing distribution point extension OID and syntax

id-ce-issuingDistributionPoint OBJECT IDENTIFIER ::= { id-ce 28 }

IssuingDistributionPoint ::= SEQUENCE {
     distributionPoint          [0] DistributionPointName OPTIONAL,
     onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
     onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
     onlySomeReasons            [3] ReasonFlags OPTIONAL,
     indirectCRL                [4] BOOLEAN DEFAULT FALSE,
     onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
     -- at most one of onlyContainsUserCerts, onlyContainsCACerts,
     -- and onlyContainsAttributeCerts may be set to TRUE.

id-ce-deltaCRLIndicator OBJECT IDENTIFIER ::= { id-ce 27 }

BaseCRLNumber ::= CRLNumber

-- reason code extension OID and syntax

id-ce-cRLReasons OBJECT IDENTIFIER ::= { id-ce 21 }

CRLReason ::= ENUMERATED {
     unspecified             (0),
     keyCompromise           (1),
     cACompromise            (2),
     affiliationChanged      (3),
     superseded              (4),
     cessationOfOperation    (5),
     certificateHold         (6),
     removeFromCRL           (8),
     privilegeWithdrawn      (9),
     aACompromise           (10) }

-- certificate issuer CRL entry extension OID and syntax

id-ce-certificateIssuer OBJECT IDENTIFIER ::= { id-ce 29 }

CertificateIssuer ::= GeneralNames

-- hold instruction extension OID and syntax

id-ce-holdInstructionCode OBJECT IDENTIFIER ::= { id-ce 23 }

HoldInstructionCode ::= OBJECT IDENTIFIER

-- ANSI x9 arc holdinstruction arc

holdInstruction OBJECT IDENTIFIER ::=
          {joint-iso-itu-t(2) member-body(2) us(840) x9cm(10040) 2}

-- ANSI X9 holdinstructions

id-holdinstruction-none OBJECT IDENTIFIER  ::=
                                      {holdInstruction 1} -- deprecated

id-holdinstruction-callissuer OBJECT IDENTIFIER ::= {holdInstruction 2}

id-holdinstruction-reject OBJECT IDENTIFIER ::= {holdInstruction 3}

-- invalidity date CRL entry extension OID and syntax

id-ce-invalidityDate OBJECT IDENTIFIER ::= { id-ce 24 }

InvalidityDate ::=  GeneralizedTime

END
'''

x509_conv = asn1tools.compile_string(X509, codec="der")


def hash_file(file):
    sha = hashlib.sha512()
    sha.update(file)
    digest = sha.digest()
    return digest


def decode_envelope(assinatura):
    envelope_encoded = bytearray(assinatura)
    envelope_decoded = conv.decode(
        "EntidadeAssinaturaResultado", envelope_encoded)
    entidade_assinatura = envelope_decoded['assinaturaHW']
    return entidade_assinatura


def decode_assinaturas(entidade_assinatura):
    assinaturas_encoded = entidade_assinatura["conteudoAutoAssinado"]
    assinaturas_decoded = conv.decode("Assinatura", assinaturas_encoded)
    return assinaturas_decoded


def extract_pubkey(entidade_assinatura):
    """
    Code from epicleet: https://github.com/epicleet/var-ue
    """
    cert = entidade_assinatura['certificadoDigital']
    if cert.startswith(b'-----'):
        # PEM to DER
        cert = b64decode(b''.join(cert.splitlines()[1:-1]))
    cert = x509_conv.decode('Certificate', cert)
    cert = cert['tbsCertificate']
    cn = next(
        item['value'] for item in cert['subject'][1][0]
        if item['type'] == '2.5.4.3')
    assert cn[0] in {
        0x13, 0xc}, 'CN deveria ser PrintableString ou OCTET STRING'
    cn = cn[2:2+cn[1]].decode('utf-8')

    pubkey_algo = cert['subjectPublicKeyInfo']['algorithm']['algorithm']
    pubkey, _ = cert['subjectPublicKeyInfo']['subjectPublicKey']

    if pubkey_algo == '1.2.840.10045.2.1':
        signer = ECDSA()
        curve = Curve.get_curve('secp521r1')
    elif pubkey_algo == '1.3.6.1.4.1.44588.2.1':
        signer = EDDSA(hashlib.shake_256, hash_len=132)
        curve = Curve.get_curve('Ed521')
    else:
        "ERRO Algoritmo de encriptação"
    pubkey = ECPublicKey(curve.decode_point(pubkey))
    return {"pubkey": pubkey, "signer": signer, "cn": cn}


def extract_hash_signature(assinaturas_decoded, arquivo, sign):
    assert sign in {'hash', 'assinatura'}
    if arquivo == "log":
        resumo = assinaturas_decoded['arquivosAssinados'][10]['assinatura'][sign]
    elif arquivo == "bu":
        resumo = assinaturas_decoded['arquivosAssinados'][0]['assinatura'][sign]
    else:
        resumo = "Opção inválida"
    return resumo


def check_signature(hash_arquivo, assinatura_original, pub_key):
    pubkey, signer, _ = pub_key.values()
    return signer.verify(hash_arquivo, assinatura_original, pubkey)


def build_output(checked, hash_original, hash_arquivo):
    if checked:
        color = "green"
    else:
        color = "red"

    out = "<p><strong>Hash da assinatura da urna</strong></p>" + \
        "<p style='color:" + color + "'>" + \
        binascii.hexlify(hash_original).decode('ascii') + "</p>" + \
        "<p><strong>Hash do arquivo apresentado</strong></p>" + \
        "<p style='color:" + color + "'>" + \
        binascii.hexlify(hash_arquivo).decode('ascii') + "</p>"

    return out


app_ui = ui.page_fluid(
    ui.tags.head(
        ui.tags.title("urnaHash"),
        ui.tags.style(ui.HTML(
            """
            html {
                margin-left: 10%;
                margin-right: 10%;
                background: #0f172a;
                padding: 0;
                word-wrap: break-word;
            }

            body {
                min-height: 100vh;
                display: flex;
                flex-direction: column;
                justify-content: stretch;

            }

            .container-fluid {
                flex: 1 1 auto;
                display: flex;
                flex-direction: column;
                padding: 0;
                background-color: black;
            }

            h1, h2, h3, h4 {
                margin: 0;
                padding: 0;
            }

            #titles {
                flex: 1 1 auto;
                background: #5b21b6;
                padding: 20px;
                color: #eff6ff;
                border-radius: 40px 40px 0 0;
            }

            header {
                flex: 1 1 auto;
                display: flex;
                flex-direction: column;
                background: #0f172a;
            }

            #exp {
                flex: 1 1 auto;
                background: #0284c7;
                color: #eff6ff;
                padding: 40px 40px 10px 40px;
                border-radius: 40px 40px 0 0;
            }
            #expBack {
                flex: 3 1 auto;
                display: flex;
                flex-direction: column;
                background: #5b21b6;
            }
            a {
                color: #312e81;
            }

            #mainDiv {
                flex: 1 1 auto;
                display: flex;
                flex-direction: column;
                background: #0284c7;

            }

            main {
                flex: 1;
                border-radius: 40px 40px 0 0;
                background: white;
                padding: 40px;
            }
            p {
                margin-top: 0.5rem;
                margin-bottom: 0.5rem;
            }

            footer {
                display: flex;
                justify-content: center;
                padding: 5px;
                background-color: rgba(255, 255, 255, 0.3);
                height: 60px;
            }

            #github {
                height: 50px;
            }
            """
        ))
    ),
    ui.tags.header(
        ui.tags.div(
            ui.h1("UrnaHash", style='text-align: center'),
            ui.h2("Aplicativo para comparação dos hashes gerados pelas Urnas Eletrônicas",
                  style='text-align: center'),
            id="titles",
        ),
        ui.tags.div(
            ui.tags.div(
                ui.HTML("""
                <h4 onclick='(function(){const lista = document.getElementById("guia");
                                        if (lista.style.display=="block") {
                                            lista.style.display="none";
                                            } else {
                                            lista.style.display="block";
                                            }
                                            })();' style="cursor: pointer; text-decoration: underline;">Guia rápido</h4>
                <ol id="guia" style="display: none">
                <li>Ir ao site dos <a href="https://resultados.tse.jus.br/">Resultados das Eleições 2022 no TSE, em "Dados de Urna"<a>
                <li>Escolher Estado, Município, Zona e Seção Eleitoral</li>
                <li>Fazer download dos arquivos de Boletim de Urna (.bu), Log de Urna (.zip) e Todos os Arquivos (.zip), que contém as assinaturas da urna</li>
                <li>Carregar cada arquivo em seu campo específico abaixo</li>
                <li>Verificar se os <i>hashes</i> são iguais (em verde) ou diferem (em vermelho)</li>
                <li>Opcional: teste o mesmo arquivo de assinaturas com Boletins de Urna e Log de Urna de outras seções para verificar o que acontece</li>
                </ol>
                <p> Este aplicativo compara as assinaturas digitais dos <i>hashes</i> dos arquivos gerados pelas urnas eletrônicas com o arquivo de Boletim de Urna e Log de Urna disponibilizados pelo TSE.</p>
                <p> Quando as assinaturas dos <i>hashes</i> e dos demais arquivos são compatíveis, o resultado é apresentado em <span style="color: green">verde</span>; caso contrário, em <span style="color: red">vermelho</span>.</p>
                <p><strong> <i>Hashes</i> são como impressões digitais de arquivos, se os <i>hashes</i> dos arquivos de Boletim de Urna e Log de Urna
                são iguais aos do registrado no arquivo de assinaturas da urna, ambos só podem ser provenientes daquele urna específica.</strong></p>"""),
                ui.tags.p(
                    ui.tags.a("MANUAL DE USO DETALHADO", href="manual.html")),
                ui.HTML("<p><strong>Aviso legal</strong>: Essa ferramenta não tem qualquer vinculação com o TSE ou partidos políticos e deve ser empregada apenas para fins educacionais.</p>"),
                id="exp"),

            id="expBack"),
    ),
    ui.tags.div(
        ui.tags.main(
            ui.layout_sidebar(
                ui.panel_sidebar(
                    ui.input_file("fileSign", "Escolha um arquivo ZIP com assinaturas da UE (.zip)",
                                  accept=".zip", button_label='Escolher...', placeholder='Nenhum arquivo selecionado'),
                    ui.input_file("fileLog", "Escolha um arquivo ZIP com Log de Urna (.zip)", accept='.zip',
                                  button_label='Escolher...', placeholder='Nenhum arquivo selecionado'),
                    ui.input_file("fileBU", "Escolha um arquivo de Boletim de Urna (.bu)", accept='.bu',
                                  button_label='Escolher...', placeholder='Nenhum arquivo selecionado'),
                    width=4,
                ),
                ui.panel_main(
                    ui.output_ui("contents"),
                ),
            ),
        ),
        id="mainDiv"),
    ui.tags.footer(
        ui.tags.a(ui.tags.img(src='./img/github.png', id='github'),
                  href="https://github.com/erikson84/urnaHash")
    )
)


def server(input, output, session):
    @output
    @render.ui
    async def contents():
        if input.fileBU() is None or input.fileSign() is None or input.fileLog() is None:
            return "Por favor, escolha um arquivo de assinaturas, de log de urna e de boletim de urna."
        bu: list[types.FileInfo] = input.fileBU()
        log: list[types.FileInfo] = input.fileLog()
        sign: list[types.FileInfo] = input.fileSign()

        with zipfile.ZipFile(sign[0]['datapath'], mode='r') as zip:
            for f in zip.namelist():
                if f.endswith(".vscmr"):
                    with zip.open(f, 'r') as file:
                        fil = file.read()
                        envelope = decode_envelope(fil)
                        env_assinatura = decode_assinaturas(envelope)
                        originalLogHash = extract_hash_signature(
                            env_assinatura, "log", "hash")
                        originalBUHash = extract_hash_signature(
                            env_assinatura, "bu", "hash")
                        originalLogSign = extract_hash_signature(
                            env_assinatura, "log", "assinatura")
                        originalBUSign = extract_hash_signature(
                            env_assinatura, "bu", "assinatura")
                        pub_key = extract_pubkey(envelope)

        with zipfile.ZipFile(log[0]['datapath'], mode='r') as zip:
            for f in zip.namelist():
                if f.endswith(".logjez"):
                    with zip.open(f, 'r') as file:
                        currentLog = hash_file(file.read())

        with open(bu[0]['datapath'], 'rb') as file:
            currentBU = hash_file(file.read())

        await asyncio.sleep(1)
        check_log = check_signature(hashlib.sha512(
            currentLog).digest(), originalLogSign, pub_key)
        check_bu = check_signature(hashlib.sha512(
            currentBU).digest(), originalBUSign, pub_key)
        return ui.HTML("<h3>Identificação da UE no Certificado Digital</h3>" +
                       "<h4>" + pub_key["cn"][4:] + "</h4><br>" +
                       "<h3>Hashes do Log de Urna</h3>" +
                       build_output(check_log, originalLogHash, currentLog) +
                       "<h3>Hashes do Boletim de Urna</h3>" +
                       build_output(check_bu, originalBUHash, currentBU)
                       )


app = App(app_ui, server, static_assets=Path(__file__).parent / 'www')
