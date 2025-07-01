---
title: A CoRIM Profile for Arm's Platform Security Architecture (PSA) Endorsements
abbrev: CoRIM PSA Profile
docname: draft-fdb-rats-psa-endorsements-latest
date: {DATE}
category: info
ipr: trust200902
area: "Security"
workgroup: "Remote ATtestation ProcedureS"
submissionType: IETF

stand_alone: yes
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  text-list-symbols: -o*+
  docmapping: yes

author:

-
  name: Thomas Fossati
  org: Arm Ltd
  email: thomas.fossati@arm.com

-
  name: Yogesh Deshpande
  org: Arm Ltd
  email: yogesh.deshpande@arm.com

-
  name: Henk Birkholz
  org: Fraunhofer SIT
  email: henk.birkholz@sit.fraunhofer.de

normative:
  PSA-TOKEN: I-D.tschofenig-rats-psa-token
  CoRIM: I-D.ietf-rats-corim
  RFC5280: pkix-x509

informative:
  RATS-ARCH: RFC9334
  TEEP: I-D.ietf-teep-architecture
  PSA-CERTIFIED:
   target: https://www.psacertified.org
   title: PSA Certified
   date: 2021

entity:
  SELF: "RFCthis"

--- abstract

PSA Endorsements comprise reference values, endorsed values, cryptographic key
material and certification status information that a Verifier needs in order
to appraise Attestation Evidence produced by a PSA device.  This memo defines
PSA Endorsements as a profile of the CoRIM data model.

--- middle

# Introduction

PSA Endorsements include reference values, endorsed values, cryptographic key
material and certification status information that a Verifier needs in order to
appraise attestation Evidence produced by a PSA device {{PSA-TOKEN}}.  This
memo defines PSA Endorsements as a profile of the CoRIM data model
{{CoRIM}}.

# Conventions and Definitions

{::boilerplate bcp14}

An understanding of the {{CoRIM}} data model is a prerequisite.

The reader is also assumed to be familiar with the terms defined in {{Section
2.1 of PSA-TOKEN}} and in {{Section 4 of RATS-ARCH}}.

# PSA Endorsements
{: #sec-psa-endorsements }

PSA Endorsements describe an attesting device in terms of the hardware and
firmware components that make up its PSA Root of Trust (RoT). This includes
the identification and expected state of the device as well as the
cryptographic key material needed to verify Evidence signed by the device's PSA
RoT. Additionally, PSA Endorsements can include information related to the
certification status of the attesting device.

There are three basic types of PSA Endorsements:

* Reference Values ({{sec-ref-values}}), i.e., measurements of the PSA RoT
  firmware;
* Attestation Verification Keys ({{sec-keys}}), i.e., cryptographic keys
  that are used to verify signed Evidence produced by the PSA RoT, along
  with the identifiers that bind the keys to their device instances;
* Certification Claims ({{sec-certificates}}), i.e., metadata that describe
  the certification status associated with a PSA device;

There is a fourth PSA Endorsement type that aims at covering more advanced
Verifier use cases (e.g., the one described in {{Section 7 of TEEP}}):

* Software Relations ({{sec-swrel}}), used to model upgrade and patch
relationships between software components.

## PSA Endorsement Profile

PSA Endorsements are carried in one or more CoMIDs inside a CoRIM.

The profile attribute in the CoRIM MUST be present and MUST be the URI
`tag:arm.com,2025:psa#1.0.0` as shown in {{ex-arm-psa-profile}}.

~~~
{::include examples/profile.diag}
~~~
{: #ex-arm-psa-profile title="CoRIM profile for PSA Endorsements version 1.0.0" }

## PSA Endorsements to PSA RoT Linkage
{: #sec-psa-rot-id}

Each PSA Endorsement - be it a Reference Value, Attestation Verification Key
or Certification Claim - is associated with an immutable PSA RoT.  The linkage
between a PSA Endorsement and its PSA RoT is made by means of the unique PSA
RoT identifier known as Implementation ID (see {{Section 3.2.2 of PSA-TOKEN}}).

To encode an Implementation ID, the `tagged-bytes` variant of the `$class-id-type-choice` is used, as described in {{cddl-impl-id}}.
The length of the byte string MUST be exactly 32.

~~~
{::include psa-ext/tagged-psa-impl-id.cddl}
~~~
{: #cddl-impl-id title="PSA Platform Implementation ID encoding"}

Besides, a PSA Endorsement can be associated with a specific instance of a
certain PSA RoT - as is the case for Attestation Verification Keys.
The Instance ID (see {{Section 3.2.1 of PSA-TOKEN}}) provides a unique identifier for a given PSA RoT.


To encode an Instance ID, the `tagged-ueid-type` variant of the `$instance-id-type-choice` is used, as described in {{cddl-inst-id}}.
The first byte MUST be 0x01 (RAND) followed by the 32-byte unique instance identifier.

~~~
{::include examples/psa-instance.diag}
~~~
{: #cddl-inst-id title="PSA RoT Instance ID encoding"}

PSA Attestation Verification Keys are associated with a PSA RoT instance by means of the Instance ID and the corresponding Implementation ID.
These identifiers are typically found in the subject of a CoMID triple, encoded in an `environment-map` as shown in {{ex-psa-rot-id}}.

~~~
{::include examples/psa-rot-identification.diag}
~~~
{: #ex-psa-rot-id title="Example PSA RoT Identification" }

## Reference Values
{: #sec-ref-values}

Reference Values carry measurements and other metadata associated with the
updatable firmware in a PSA RoT.  When appraising Evidence, the Verifier
compares Reference Values against the values found in the Software Components
of the PSA token (see {{Section 3.4.1 of PSA-TOKEN}}).

Each measurement is encoded in a `measurement-map` of a CoMID `reference-triple-record`.
Since a `measurement-map` can encode one or more measurements, a single `reference-triple-record`
can carry as many measurements as needed, provided they belong to the same PSA RoT identified
in the subject of the triple.

A single `reference-triple-record` can completely describe the PSA RoT measurements.

Each PSA Software Component (i.e., the `psa-software-component` defined in {{Section 4.4.1 of PSA-TOKEN}}) is encoded in a `measurement-values-map` as defined in {{cddl-swcomp-mvm}}.

~~~ cddl
psa-swcomp-measurement-values-map = {
  ? &(version: 0) => psa-swcomp-version-map
  &(digests: 2) => psa-swcomp-digests-type
  ? &(name: 11) => psa-swcomp-name
  &(cryptokeys: 13) => [ psa-swcomp-signer-id ]
}

psa-swcomp-version-map = {
  &(version: 0) => text
}

psa-swcomp-digests-type = [ + psa-digest ]

psa-digest = [
  alg: text
  val: psa-hash-type
]

psa-hash-type = bytes .size 32 / bytes .size 48 / bytes .size 64

psa-swcomp-name = text

psa-swcomp-signer-id = #6.560(psa-hash-type)
~~~
{: #cddl-swcomp-mvm title="PSA Software Component encoding"}

version (key 0):
: A `version-map` with its `version` field containing the version (key 4) of the `psa-software-component`.
The `version-scheme` field of the `version-map` MUST NOT be present.
The `version` field is optional.

digests (key 2):
: Each array element encodes the "measurement value" (key 2) and "measurement-desc" (key 6) of the `psa-sw-component` in the `val` and `alg` entries, respectively.
The `alg` entry MUST use the text encoding.
The digests array MUST contain at least one entry and MAY contain more than one entry if multiple digests (obtained with different hash algorithms) of the same measured component exist.
If multiple entries exist, they MUST have different `alg` values.
The `digests` field is mandatory.

name (key 11):
: A text value containing the "measurement-type" (key 1) of the `psa-sw-component`.
The `name` field is optional.

cryptokeys (key 13):
: An array with *only one* entry using the `tagged-bytes` variant of the `$crypto-key-type-choice`.
The entry contains the "signer-id" (key 5) of the `psa-sw-component`.
The `cryptokeys` field is mandatory.

Each `measurement-values-map` for a PSA RoT software component is wrapped in a `measurement-map` with an `mkey` using the text variant of the `$measured-element-type-choice`.
The value of the `mkey` MUST be "psa.software-component".
The `authorized-by` field of the `measurement-map` MUST NOT be present.
See {{cddl-swcomp-mm}} for the related CDDL definitions.

~~~ cddl
psa-swcomp-measurement-map = {
  &(mkey: 0) => "psa.software-component"
  &(mval: 1) => psa-swcomp-measurement-values-map
}
~~~
{:#cddl-swcomp-mm title="PSA RoT Software Component measurement-map"}

The complete example of a Reference Value CoMID Triple that encodes multiple `psa-sw-component` is given {{ex-reference-value}}.

~~~ cbor.diag
{:: include examples/ref-value.diag }
~~~
{: #ex-reference-value title="Example Reference Value"}

## Attestation Verification Keys
{: #sec-keys}

An Attestation Verification Key carries the verification key associated with
the Initial Attestation Key (IAK) of a PSA device.  When appraising Evidence,
the Verifier can use the Implementation ID and Instance ID claims (see
{{sec-psa-rot-id}}) to look up the verification key that it SHALL use to check
the signature on the Evidence.  This allows the Verifier to prove (or disprove)
the Attester's claimed identity.

Each verification key is provided alongside the corresponding device Instance
and Implementation IDs (and, possibly, a product identifier) in an
`attest-key-triple-record`. Specifically:

* The Instance and Implementation IDs are encoded in the environment-map as shown in {{ex-psa-rot-id}};
* The IAK public key uses the `tagged-pkix-base64-key-type` variant of the `$crypto-key-type-choice`.
The IAK public key is a PEM-encoded SubjectPublicKeyInfo {{-pkix-x509}}.
There MUST be only one key in an `attest-key-triple-record`.

The example in {{ex-attestation-verification-claim}} shows the PSA Endorsement
of type Attestation Verification Key carrying a secp256r1 EC public IAK
associated with Instance ID `4ca3...d296`.

~~~ cbor-diag
{::include examples/instance-pub.diag}
~~~
{: #ex-attestation-verification-claim title="Example Attestation Verification Key"}

## Certification Claims
{: #sec-certificates}

PSA Certified {{PSA-CERTIFIED}} defines a certification scheme for the PSA
ecosystem.  A product - either a hardware component, a software component, or
an entire device - that is verified to meet the security criteria established
by the PSA Certified scheme is warranted a PSA Certified Security Assurance
Certificate (SAC). A SAC contains information about the certification of a
certain product (e.g., the target system, the attained certification level, the
test lab that conducted the evaluation, etc.), and has a unique Certificate
Number.

The linkage between a PSA RoT -- comprising the immutable part as well as zero
or more of the mutable components -- and the associated SAC is provided by a
Certification Claim, which binds the PSA RoT Implementation ID and the software
component identifiers with the SAC unique Certificate Number.  When appraising
Evidence, the Verifier can use the Certification Claims associated with the
identified Attester as ancillary input to the Appraisal Policy, or to enrich
the produced Attestation Result.

A Certification Claim is encoded as a `conditional-endorsement-triple-record`.

The SAC is encoded in a `psa-cert-num` that extends the
`measurement-values-map`.  See {{ex-cert-triple}}.

~~~
{::include psa-ext/cert-triple.cddl}
~~~
{: #ex-cert-triple title="Example Certification Triple"}

The `conditional-endorsement-triple-record` is constructed as follows:

* The Implementation ID of the immutable PSA RoT to which the SAC applies is encoded as a `tagged-bytes` in the `environment-map` of the
`stateful-environment-record`; as shown in  {{cddl-impl-id}}
* Any software component that is part of the certified PSA RoT is encoded as a reference value (see {{sec-ref-values}}) in the `measurement-map` of the `stateful-environment-record`;
* The unique SAC Certificate Number is encoded as `psa-cert-num` (key 100) in the `measurement-values-map`.

The example in {{ex-certification-claim}} shows a Certification Claim that
associates Certificate Number `1234567890123 - 12345` to Implementation ID
`acme-implementation-id-000000001` and a single "PRoT" software component with
version "1.3.5".

~~~
{::include examples/cert-val.diag}
~~~
{: #ex-certification-claim title="Example Certification Claim"}

## Software Upgrades and Patches
{:#sec-swrel}

In order to model software lifecycle events such as updates and patches, this
profile defines a new triple that conveys the following semantics:

* SUBJECT: a software component
* PREDICATE: (non-critically / critically) (updates / patches)
* OBJECT: another software component

The triple is reified and used as the object of another triple,
`psa-swrel-triple-record`, whose subject is the embedding environment.

~~~
{::include psa-ext/swrel.cddl}
~~~

An example of a security critical update involving versions "1.2.5" and "1.3.0"
of software component "PRoT" within the target environment associated with
Implementation ID `acme-implementation-id-000000001` is shown in
{{ex-psa-swrel-update-crit}}.

~~~
{::include examples/swrel-update-crit.diag}
~~~
{: #ex-psa-swrel-update-crit title="Example Critical Software Upgrade" }


# Security Considerations

<cref>TODO</cref>

# IANA Considerations

## CBOR Tag Registrations

This document makes no requests to IANA.


## CoMID Codepoints

### CoMID Triples Map Extension

IANA is requested to register the following codepoints to the "CoMID Triples
Map" registry.

| Index | Item Name | Specification
|---
| 50 | comid.psa-swrel-triples | {{&SELF}}
{: #tbl-psa-comid-triples
   align="left"
   title="PSA CoMID Triples"}

### CoMID Measurement Values Map Extension

| Key | Item Name | Item Type | Specification
|---
| 100 | comid.psa-cert-num | `psa-cert-num` | {{sec-certificates}} of {{&SELF}}
{: #tbl-psa-comid-measurement-values-map
   align="left"
   title="Measurement Values Map Extensions"}

# Acknowledgements
{: numbered="no"}

<cref>TODO</cref>
