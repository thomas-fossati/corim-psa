---
title: A CoRIM Profile for Arm's Platform Security Architecture (PSA)
abbrev: CoRIM PSA Profile
docname: draft-fdb-rats-psa-endorsements-latest
date: {DATE}
category: info
ipr: trust200902
area: "Security"
workgroup: "Remote ATtestation ProcedureS"

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

informative:
  RATS-ARCH: RFC9334

  PSA-CERTIFIED:
   target: https://www.psacertified.org
   title: PSA Certified
   date: 2021

--- abstract

PSA Endorsements include reference values, cryptographic key material and
certification status information that a Verifier needs in order to appraise
attestation Evidence produced by a PSA device.  This memo defines such PSA
Endorsements as a profile of the CoRIM data model.

--- middle

# Introduction

PSA Endorsements include reference values, cryptographic key material and
certification status information that a Verifier needs in order to appraise
attestation Evidence produced by a PSA device {{PSA-TOKEN}}.  This memo defines
such PSA Endorsements as a profile of the CoRIM data model {{CoRIM}}.

# Conventions and Definitions

{::boilerplate bcp14}

The reader is assumed to be familiar with the terms defined in Section 2.1 of
{{PSA-TOKEN}} and in Section 4 of {{RATS-ARCH}}.

# PSA Endorsements
{: #sec-psa-endorsements }

PSA Endorsements describe an attesting device in terms of the hardware and
firmware components that make up its PSA Root of Trust (RoT). This includes
the identification and expected state of the device as well as the
cryptographic key material needed to verify Evidence signed by the device's PSA
RoT. Additionally, PSA Endorsements can include information related to the
certification status of the attesting device.

There are five types of PSA Endorsements:

* Reference Values ({{sec-ref-values}}), i.e., measurements of the PSA RoT
  firmware;
* Attestation Verification Claims ({{sec-keys}}), i.e., cryptographic keys
  that can be used to verify signed Evidence produced by the PSA RoT, along
  with the identifiers that bind the keys to their device instances;
* Certification Claims ({{sec-certificates}}), i.e., metadata that describe
  the certification status associated with a PSA device;
* Software Relations ({{sec-swrel}}), used to model upgrade and patch
  relationships between software components;
* Endorsements Block List ({{sec-endorsements-block-list}}), used to invalidate
  previously provisioned Endorsements.

## PSA Endorsement Profile

PSA Endorsements are carried in one or more CoMIDs inside a CoRIM.

The profile attribute in the CoRIM MUST be present and MUST have a single entry
set to the uri `http://arm.com/psa/iot/1` as shown in {{ex-psa-iot-profile}}.

~~~
{::include examples/profile.diag}
~~~
{: #ex-psa-iot-profile title="PSA IoT version 1, CoRIM profile" }

## PSA Endorsements to PSA RoT Linkage
{: #sec-psa-rot-id}

Each PSA Endorsement - be it a Reference Value, Attestation Verification Claim
or Certification Claim - is associated with an immutable PSA RoT.  A PSA
Endorsement is associated to its PSA RoT by means of the unique PSA RoT
identifier known as Implementation ID (see Section 3.2.2 of {{PSA-TOKEN}}).

In order to support PSA Implementation IDs, the CoMID type
`$class-id-type-choice` is extended as follows:

~~~
{::include psa-ext/tagged-psa-impl-id.cddl}
~~~

Besides, a PSA Endorsement can be associated with a specific instance of a
certain PSA RoT - as in the case of Attestation Verification Claims.  A PSA
Endorsement is associated with a PSA RoT instance by means of the Instance ID
(see Section 3.2.1 of {{PSA-TOKEN}}) and its "parent" Implementation ID.

These identifiers are typically found in the subject of a CoMID triple, encoded
in an `environment-map` as shown in {{ex-psa-rot-id}}.

~~~
{::include examples/psa-rot-identification.diag}
~~~
{: #ex-psa-rot-id title="Example PSA RoT Identification" }

Optional `vendor` and `model` can be specified as well.  Together, they are
interpreted as a unique identifier of the product that embeds the PSA RoT.
It is RECOMMENDED to consistently provide a product identifier.

## Reference Values
{: #sec-ref-values}

Reference Values carry measurements and other metadata associated with the
updatable firmware in a PSA RoT.  When appraising Evidence, the Verifier
compares Reference Values against the values found in the Software Components
of the PSA token (see Section 3.4.1 of {{PSA-TOKEN}}).

Each measurement is encoded in a `measurement-map` of a CoMID
`reference-triple-record`.  Since a `measurement-map` can encode one or more
measurements, a single `reference-triple-record` can carry as many measurements
as needed, provided they belong to the same PSA RoT identified in the subject of
the "reference value" triple.  A single `reference-triple-record` MUST
completely describe the updatable PSA RoT.

The identifier of a measured software component is encoded in a `psa-swcomp-id`
object as follows:

~~~
{::include psa-ext/swcomp-id.cddl}
~~~

The semantics of the codepoints in the `psa-swcomp-id` map are equivalent to
those in the `psa-software-component` map defined in Section 3.4.1 of
{{PSA-TOKEN}}.  The `psa-swcomp-id` MUST uniquely identify a given software
component within the PSA RoT / product.

In order to support PSA Reference Value identifiers, the CoMID type
`$measured-element-type-choice` is extended as follows:

~~~
{::include psa-ext/swcomp-id-ext.cddl}
~~~

and automatically bound to the `comid.mkey` in the `measurement-map`.

The raw measurement is encoded in a `digests-type` object in the
`measurement-values-map`.  The `digests-type` array MUST contain at least one
entry.  The `digests-type` array MAY contain more than one entry if multiple
digests (obtained with different hash algorithms) of the same measured
component exist.

The example in {{ex-reference-value}} shows a CoMID encoding a PSA Endorsement
of type Reference Value for a firmware measurement associated with
Implementation ID `acme-implementation-id-000000001`.

~~~
{::include examples/ref-value.diag}
~~~
{: #ex-reference-value title="Example Reference Value"}

### Software Upgrades and Patches
{: #sec-swrel}

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

An example of a security critical update involving versions "1.3.5" and "1.4.0"
of software component "PRoT" within the target environment associated with
Implementation ID `acme-implementation-id-000000001` is shown in
{{ex-psa-swrel-update-crit}}.

~~~
{::include examples/swrel-update-crit.diag}
~~~
{: #ex-psa-swrel-update-crit title="Example Critical Software Upgrade" }


## Attestation Verification Claims
{: #sec-keys}

An Attestation Verification Claim carries the verification key associated with
the Initial Attestation Key (IAK) of a PSA device.  When appraising Evidence,
the Verifier uses the Implementation ID and Instance ID claims (see
{{sec-psa-rot-id}}) to retrieve the verification key that it SHALL use to check
the signature on the Evidence.  This allows the Verifier to prove (or disprove)
the Attester's claimed identity.

Each verification key is provided alongside the corresponding device Instance
and Implementation IDs (and, possibly, a product identifier) in an
`attest-key-triple-record`.  Specifically:

* The Instance and Implementation IDs are encoded in the environment-map as
  shown in {{ex-psa-rot-id}};
* The IAK public key is carried in the `comid.key` entry in the
  `verification-key-map`.  The IAK public key is a PEM-encoded
  SubjectPublicKeyInfo {{!RFC5280}}.  There MUST be only one
  `verification-key-map` in an `attest-key-triple-record`;
* The optional `comid.keychain` entry MUST NOT be set by a CoMID producer that
  uses the profile described in this document, and MUST be ignored by a CoMID
  consumer that is parsing according to this profile.

The example in {{ex-attestation-verification-claim}} shows the PSA Endorsement
of type Attestation Verification Claim carrying a secp256r1 EC public IAK
associated with Instance ID `4ca3...d296`.

~~~
{::include examples/instance-pub.diag}
~~~
{: #ex-attestation-verification-claim title="Example Attestation Verification Claim"}

## Certification Claims
{: #sec-certificates}

PSA Certified {{PSA-CERTIFIED}} defines a certification scheme for the PSA
ecosystem.  A product - either a hardware component, a software component, or
an entire device - that is verified to meet the security criteria established
by the PSA Certified scheme is warranted a PSA Certified Security Assurance
Certificate (SAC).  A SAC contains information about the certification of a
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

A Certification Claim is encoded in an `psa-cert-triple-record`, which extends
the `$$triples-map-extension` socket, as follows:

~~~
{::include psa-ext/cert-triple.cddl}
~~~

* The Implementation ID of the immutable PSA RoT to which the SAC applies is
  encoded as a `tagged-impl-id-type` in the `psa.immutable-rot` of the
  `psa-rot-descriptor`;
* Any software component that is part of the certified PSA RoT is encoded as a
  `psa-swcomp-id` (see {{sec-ref-values}}) in the `psa.mutable-rot` of the
  `psa-rot-descriptor`;
* The unique SAC Certificate Number is encoded in the `psa-cert-num-type`.

A single CoMID can carry one or more Certification Claims.

The example in {{ex-certification-claim}} shows a Certification Claim that
associates Certificate Number `1234567890123 - 12345` to Implementation ID
`acme-implementation-id-000000001` and a single "PRoT" software component with
version "1.3.5".

~~~
{::include examples/cert-val.diag}
~~~
{: #ex-certification-claim title="Example Certification Claim with `supplement` Link-Relation"}

## Endorsements Block List
{: #sec-endorsements-block-list}

<cref>This is work in progress.  It may change or be removed in the future.</cref>

The following three "blocklist" claims:

* `reference-blocklist-triple`
* `attest-key-blocklist-triple`
* `cert-blocklist-triple`

are defined with the same syntax but opposite semantics with regards to their
"positive" counterparts to allow invalidating previously provisioned endorsements
from the acceptable set.

# Security Considerations

<cref>TODO</cref>

# IANA Considerations

## CBOR Tag Registrations

IANA is requested to allocate the following tag in the "CBOR Tags" registry
{{!IANA.cbor-tags}}, preferably with the specified value:

| Tag | Data Item | Semantics |
|---
| 600 | tagged bytes | PSA Implementation ID ({{sec-psa-rot-id}} of RFCTHIS) |
| 601 | tagged map | PSA Software Component Identifier ({{sec-ref-values}} of RFCTHIS) |
{: #tbl-psa-cbor-tag title="CoRIM CBOR Tags"}

## CoRIM Profile Registration

IANA is requested to register the following profile value in the
<cref>TODO</cref> CoRIM registry.

| Profile Value | Type | Semantics |
|---
| `http://arm.com/psa/iot/1` | uri | The CoRIM profile specified by this document |
{: #tbl-psa-corim-profile title="PSA profile for CoRIM"}

## CoMID Codepoints

IANA is requested to register the following codepoints to the "CoMID Triples
Map" registry.

| Index | Item Name | Specification
|---
| 4 | comid.psa-cert-triples | RFCTHIS
| 5 | comid.psa-swrel-triples | RFCTHIS
{: #tbl-psa-comid-triples title="PSA CoMID Triples"}

# Acknowledgements
{: numbered="no"}

<cref>TODO</cref>
