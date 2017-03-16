## Modules

<dl>
<dt><a href="#module_api">api</a></dt>
<dd><p>This module defines the API for the pluggable components of the node.js SDK. The APIs are defined
according to the Hyperledger Fabric&#39;s <a href="https://docs.google.com/document/d/1R5RtIBMW9fZpli37E5Li5_Q9ve3BnQ4q3gWmGZj6Sv4/edit?usp=sharing">common SDK specification</a></p>
</dd>
</dl>

## Classes

<dl>
<dt><a href="#Chain">Chain</a></dt>
<dd><p>The class representing a chain with which the client SDK interacts.</p>
<p>The “Chain” object captures settings for a channel, which is created by
the orderers to isolate transactions delivery to peers participating on channel.
A chain must be initialized after it has been configured with the list of peers
and orderers. The initialization sends a get configuration block request to the
primary orderer to retrieve the configuration settings for this channel.</p>
</dd>
<dt><a href="#Client">Client</a></dt>
<dd><p>Main interaction handler with end user. A client instance provides a handler to interact
with a network of peers, orderers and optionally member services. An application using the
SDK may need to interact with multiple networks, each through a separate instance of the Client.</p>
<p>Each client when initially created should be initialized with configuration data from the
consensus service, which includes a list of trusted roots, orderer certificates and IP addresses,
and a list of peer certificates and IP addresses that it can access. This must be done out of band
as part of bootstrapping the application environment. It is also the responsibility of the application
to maintain the configuration of a client as the SDK does not persist this object.</p>
<p>Each Client instance can maintain several <a href="#Chain">Chain</a> instances representing channels and the associated
private ledgers.</p>
</dd>
<dt><a href="#ChainCodeCBE">ChainCodeCBE</a></dt>
<dd><p>The ChainCodeCBE is used internal to the EventHub to hold chaincode
event registration callbacks.</p>
</dd>
<dt><a href="#EventHub">EventHub</a></dt>
<dd><p>The EventHub class is used to distribute events from an
event source(peer)</p>
</dd>
<dt><a href="#CouchDBKeyValueStore">CouchDBKeyValueStore</a></dt>
<dd><p>This is a sample database implementation of the <a href="#module_api.KeyValueStore">KeyValueStore</a> API.
It uses a local or remote CouchDB database instance to store the keys.</p>
</dd>
<dt><a href="#CryptoSuite_ECDSA_AES">CryptoSuite_ECDSA_AES</a></dt>
<dd><p>The <a href="#module_api.CryptoSuite">CryptoSuite</a> implementation for ECDSA, and AES algorithms using software key generation.
This class implements a software-based key generation (as opposed to Hardware Security Module based key management)</p>
</dd>
<dt><a href="#KeyValueStore">KeyValueStore</a></dt>
<dd><p>This is a default implementation of the <a href="#module_api.KeyValueStore">KeyValueStore</a> API.
It uses files to store the key values.</p>
</dd>
<dt><a href="#Identity">Identity</a></dt>
<dd><p>This interface is shared within the peer and client API of the membership service provider.
Identity interface defines operations associated to a &quot;certificate&quot;.
That is, the public part of the identity could be thought to be a certificate,
and offers solely signature verification capabilities. This is to be used
at the client side when validating certificates that endorsements are signed
with, and verifying signatures that correspond to these certificates.</p>
</dd>
<dt><a href="#Signer">Signer</a></dt>
<dd><p>Signer is an interface for an opaque private key that can be used for signing operations</p>
</dd>
<dt><a href="#SigningIdentity">SigningIdentity</a></dt>
<dd><p>SigningIdentity is an extension of Identity to cover signing capabilities. E.g., signing identity
should be requested in the case of a client who wishes to sign proposal responses and transactions</p>
</dd>
<dt><a href="#MSPManager">MSPManager</a></dt>
<dd><p>MSPManager is an interface defining a manager of one or more MSPs. This essentially acts
as a mediator to MSP calls and routes MSP related calls to the appropriate MSP. This object
is immutable, it is initialized once and never changed.</p>
</dd>
<dt><a href="#MSP">MSP</a></dt>
<dd><p>MSP is the minimal Membership Service Provider Interface to be implemented
to manage identities (in terms of signing and signature verification) represented
by private keys and certificates generated from different algorithms (ECDSA, RSA, etc)
and PKIs (software-managed or HSM based)</p>
</dd>
<dt><a href="#Orderer">Orderer</a></dt>
<dd><p>The Orderer class represents a peer in the target blockchain network to which
HFC sends a block of transactions of endorsed proposals requiring ordering.</p>
</dd>
<dt><a href="#Peer">Peer</a></dt>
<dd><p>The Peer class represents a peer in the target blockchain network to which
HFC sends endorsement proposals, transaction ordering or query requests.</p>
<p>The Peer class represents the remote Peer node and its network membership materials,
aka the ECert used to verify signatures. Peer membership represents organizations,
unlike User membership which represents individuals.</p>
<p>When constructed, a Peer instance can be designated as an event source, in which case
a “eventSourceUrl” attribute should be configured. This allows the SDK to automatically
attach transaction event listeners to the event stream.</p>
<p>It should be noted that Peer event streams function at the Peer level and not at the
chain and chaincode levels.</p>
</dd>
<dt><a href="#Remote">Remote</a></dt>
<dd><p>The Remote class represents a the base class for all remote nodes, Peer, Orderer , and MemberServicespeer.</p>
</dd>
<dt><a href="#User">User</a></dt>
<dd><p>The User class represents users that have been enrolled and represented by
an enrollment certificate (ECert) and a signing key. The ECert must have
been signed by one of the CAs the blockchain network has been configured to trust.
An enrolled user (having a signing key and ECert) can conduct chaincode instantiate,
transactions and queries with the Chain.</p>
<p>User ECerts can be obtained from a CA beforehand as part of installing and instantiating
the application, or it can be obtained from the optional Fabric CA service via its
enrollment process.</p>
<p>Sometimes User identities are confused with Peer identities. User identities represent
signing capability because it has access to the private key, while Peer identities in
the context of the application/SDK only has the certificate for verifying signatures.
An application cannot use the Peer identity to sign things because the application doesn’t
have access to the Peer identity’s private key.</p>
</dd>
</dl>

## Members

<dl>
<dt><a href="#sjcl">sjcl</a></dt>
<dd><p>Implement hash primitives.
Currently SHA3 is implemented, but needs to also add SHA2.</p>
<p>NOTE: This is in pure java script to be compatible with the sjcl.hmac function.</p>
</dd>
</dl>

## Functions

<dl>
<dt><a href="#bitsToBytes">bitsToBytes(a)</a> ⇒ <code>bytes</code></dt>
<dd><p>Convert from a bitArray to bytes (using SJCL&#39;s codec)</p>
</dd>
<dt><a href="#bytesToBits">bytesToBits(a)</a> ⇒ <code>bitArray</code></dt>
<dd><p>Convert from bytes to a bitArray (using SJCL&#39;s codec)</p>
</dd>
<dt><a href="#package">package(chaincodePath, chaincodeType, devmode)</a> ⇒ <code>Promise</code></dt>
<dd><p>Utility function to package a chaincode. The contents will be returned as a byte array.</p>
</dd>
</dl>

<a name="module_api"></a>

## api
This module defines the API for the pluggable components of the node.js SDK. The APIs are defined
according to the Hyperledger Fabric's [common SDK specification](https://docs.google.com/document/d/1R5RtIBMW9fZpli37E5Li5_Q9ve3BnQ4q3gWmGZj6Sv4/edit?usp=sharing)


* [api](#module_api)
    * [.KeyValueStore](#module_api.KeyValueStore)
        * [.getValue(name)](#module_api.KeyValueStore+getValue) ⇒
        * [.setValue(name, value)](#module_api.KeyValueStore+setValue) ⇒ <code>Promise</code>
    * [.CryptoSuite](#module_api.CryptoSuite)
        * [.generateKey(opts)](#module_api.CryptoSuite+generateKey) ⇒ <code>Key</code>
        * [.deriveKey(key, opts)](#module_api.CryptoSuite+deriveKey) ⇒ <code>Key</code>
        * [.importKey(raw, opts)](#module_api.CryptoSuite+importKey) ⇒ <code>Key</code>
        * [.getKey(ski)](#module_api.CryptoSuite+getKey) ⇒ <code>Key</code>
        * [.hash(msg, opts)](#module_api.CryptoSuite+hash) ⇒ <code>string</code>
        * [.sign(key, digest, opts)](#module_api.CryptoSuite+sign) ⇒ <code>Array.&lt;byte&gt;</code>
        * [.verify(key, signature, digest)](#module_api.CryptoSuite+verify) ⇒ <code>boolean</code>
        * [.encrypt(key, plainText, opts)](#module_api.CryptoSuite+encrypt) ⇒ <code>Array.&lt;byte&gt;</code>
        * [.decrypt(key, cipherText, opts)](#module_api.CryptoSuite+decrypt) ⇒ <code>Array.&lt;byte&gt;</code>
    * [.Key](#module_api.Key)
        * [.getSKI()](#module_api.Key+getSKI) ⇒ <code>Array.&lt;byte&gt;</code>
        * [.isSymmetric()](#module_api.Key+isSymmetric) ⇒ <code>boolean</code>
        * [.isPrivate()](#module_api.Key+isPrivate) ⇒ <code>boolean</code>
        * [.getPublicKey()](#module_api.Key+getPublicKey) ⇒ <code>Key</code>
        * [.toBytes()](#module_api.Key+toBytes) ⇒ <code>Array.&lt;byte&gt;</code>

<a name="module_api.KeyValueStore"></a>

### api.KeyValueStore
Abstract class for a Key-Value store. The Chain class uses this store
to save sensitive information such as authenticated user's private keys,
certificates, etc.

The SDK provides a default implementation based on files. An alternative
implementation can be specified using the "KEY_VALUE_STORE" environment
variable pointing to a full path to the require() package for the module.

**Kind**: static class of <code>[api](#module_api)</code>  

* [.KeyValueStore](#module_api.KeyValueStore)
    * [.getValue(name)](#module_api.KeyValueStore+getValue) ⇒
    * [.setValue(name, value)](#module_api.KeyValueStore+setValue) ⇒ <code>Promise</code>

<a name="module_api.KeyValueStore+getValue"></a>

#### keyValueStore.getValue(name) ⇒
Get the value associated with name.

**Kind**: instance method of <code>[KeyValueStore](#module_api.KeyValueStore)</code>  
**Returns**: Promise for the value corresponding to the key. If the value does not exist in the
store, returns null without rejecting the promise  

| Param | Type | Description |
| --- | --- | --- |
| name | <code>string</code> | of the key |

<a name="module_api.KeyValueStore+setValue"></a>

#### keyValueStore.setValue(name, value) ⇒ <code>Promise</code>
Set the value associated with name.

**Kind**: instance method of <code>[KeyValueStore](#module_api.KeyValueStore)</code>  
**Returns**: <code>Promise</code> - Promise for the 'value' object upon successful write operation  

| Param | Type | Description |
| --- | --- | --- |
| name | <code>string</code> | of the key to save |
| value | <code>string</code> | to save |

<a name="module_api.CryptoSuite"></a>

### api.CryptoSuite
Abstract class for a suite of crypto algorithms used by the SDK to perform encryption,
decryption and secure hashing. A complete suite includes libraries for asymmetric
keys (such as ECDSA or RSA), symmetric keys (such as AES) and secure hash (such as
SHA2/3).

The SDK provides a default implementation based on ECDSA + AES + SHA2/3. An alternative
implementation can be specified using the "CRYPTO_SUITE" environment variable, pointing
to a full path to the require() package for the module.

**Kind**: static class of <code>[api](#module_api)</code>  

* [.CryptoSuite](#module_api.CryptoSuite)
    * [.generateKey(opts)](#module_api.CryptoSuite+generateKey) ⇒ <code>Key</code>
    * [.deriveKey(key, opts)](#module_api.CryptoSuite+deriveKey) ⇒ <code>Key</code>
    * [.importKey(raw, opts)](#module_api.CryptoSuite+importKey) ⇒ <code>Key</code>
    * [.getKey(ski)](#module_api.CryptoSuite+getKey) ⇒ <code>Key</code>
    * [.hash(msg, opts)](#module_api.CryptoSuite+hash) ⇒ <code>string</code>
    * [.sign(key, digest, opts)](#module_api.CryptoSuite+sign) ⇒ <code>Array.&lt;byte&gt;</code>
    * [.verify(key, signature, digest)](#module_api.CryptoSuite+verify) ⇒ <code>boolean</code>
    * [.encrypt(key, plainText, opts)](#module_api.CryptoSuite+encrypt) ⇒ <code>Array.&lt;byte&gt;</code>
    * [.decrypt(key, cipherText, opts)](#module_api.CryptoSuite+decrypt) ⇒ <code>Array.&lt;byte&gt;</code>

<a name="module_api.CryptoSuite+generateKey"></a>

#### cryptoSuite.generateKey(opts) ⇒ <code>Key</code>
Generate a key using the opts

**Kind**: instance method of <code>[CryptoSuite](#module_api.CryptoSuite)</code>  
**Returns**: <code>Key</code> - Promise of an instance of the Key class  

| Param | Type | Description |
| --- | --- | --- |
| opts | <code>Object</code> | algorithm: an identifier for the algorithm to be used, such as "ECDSA"      ephemeral: true if the key to generate has to be ephemeral |

<a name="module_api.CryptoSuite+deriveKey"></a>

#### cryptoSuite.deriveKey(key, opts) ⇒ <code>Key</code>
Derives a key from k using opts.

**Kind**: instance method of <code>[CryptoSuite](#module_api.CryptoSuite)</code>  
**Returns**: <code>Key</code> - derived key  

| Param | Type | Description |
| --- | --- | --- |
| key | <code>Key</code> | the source key |
| opts | <code>Object</code> | algorithm: an identifier for the algorithm to be used      ephemeral: true if the key to generate has to be ephemeral |

<a name="module_api.CryptoSuite+importKey"></a>

#### cryptoSuite.importKey(raw, opts) ⇒ <code>Key</code>
Imports a key from its raw representation using opts. If the `opts.ephemeral`
parameter is false, the method, in addition to returning the imported [Key](Key)
instance, also saves the imported key in the key store as PEM files that can be
retrieved using the 'getKey()' method

**Kind**: instance method of <code>[CryptoSuite](#module_api.CryptoSuite)</code>  
**Returns**: <code>Key</code> - Promise of an instance of the Key class wrapping the raw key bytes  

| Param | Type | Description |
| --- | --- | --- |
| raw | <code>Array.&lt;byte&gt;</code> | Raw bytes of the key to import |
| opts | <code>Object</code> | <br>`type`: type of information that 'raw' represents: x509 certificate,      <br>`algorithm`: an identifier for the algorithm to be used      <br>`ephemeral`: true if the key to generate has to be ephemeral |

<a name="module_api.CryptoSuite+getKey"></a>

#### cryptoSuite.getKey(ski) ⇒ <code>Key</code>
Returns the key this CSP associates to the Subject Key Identifier ski.

**Kind**: instance method of <code>[CryptoSuite](#module_api.CryptoSuite)</code>  
**Returns**: <code>Key</code> - Promise of an instance of the Key class corresponding to the ski  

| Param | Type | Description |
| --- | --- | --- |
| ski | <code>Array.&lt;byte&gt;</code> | Subject Key Identifier specific to a Crypto Suite implementation |

<a name="module_api.CryptoSuite+hash"></a>

#### cryptoSuite.hash(msg, opts) ⇒ <code>string</code>
Hashes messages msg using options opts.

**Kind**: instance method of <code>[CryptoSuite](#module_api.CryptoSuite)</code>  
**Returns**: <code>string</code> - The hashed digest in hexidecimal string encoding  

| Param | Type | Description |
| --- | --- | --- |
| msg | <code>Array.&lt;byte&gt;</code> | Source message to be hashed |
| opts | <code>Object</code> | algorithm: an identifier for the algorithm to be used, such as "SHA3" |

<a name="module_api.CryptoSuite+sign"></a>

#### cryptoSuite.sign(key, digest, opts) ⇒ <code>Array.&lt;byte&gt;</code>
Signs digest using key k.
The opts argument should be appropriate for the algorithm used.

**Kind**: instance method of <code>[CryptoSuite](#module_api.CryptoSuite)</code>  
**Returns**: <code>Array.&lt;byte&gt;</code> - the resulting signature  

| Param | Type | Description |
| --- | --- | --- |
| key | <code>Key</code> | Signing key (private key) |
| digest | <code>Array.&lt;byte&gt;</code> | The message digest to be signed. Note that when a signature of a hash of a larger message is needed, the caller is responsible for hashing the larger message and passing the hash (as digest) and the hash function (as opts) to sign. |
| opts | <code>Object</code> | hashingFunction: the function to use to hash |

<a name="module_api.CryptoSuite+verify"></a>

#### cryptoSuite.verify(key, signature, digest) ⇒ <code>boolean</code>
Verifies signature against key k and digest
The opts argument should be appropriate for the algorithm used.

**Kind**: instance method of <code>[CryptoSuite](#module_api.CryptoSuite)</code>  
**Returns**: <code>boolean</code> - true if the signature verifies successfully  

| Param | Type | Description |
| --- | --- | --- |
| key | <code>Key</code> | Signing verification key (public key) |
| signature | <code>Array.&lt;byte&gt;</code> | The signature to verify |
| digest | <code>Array.&lt;byte&gt;</code> | The digest that the signature was created for |

<a name="module_api.CryptoSuite+encrypt"></a>

#### cryptoSuite.encrypt(key, plainText, opts) ⇒ <code>Array.&lt;byte&gt;</code>
Encrypts plaintext using key k.
The opts argument should be appropriate for the algorithm used.

**Kind**: instance method of <code>[CryptoSuite](#module_api.CryptoSuite)</code>  
**Returns**: <code>Array.&lt;byte&gt;</code> - Cipher text after encryption  

| Param | Type | Description |
| --- | --- | --- |
| key | <code>Key</code> | Encryption key (public key) |
| plainText | <code>Array.&lt;byte&gt;</code> | Plain text to encrypt |
| opts | <code>Object</code> | Encryption options |

<a name="module_api.CryptoSuite+decrypt"></a>

#### cryptoSuite.decrypt(key, cipherText, opts) ⇒ <code>Array.&lt;byte&gt;</code>
Decrypts ciphertext using key k.
The opts argument should be appropriate for the algorithm used.

**Kind**: instance method of <code>[CryptoSuite](#module_api.CryptoSuite)</code>  
**Returns**: <code>Array.&lt;byte&gt;</code> - Plain text after decryption  

| Param | Type | Description |
| --- | --- | --- |
| key | <code>Key</code> | Decryption key (private key) |
| cipherText | <code>Array.&lt;byte&gt;</code> | Cipher text to decrypt |
| opts | <code>Object</code> | Decrypt options |

<a name="module_api.Key"></a>

### api.Key
Key represents a cryptographic key. It can be symmetric or asymmetric. In the case of an
asymmetric key, the key can be public or private. In the case of a private asymmetric
key, the getPublicKey() method allows to retrieve the corresponding public-key.
A key can be referenced via the Subject Key Identifier in DER or PEM encoding

**Kind**: static class of <code>[api](#module_api)</code>  

* [.Key](#module_api.Key)
    * [.getSKI()](#module_api.Key+getSKI) ⇒ <code>Array.&lt;byte&gt;</code>
    * [.isSymmetric()](#module_api.Key+isSymmetric) ⇒ <code>boolean</code>
    * [.isPrivate()](#module_api.Key+isPrivate) ⇒ <code>boolean</code>
    * [.getPublicKey()](#module_api.Key+getPublicKey) ⇒ <code>Key</code>
    * [.toBytes()](#module_api.Key+toBytes) ⇒ <code>Array.&lt;byte&gt;</code>

<a name="module_api.Key+getSKI"></a>

#### key.getSKI() ⇒ <code>Array.&lt;byte&gt;</code>
Returns the subject key identifier of this key in DER encoding for private keys or PEM encoding for public keys.

**Kind**: instance method of <code>[Key](#module_api.Key)</code>  
**Returns**: <code>Array.&lt;byte&gt;</code> - the subject key identifier of this key  
<a name="module_api.Key+isSymmetric"></a>

#### key.isSymmetric() ⇒ <code>boolean</code>
Returns true if this key is a symmetric key, false is this key is asymmetric

**Kind**: instance method of <code>[Key](#module_api.Key)</code>  
**Returns**: <code>boolean</code> - if this key is a symmetric key  
<a name="module_api.Key+isPrivate"></a>

#### key.isPrivate() ⇒ <code>boolean</code>
Returns true if this key is an asymmetric private key, false otherwise.

**Kind**: instance method of <code>[Key](#module_api.Key)</code>  
**Returns**: <code>boolean</code> - if this key is an asymmetric private key  
<a name="module_api.Key+getPublicKey"></a>

#### key.getPublicKey() ⇒ <code>Key</code>
Returns the corresponding public key if this key is an asymmetric private key.
If this key is already public, PublicKey returns this key itself.

**Kind**: instance method of <code>[Key](#module_api.Key)</code>  
**Returns**: <code>Key</code> - the corresponding public key if this key is an asymmetric private key.
If this key is already public, PublicKey returns this key itself.  
<a name="module_api.Key+toBytes"></a>

#### key.toBytes() ⇒ <code>Array.&lt;byte&gt;</code>
Converts this key to its byte representation, if this operation is allowed.

**Kind**: instance method of <code>[Key](#module_api.Key)</code>  
**Returns**: <code>Array.&lt;byte&gt;</code> - the byte representation of the key  
<a name="Chain"></a>

## Chain
The class representing a chain with which the client SDK interacts.

The “Chain” object captures settings for a channel, which is created by
the orderers to isolate transactions delivery to peers participating on channel.
A chain must be initialized after it has been configured with the list of peers
and orderers. The initialization sends a get configuration block request to the
primary orderer to retrieve the configuration settings for this channel.

**Kind**: global class  

* [Chain](#Chain)
    * [new Chain(name, clientContext)](#new_Chain_new)
    * [.initialize()](#Chain+initialize)
    * [.getName()](#Chain+getName) ⇒ <code>string</code>
    * [.isSecurityEnabled()](#Chain+isSecurityEnabled)
    * [.isPreFetchMode()](#Chain+isPreFetchMode)
    * [.setPreFetchMode()](#Chain+setPreFetchMode)
    * [.isDevMode()](#Chain+isDevMode)
    * [.setDevMode()](#Chain+setDevMode)
    * [.getTCertBatchSize()](#Chain+getTCertBatchSize)
    * [.setTCertBatchSize()](#Chain+setTCertBatchSize)
    * [.getOrganizationUnits()](#Chain+getOrganizationUnits) ⇒ <code>Array.&lt;string&gt;</code>
    * [.setMSPManager(the)](#Chain+setMSPManager)
    * [.getMSPManager()](#Chain+getMSPManager) ⇒ <code>[MSPManager](#MSPManager)</code>
    * [.addPeer(peer)](#Chain+addPeer)
    * [.removePeer(peer)](#Chain+removePeer)
    * [.getPeers()](#Chain+getPeers) ⇒ <code>[Array.&lt;Peer&gt;](#Peer)</code>
    * [.setPrimaryPeer(peer)](#Chain+setPrimaryPeer)
    * [.getPrimaryPeer()](#Chain+getPrimaryPeer) ⇒ <code>[Peer](#Peer)</code>
    * [.addOrderer(orderer)](#Chain+addOrderer)
    * [.removeOrderer(orderer)](#Chain+removeOrderer)
    * [.getOrderers()](#Chain+getOrderers)
    * [.createChannel(request)](#Chain+createChannel) ⇒ <code>boolean</code>
    * [.joinChannel(request)](#Chain+joinChannel) ⇒ <code>Promise</code>
    * [.getChannelConfig()](#Chain+getChannelConfig) ⇒ <code>ConfigEnvelope</code>
    * [.updateChain()](#Chain+updateChain) ⇒ <code>boolean</code>
    * [.isReadonly()](#Chain+isReadonly) ⇒ <code>boolean</code>
    * [.queryInfo()](#Chain+queryInfo) ⇒ <code>object</code>
    * [.queryBlockByHash(block)](#Chain+queryBlockByHash) ⇒ <code>object</code>
    * [.queryBlock(blockNumber)](#Chain+queryBlock) ⇒ <code>object</code>
    * [.queryTransaction(transactionID)](#Chain+queryTransaction) ⇒ <code>object</code>
    * [.queryInstalledChaincodes(peer)](#Chain+queryInstalledChaincodes) ⇒ <code>object</code>
    * [.queryInstantiatedChaincodes()](#Chain+queryInstantiatedChaincodes) ⇒ <code>object</code>
    * [.queryChannels(peer)](#Chain+queryChannels) ⇒ <code>object</code>
    * [.sendInstallProposal(request)](#Chain+sendInstallProposal) ⇒ <code>Promise</code>
    * [.sendInstantiateProposal(request)](#Chain+sendInstantiateProposal) ⇒ <code>Promise</code>
    * [.sendTransactionProposal(request)](#Chain+sendTransactionProposal) ⇒ <code>Promise</code>
    * [.sendTransaction(proposalResponses, chaincodeProposal)](#Chain+sendTransaction) ⇒ <code>Promise</code>
    * [.queryByChaincode(request)](#Chain+queryByChaincode) ⇒ <code>Promise</code>
    * [.buildTransactionID(nonce, userContext)](#Chain+buildTransactionID) ⇒ <code>string</code>
    * [.buildTransactionID_getUserContext(nonce)](#Chain+buildTransactionID_getUserContext) ⇒ <code>Promise</code>
    * [.toString()](#Chain+toString)

<a name="new_Chain_new"></a>

### new Chain(name, clientContext)

| Param | Type | Description |
| --- | --- | --- |
| name | <code>string</code> | to identify different chain instances. The naming of chain instances is enforced by the ordering service and must be unique within the blockchain network |
| clientContext | <code>[Client](#Client)</code> | An instance of [Client](#Client) that provides operational context such as submitting User etc. |

<a name="Chain+initialize"></a>

### chain.initialize()
Retrieve the configuration from the primary orderer and initialize this chain (channel)
with those values. Currently only the MSP config value of the channel is loaded
into this chain.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
<a name="Chain+getName"></a>

### chain.getName() ⇒ <code>string</code>
Get the chain name.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>string</code> - The name of the chain.  
<a name="Chain+isSecurityEnabled"></a>

### chain.isSecurityEnabled()
Determine if security is enabled.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
<a name="Chain+isPreFetchMode"></a>

### chain.isPreFetchMode()
Determine if pre-fetch mode is enabled to prefetch tcerts.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
<a name="Chain+setPreFetchMode"></a>

### chain.setPreFetchMode()
Set prefetch mode to true or false.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
<a name="Chain+isDevMode"></a>

### chain.isDevMode()
Determine if dev mode is enabled.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
<a name="Chain+setDevMode"></a>

### chain.setDevMode()
Set dev mode to true or false.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
<a name="Chain+getTCertBatchSize"></a>

### chain.getTCertBatchSize()
Get the tcert batch size.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
<a name="Chain+setTCertBatchSize"></a>

### chain.setTCertBatchSize()
Set the tcert batch size.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
<a name="Chain+getOrganizationUnits"></a>

### chain.getOrganizationUnits() ⇒ <code>Array.&lt;string&gt;</code>
Get organizational unit identifiers from
the MSP's for this channel

**Kind**: instance method of <code>[Chain](#Chain)</code>  
<a name="Chain+setMSPManager"></a>

### chain.setMSPManager(the)
Set the MSP Manager for this channel
This utility method will not normally be use as the
`initialize()` method will read this channel's
current configuration and reset MSPManager with
the MSP's found.

**Kind**: instance method of <code>[Chain](#Chain)</code>  

| Param | Type | Description |
| --- | --- | --- |
| the | <code>[MSPManager](#MSPManager)</code> | msp manager for this channel |

<a name="Chain+getMSPManager"></a>

### chain.getMSPManager() ⇒ <code>[MSPManager](#MSPManager)</code>
Get the MSP Manager for this channel

**Kind**: instance method of <code>[Chain](#Chain)</code>  
<a name="Chain+addPeer"></a>

### chain.addPeer(peer)
Add peer endpoint to chain.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Throws**:

- <code>Error</code> if the peer with that url already exists.


| Param | Type | Description |
| --- | --- | --- |
| peer | <code>[Peer](#Peer)</code> | An instance of the Peer class that has been initialized with URL, TLC certificate, and enrollment certificate. |

<a name="Chain+removePeer"></a>

### chain.removePeer(peer)
Remove peer endpoint from chain.

**Kind**: instance method of <code>[Chain](#Chain)</code>  

| Param | Type | Description |
| --- | --- | --- |
| peer | <code>[Peer](#Peer)</code> | An instance of the Peer class. |

<a name="Chain+getPeers"></a>

### chain.getPeers() ⇒ <code>[Array.&lt;Peer&gt;](#Peer)</code>
Get peers of a chain from local information.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>[Array.&lt;Peer&gt;](#Peer)</code> - The peer list on the chain.  
<a name="Chain+setPrimaryPeer"></a>

### chain.setPrimaryPeer(peer)
Set the primary peer
The peer to use for doing queries.
Peer must be a peer on this chain's peer list.
Default: When no primary peer has been set the first peer
on the list will be used.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Throws**:

- Error when peer is not on the existing peer list


| Param | Type | Description |
| --- | --- | --- |
| peer | <code>[Peer](#Peer)</code> | An instance of the Peer class. |

<a name="Chain+getPrimaryPeer"></a>

### chain.getPrimaryPeer() ⇒ <code>[Peer](#Peer)</code>
Get the primary peer
The peer to use for doing queries.
Default: When no primary peer has been set the first peer
on the list will be used.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>[Peer](#Peer)</code> - peer An instance of the Peer class.  
<a name="Chain+addOrderer"></a>

### chain.addOrderer(orderer)
Add orderer endpoint to a chain object, this is a local-only operation.
A chain instance may choose to use a single orderer node, which will broadcast
requests to the rest of the orderer network. Or if the application does not trust
the orderer nodes, it can choose to use more than one by adding them to the chain instance.
All APIs concerning the orderer will broadcast to all orderers simultaneously.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Throws**:

- <code>Error</code> if the orderer with that url already exists.


| Param | Type | Description |
| --- | --- | --- |
| orderer | <code>[Orderer](#Orderer)</code> | An instance of the Orderer class. |

<a name="Chain+removeOrderer"></a>

### chain.removeOrderer(orderer)
Remove orderer endpoint from a chain object, this is a local-only operation.

**Kind**: instance method of <code>[Chain](#Chain)</code>  

| Param | Type | Description |
| --- | --- | --- |
| orderer | <code>[Orderer](#Orderer)</code> | An instance of the Orderer class. |

<a name="Chain+getOrderers"></a>

### chain.getOrderers()
Get orderers of a chain.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
<a name="Chain+createChannel"></a>

### chain.createChannel(request) ⇒ <code>boolean</code>
Calls the orderer(s) to start building the new chain.
Only one of the application instances needs to call this method.
Once the chain is successfully created, this and other application
instances only need to call joinChannel() to participate on the channel.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>boolean</code> - Whether the chain initialization process was successful.  

| Param | Type | Description |
| --- | --- | --- |
| request | <code>Object</code> | An object containing the following field: 		<br>`envelope` : required - byte[] of the envelope object containing                          all required settings to initialize this channel |

<a name="Chain+joinChannel"></a>

### chain.joinChannel(request) ⇒ <code>Promise</code>
Sends a join channel proposal to one or more endorsing peers
Will get the genesis block from the defined orderer to be used
in the proposal.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>Promise</code> - A Promise for a `ProposalResponse`  
**See**: /protos/peer/proposal_response.proto  

| Param | Type | Description |
| --- | --- | --- |
| request | <code>Object</code> | An object containing the following fields: 		<br>`targets` : required - An array of `Peer` objects that will join                      this channel 		<br>`txId` : required - String of the transaction id 		<br>`nonce` : required - Integer of the once time number |

<a name="Chain+getChannelConfig"></a>

### chain.getChannelConfig() ⇒ <code>ConfigEnvelope</code>
Queries for the current config block for this chain(channel).
This transaction will be made to the orderer.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>ConfigEnvelope</code> - Object containing the configuration items.  
**See**

- /protos/orderer/ab.proto
- /protos/common/configtx.proto

<a name="Chain+updateChain"></a>

### chain.updateChain() ⇒ <code>boolean</code>
Calls the orderer(s) to update an existing chain. This allows the addition and
deletion of Peer nodes to an existing chain, as well as the update of Peer
certificate information upon certificate renewals.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>boolean</code> - Whether the chain update process was successful.  
<a name="Chain+isReadonly"></a>

### chain.isReadonly() ⇒ <code>boolean</code>
Get chain status to see if the underlying channel has been terminated,
making it a read-only chain, where information (transactions and states)
can be queried but no new transactions can be submitted.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>boolean</code> - Is read-only, true or not.  
<a name="Chain+queryInfo"></a>

### chain.queryInfo() ⇒ <code>object</code>
Queries for various useful information on the state of the Chain
(height, known peers).
This query will be made to the primary peer.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>object</code> - With height, currently the only useful info.  
<a name="Chain+queryBlockByHash"></a>

### chain.queryBlockByHash(block) ⇒ <code>object</code>
Queries the ledger for Block by block hash.
This query will be made to the primary peer.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>object</code> - Object containing the block.  

| Param | Type | Description |
| --- | --- | --- |
| block | <code>Array.&lt;byte&gt;</code> | hash of the Block. |

<a name="Chain+queryBlock"></a>

### chain.queryBlock(blockNumber) ⇒ <code>object</code>
Queries the ledger for Block by block number.
This query will be made to the primary peer.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>object</code> - Object containing the block.  

| Param | Type | Description |
| --- | --- | --- |
| blockNumber | <code>number</code> | The number which is the ID of the Block. |

<a name="Chain+queryTransaction"></a>

### chain.queryTransaction(transactionID) ⇒ <code>object</code>
Queries the ledger for Transaction by number.
This query will be made to the primary peer.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>object</code> - Transaction information containing the transaction.  

| Param | Type |
| --- | --- |
| transactionID | <code>number</code> | 

<a name="Chain+queryInstalledChaincodes"></a>

### chain.queryInstalledChaincodes(peer) ⇒ <code>object</code>
Queries the installed chaincodes on a peer
returning the details of all chaincodes
installed on a peer.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>object</code> - ChaincodeQueryResponse proto  

| Param | Type |
| --- | --- |
| peer | <code>[Peer](#Peer)</code> | 

<a name="Chain+queryInstantiatedChaincodes"></a>

### chain.queryInstantiatedChaincodes() ⇒ <code>object</code>
Queries the instantiated chaincodes on this channel.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>object</code> - ChaincodeQueryResponse proto  
<a name="Chain+queryChannels"></a>

### chain.queryChannels(peer) ⇒ <code>object</code>
Queries the names of all the channels that a
peer has joined.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>object</code> - ChannelQueryResponse proto  

| Param | Type |
| --- | --- |
| peer | <code>[Peer](#Peer)</code> | 

<a name="Chain+sendInstallProposal"></a>

### chain.sendInstallProposal(request) ⇒ <code>Promise</code>
Sends an install proposal to one or more endorsing peers.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>Promise</code> - A Promise for a `ProposalResponse`  
**See**: /protos/peer/proposal_response.proto  

| Param | Type | Description |
| --- | --- | --- |
| request | <code>Object</code> | An object containing the following fields: 		<br>`chaincodePath` : required - String of the path to location of                            the source code of the chaincode 		<br>`chaincodeId` : required - String of the name of the chaincode 		<br>`chaincodeVersion` : required - String of the version of the chaincode 		<br>`chaincodePackage` : optional - Byte array of the archive content for                               the chaincode source. The archive must have a 'src'                               folder containing subfolders corresponding to the                               'chaincodePath' field. For instance, if the chaincodePath                               is 'mycompany/myproject', then the archive must contain a                               folder at the path 'src/mycompany/myproject', where the                               GO source code resides. 		<br>`chaincodeType` : optional - Type of chaincode ['golang', 'car', 'java']                   (default 'golang') 		<br>`txId` : required - String of the transaction id 		<br>`nonce` : required - Integer of the once time number |

<a name="Chain+sendInstantiateProposal"></a>

### chain.sendInstantiateProposal(request) ⇒ <code>Promise</code>
Sends an instantiate proposal to one or more endorsing peers.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>Promise</code> - A Promise for a `ProposalResponse`  
**See**: /protos/peer/proposal_response.proto  

| Param | Type | Description |
| --- | --- | --- |
| request | <code>Object</code> | An object containing the following fields: 		<br>`chaincodeType` : optional -- Type of chaincode ['golang', 'car', 'java']                            (default 'golang') 		<br>`chaincodePath` : required - String of the path to location of                            the source code of the chaincode 		<br>`chaincodeId` : required - String of the name of the chaincode 		<br>`chaincodeVersion` : required - String of the version of the chaincode 		<br>`chainId` : required - String of the name of the chain 		<br>`txId` : required - String of the transaction id 		<br>`nonce` : required - Integer of the once time number 		<br>`fcn` : optional - String of the function to be called on                  the chaincode once instantiated (default 'init') 		<br>`args` : optional - String Array arguments specific to                   the chaincode being instantiated |

<a name="Chain+sendTransactionProposal"></a>

### chain.sendTransactionProposal(request) ⇒ <code>Promise</code>
Sends a transaction proposal to one or more endorsing peers.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>Promise</code> - A Promise for a `ProposalResponse`  

| Param | Type | Description |
| --- | --- | --- |
| request | <code>Object</code> | <br>`chaincodeId` : The id of the chaincode to perform the transaction proposal 		<br>`chainId` : required - String of the name of the chain 		<br>`txId` : required - String of the transaction id 		<br>`nonce` : required - Integer of the once time number 		<br>`args` : an array of arguments specific to the chaincode 'invoke' |

<a name="Chain+sendTransaction"></a>

### chain.sendTransaction(proposalResponses, chaincodeProposal) ⇒ <code>Promise</code>
Sends the orderer an endorsed proposal.
The caller must use the proposal response returned from the endorser along
with the original proposal request sent to the endorser.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>Promise</code> - A Promise for a `BroadcastResponse`.
        This will be an acknowledgement from the orderer of successfully submitted transaction.  
**See**

- /protos/peer/proposal_response.proto
- /protos/peer/proposal.proto
- /protos/orderer/ab.proto


| Param | Type | Description |
| --- | --- | --- |
| proposalResponses | <code>Array</code> | An array or single {ProposalResponse} objects containing        the response from the endorsement |
| chaincodeProposal | <code>Proposal</code> | A Proposal object containing the original        request for endorsement(s) |

<a name="Chain+queryByChaincode"></a>

### chain.queryByChaincode(request) ⇒ <code>Promise</code>
Sends a proposal to one or more endorsing peers that will be handled by the chaincode.
This request will be presented to the chaincode 'invoke' and must understand
from the arguments that this is a query request. The chaincode must also return
results in the byte array format and the caller will have to be able to decode
these results

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>Promise</code> - A Promise for an array of byte array results from the chaincode on all Endorsing Peers  

| Param | Type | Description |
| --- | --- | --- |
| request | <code>Object</code> | A JSON object with the following 		<br>targets : An array or single Endorsing [Peer](#Peer) objects as the targets of the request 		<br>chaincodeId : The id of the chaincode to perform the query 		<br>`args` : an array of arguments specific to the chaincode 'innvoke'             that represent a query invocation on that chaincode |

<a name="Chain+buildTransactionID"></a>

### chain.buildTransactionID(nonce, userContext) ⇒ <code>string</code>
Utility method to build an unique transaction id
based on a nonce and this chain's user.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>string</code> - An unique string  

| Param | Type | Description |
| --- | --- | --- |
| nonce | <code>int</code> | a one time use number |
| userContext | <code>[User](#User)</code> | the user context |

<a name="Chain+buildTransactionID_getUserContext"></a>

### chain.buildTransactionID_getUserContext(nonce) ⇒ <code>Promise</code>
Utility method to build an unique transaction id
based on a nonce and this chain's user.
Gets the user context.

**Kind**: instance method of <code>[Chain](#Chain)</code>  
**Returns**: <code>Promise</code> - A promise for the transaction id  

| Param | Type | Description |
| --- | --- | --- |
| nonce | <code>int</code> | a one time use number |

<a name="Chain+toString"></a>

### chain.toString()
return a printable representation of this object

**Kind**: instance method of <code>[Chain](#Chain)</code>  
<a name="Client"></a>

## Client
Main interaction handler with end user. A client instance provides a handler to interact
with a network of peers, orderers and optionally member services. An application using the
SDK may need to interact with multiple networks, each through a separate instance of the Client.

Each client when initially created should be initialized with configuration data from the
consensus service, which includes a list of trusted roots, orderer certificates and IP addresses,
and a list of peer certificates and IP addresses that it can access. This must be done out of band
as part of bootstrapping the application environment. It is also the responsibility of the application
to maintain the configuration of a client as the SDK does not persist this object.

Each Client instance can maintain several [Chain](#Chain) instances representing channels and the associated
private ledgers.

**Kind**: global class  

* [Client](#Client)
    * _instance_
        * [.newChain(name)](#Client+newChain) ⇒ <code>[Chain](#Chain)</code>
        * [.getChain(name)](#Client+getChain) ⇒ <code>[Chain](#Chain)</code>
        * [.queryChainInfo(name, peers)](#Client+queryChainInfo) ⇒ <code>[Chain](#Chain)</code>
        * [.setStateStore(keyValueStore)](#Client+setStateStore)
        * [.saveUserToStateStore()](#Client+saveUserToStateStore) ⇒ <code>Promise</code>
        * [.setUserContext(user, skipPersistence)](#Client+setUserContext) ⇒ <code>Promise</code>
        * [.getUserContext(name)](#Client+getUserContext) ⇒ <code>Promise</code>
        * [.loadUserFromStateStore()](#Client+loadUserFromStateStore) ⇒ <code>Promise</code>
        * [.getStateStore()](#Client+getStateStore) ⇒ <code>[KeyValueStore](#KeyValueStore)</code>
    * _static_
        * [.newDefaultKeyValueStore(options)](#Client.newDefaultKeyValueStore) ⇒
        * [.setLogger(logger)](#Client.setLogger)
        * [.addConfigFile(path)](#Client.addConfigFile)
        * [.setConfigSetting(name, value)](#Client.setConfigSetting)
        * [.getConfigSetting(name, default_value)](#Client.getConfigSetting)

<a name="Client+newChain"></a>

### client.newChain(name) ⇒ <code>[Chain](#Chain)</code>
Returns a chain instance with the given name. This represents a channel and its associated ledger
(as explained above), and this call returns an empty object. To initialize the chain in the blockchain network,
a list of participating endorsers and orderer peers must be configured first on the returned object.

**Kind**: instance method of <code>[Client](#Client)</code>  
**Returns**: <code>[Chain](#Chain)</code> - The uninitialized chain instance.  
**Throws**:

- <code>Error</code> if the chain by that name already exists in the application's state store


| Param | Type | Description |
| --- | --- | --- |
| name | <code>string</code> | The name of the chain.  Recommend using namespaces to avoid collision. |

<a name="Client+getChain"></a>

### client.getChain(name) ⇒ <code>[Chain](#Chain)</code>
Get a [Chain](#Chain) instance from the state storage. This allows existing chain instances to be saved
for retrieval later and to be shared among instances of the application. Note that it’s the
application/SDK’s responsibility to record the chain information. If an application is not able
to look up the chain information from storage, it may call another API that queries one or more
Peers for that information.

**Kind**: instance method of <code>[Client](#Client)</code>  
**Returns**: <code>[Chain](#Chain)</code> - The chain instance  
**Throws**:

- <code>Error</code> if the state store has not been set or a chain does not exist under that name.


| Param | Type | Description |
| --- | --- | --- |
| name | <code>string</code> | The name of the chain. |

<a name="Client+queryChainInfo"></a>

### client.queryChainInfo(name, peers) ⇒ <code>[Chain](#Chain)</code>
This is a network call to the designated Peer(s) to discover the chain information.
The target Peer(s) must be part of the chain to be able to return the requested information.

**Kind**: instance method of <code>[Client](#Client)</code>  
**Returns**: <code>[Chain](#Chain)</code> - The chain instance for the name or error if the target Peer(s) does not know
anything about the chain.  

| Param | Type | Description |
| --- | --- | --- |
| name | <code>string</code> | The name of the chain. |
| peers | <code>[Array.&lt;Peer&gt;](#Peer)</code> | Array of target Peers to query. |

<a name="Client+setStateStore"></a>

### client.setStateStore(keyValueStore)
The enrollment materials for Users that have appeared in the instances of the application.

The SDK should have a built-in key value store file-based implementation to allow easy setup during
development. Production systems would use a store backed by database for more robust storage and
clustering, so that multiple app instances can share app state via the database.
This API makes this pluggable so that different store implementations can be selected by the application.

**Kind**: instance method of <code>[Client](#Client)</code>  

| Param | Type | Description |
| --- | --- | --- |
| keyValueStore | <code>[KeyValueStore](#KeyValueStore)</code> | Instance of an alternative KeyValueStore implementation provided by the consuming app. |

<a name="Client+saveUserToStateStore"></a>

### client.saveUserToStateStore() ⇒ <code>Promise</code>
Save the state of this member to the key value store.

**Kind**: instance method of <code>[Client](#Client)</code>  
**Returns**: <code>Promise</code> - A Promise for the user context object upon successful save  
<a name="Client+setUserContext"></a>

### client.setUserContext(user, skipPersistence) ⇒ <code>Promise</code>
Sets an instance of the User class as the security context of self client instance. This user’s
credentials (ECert), or special transaction certificates that are derived from the user's ECert,
will be used to conduct transactions and queries with the blockchain network.
Upon setting the user context, the SDK saves the object in a persistence cache if the “state store”
has been set on the Client instance. If no state store has been set, this cache will not be established
and the application is responsible for setting the user context again if the application crashes and is recovered.

**Kind**: instance method of <code>[Client](#Client)</code>  
**Returns**: <code>Promise</code> - Promise of the 'user' object upon successful persistence of the user to the state store  

| Param | Type | Description |
| --- | --- | --- |
| user | <code>[User](#User)</code> | An instance of the User class encapsulating the authenticated user’s signing materials (private key and enrollment certificate) |
| skipPersistence | <code>boolean</code> | Whether to skip saving the user object into persistence. Default is false and the method will attempt to save the user object to the state store. |

<a name="Client+getUserContext"></a>

### client.getUserContext(name) ⇒ <code>Promise</code>
As explained above, the client instance can have an optional state store. The SDK saves enrolled users
in the storage which can be accessed by authorized users of the application (authentication is done by
the application outside of the SDK). This function attempts to load the user by name from the local storage
(via the KeyValueStore interface). The loaded user object must represent an enrolled user with a valid
enrollment certificate signed by a trusted CA (such as the CA server).

**Kind**: instance method of <code>[Client](#Client)</code>  
**Returns**: <code>Promise</code> - The user object corresponding to the name, or null if the user does not exist or if the
state store has not been set.  

| Param | Type | Description |
| --- | --- | --- |
| name | <code>String</code> | Optional. If not specified, will only return the in-memory user context object, or null if not found in memory. If "name" is specified, will also attempt to load it from the state store if search in memory failed. |

<a name="Client+loadUserFromStateStore"></a>

### client.loadUserFromStateStore() ⇒ <code>Promise</code>
Restore the state of this member from the key value store (if found).  If not found, do nothing.

**Kind**: instance method of <code>[Client](#Client)</code>  
**Returns**: <code>Promise</code> - A Promise for a {User} object upon successful restore, or if the user by the name
does not exist in the state store, returns null without rejecting the promise  
<a name="Client+getStateStore"></a>

### client.getStateStore() ⇒ <code>[KeyValueStore](#KeyValueStore)</code>
A convenience method for obtaining the state store object in use for this client.

**Kind**: instance method of <code>[Client](#Client)</code>  
**Returns**: <code>[KeyValueStore](#KeyValueStore)</code> - The KeyValueStore implementation object set within this Client, or null if it does not exist.  
<a name="Client.newDefaultKeyValueStore"></a>

### Client.newDefaultKeyValueStore(options) ⇒
Obtains an instance of the [KeyValueStore](#module_api.KeyValueStore) class. By default
it returns the built-in implementation, which is based on files ([FileKeyValueStore](module:api.FileKeyValueStore)).
This can be overriden with an environment variable KEY_VALUE_STORE, the value of which is the
full path of a CommonJS module for the alternative implementation.

**Kind**: static method of <code>[Client](#Client)</code>  
**Returns**: [KeyValueStore](#module_api.KeyValueStore) an instance of the KeyValueStore implementation  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>Object</code> | is whatever the implementation requires for initializing the instance. For the built-in file-based implementation, this requires a single property "path" to the top-level folder for the store |

<a name="Client.setLogger"></a>

### Client.setLogger(logger)
Configures a logger for the entire HFC SDK to use and override the default logger. Unless this method is called,
HFC uses a default logger (based on winston). When using the built-in "winston" based logger, use the environment
variable HFC_LOGGING to pass in configurations in the following format:

{
  'error': 'error.log',				// 'error' logs are printed to file 'error.log' relative of the current working dir for node.js
  'debug': '/tmp/myapp/debug.log',	// 'debug' and anything more critical ('info', 'warn', 'error') can also be an absolute path
  'info': 'console'					// 'console' is a keyword for logging to console
}

**Kind**: static method of <code>[Client](#Client)</code>  

| Param | Type | Description |
| --- | --- | --- |
| logger | <code>Object</code> | a logger instance that defines the following methods: debug(), info(), warn(), error() with string interpolation methods like [util.format](https://nodejs.org/api/util.html#util_util_format_format). |

<a name="Client.addConfigFile"></a>

### Client.addConfigFile(path)
Adds a file to the top of the list of configuration setting files that are
part of the hierarchical configuration.
These files will override the default settings and be overriden by environment,
command line arguments, and settings programmatically set into configuration settings.

hierarchy search order:
 1. memory - all settings added with sdkUtils.setConfigSetting(name,value)
 2. Command-line arguments
 3. Environment variables (names will be change from AAA-BBB to aaa-bbb)
 4. Custom Files - all files added with the addConfigFile(path)
    will be ordered by when added, were last one added will override previously added files
 5. The file located at 'config/default.json' with default settings

**Kind**: static method of <code>[Client](#Client)</code>  

| Param | Type | Description |
| --- | --- | --- |
| path | <code>String</code> | The path to the file to be added to the top of list of configuration files |

<a name="Client.setConfigSetting"></a>

### Client.setConfigSetting(name, value)
Adds a setting to override all settings that are
part of the hierarchical configuration.

hierarchy search order:
 1. memory - settings added with this call
 2. Command-line arguments
 3. Environment variables (names will be change from AAA-BBB to aaa-bbb)
 4. Custom Files - all files added with the addConfigFile(path)
    will be ordered by when added, were last one added will override previously added files
 5. The file located at 'config/default.json' with default settings

**Kind**: static method of <code>[Client](#Client)</code>  

| Param | Type | Description |
| --- | --- | --- |
| name | <code>String</code> | The name of a setting |
| value | <code>Object</code> | The value of a setting |

<a name="Client.getConfigSetting"></a>

### Client.getConfigSetting(name, default_value)
Retrieves a setting from the hierarchical configuration and if not found
will return the provided default value.

hierarchy search order:
 1. memory - settings added with sdkUtils.setConfigSetting(name,value)
 2. Command-line arguments
 3. Environment variables (names will be change from AAA-BBB to aaa-bbb)
 4. Custom Files - all files added with the addConfigFile(path)
    will be ordered by when added, were last one added will override previously added files
 5. The file located at 'config/default.json' with default settings

**Kind**: static method of <code>[Client](#Client)</code>  

| Param | Type | Description |
| --- | --- | --- |
| name | <code>String</code> | The name of a setting |
| default_value | <code>Object</code> | The value of a setting if not found in the hierarchical configuration |

<a name="ChainCodeCBE"></a>

## ChainCodeCBE
The ChainCodeCBE is used internal to the EventHub to hold chaincode
event registration callbacks.

**Kind**: global class  
<a name="new_ChainCodeCBE_new"></a>

### new ChainCodeCBE(ccid, eventNameFilter, cb)
Constructs a chaincode callback entry


| Param | Type | Description |
| --- | --- | --- |
| ccid | <code>string</code> | chaincode id |
| eventNameFilter | <code>string</code> | The regex used to filter events |
| cb | <code>function</code> | Callback for filter matches |

<a name="EventHub"></a>

## EventHub
The EventHub class is used to distribute events from an
event source(peer)

**Kind**: global class  

* [EventHub](#EventHub)
    * [new EventHub()](#new_EventHub_new)
    * [.setPeerAddr(peeraddr, opts)](#EventHub+setPeerAddr)
    * [.isconnected()](#EventHub+isconnected) ⇒
    * [.connect()](#EventHub+connect)
    * [.disconnect()](#EventHub+disconnect)
    * [.registerChaincodeEvent(ccid, eventname, callback)](#EventHub+registerChaincodeEvent) ⇒ <code>object</code>
    * [.unregisterChaincodeEvent(ChainCodeCBE)](#EventHub+unregisterChaincodeEvent)
    * [.registerBlockEvent(callback)](#EventHub+registerBlockEvent)
    * [.unregisterBlockEvent(callback)](#EventHub+unregisterBlockEvent)
    * [.registerTxEvent(txid, callback)](#EventHub+registerTxEvent)
    * [.unregisterTxEvent(txid)](#EventHub+unregisterTxEvent)
    * [.txCallback(block)](#EventHub+txCallback)

<a name="new_EventHub_new"></a>

### new EventHub()
Constructs an unconnected EventHub

<a name="EventHub+setPeerAddr"></a>

### eventHub.setPeerAddr(peeraddr, opts)
Set peer url for event source<p>
Note: Only use this if creating your own EventHub. The chain
class creates a default eventHub that most Node clients can
use (see eventHubConnect, eventHubDisconnect and getEventHub).

**Kind**: instance method of <code>[EventHub](#EventHub)</code>  

| Param | Type | Description |
| --- | --- | --- |
| peeraddr | <code>string</code> | peer url |
| opts | <code>object</code> | An Object that may contain options to pass to grpcs calls <br>- pem {string} The certificate file, in PEM format,    to use with the gRPC protocol (that is, with TransportCredentials).    Required when using the grpcs protocol. <br>- ssl-target-name-override {string} Used in test environment only, when the server certificate's    hostname (in the 'CN' field) does not match the actual host endpoint that the server process runs    at, the application can work around the client TLS verify failure by setting this property to the    value of the server certificate's hostname <br>- any other standard grpc call options will be passed to the grpc service calls directly |

<a name="EventHub+isconnected"></a>

### eventHub.isconnected() ⇒
Get connected state of eventhub

**Kind**: instance method of <code>[EventHub](#EventHub)</code>  
**Returns**: true if connected to event source, false otherwise  
<a name="EventHub+connect"></a>

### eventHub.connect()
Establishes connection with peer event source<p>
Note: Only use this if creating your own EventHub. The chain
class creates a default eventHub that most Node clients can
use (see eventHubConnect, eventHubDisconnect and getEventHub).

**Kind**: instance method of <code>[EventHub](#EventHub)</code>  
<a name="EventHub+disconnect"></a>

### eventHub.disconnect()
Disconnects peer event source<p>
Note: Only use this if creating your own EventHub. The chain
class creates a default eventHub that most Node clients can
use (see eventHubConnect, eventHubDisconnect and getEventHub).

**Kind**: instance method of <code>[EventHub](#EventHub)</code>  
<a name="EventHub+registerChaincodeEvent"></a>

### eventHub.registerChaincodeEvent(ccid, eventname, callback) ⇒ <code>object</code>
Register a callback function to receive chaincode events.

**Kind**: instance method of <code>[EventHub](#EventHub)</code>  
**Returns**: <code>object</code> - ChainCodeCBE object that should be treated as an opaque
handle used to unregister (see unregisterChaincodeEvent)  

| Param | Type | Description |
| --- | --- | --- |
| ccid | <code>string</code> | string chaincode id |
| eventname | <code>string</code> | string The regex string used to filter events |
| callback | <code>function</code> | Function Callback function for filter matches that takes a single parameter which is a json object representation of type "message ChaincodeEvent" from lib/proto/chaincodeevent.proto |

<a name="EventHub+unregisterChaincodeEvent"></a>

### eventHub.unregisterChaincodeEvent(ChainCodeCBE)
Unregister chaincode event registration

**Kind**: instance method of <code>[EventHub](#EventHub)</code>  

| Param | Type | Description |
| --- | --- | --- |
| ChainCodeCBE | <code>object</code> | handle returned from call to registerChaincodeEvent. |

<a name="EventHub+registerBlockEvent"></a>

### eventHub.registerBlockEvent(callback)
Register a callback function to receive block events.

**Kind**: instance method of <code>[EventHub](#EventHub)</code>  

| Param | Type | Description |
| --- | --- | --- |
| callback | <code>function</code> | Function that takes a single parameter which is a json object representation of type "message Block" from lib/proto/fabric.proto |

<a name="EventHub+unregisterBlockEvent"></a>

### eventHub.unregisterBlockEvent(callback)
Unregister block event registration

**Kind**: instance method of <code>[EventHub](#EventHub)</code>  

| Param | Type | Description |
| --- | --- | --- |
| callback | <code>function</code> | Function to unregister |

<a name="EventHub+registerTxEvent"></a>

### eventHub.registerTxEvent(txid, callback)
Register a callback function to receive transactional events.<p>
Note: transactional event registration is primarily used by
the sdk to track instantiate and invoke completion events. Nodejs
clients generally should not need to call directly.

**Kind**: instance method of <code>[EventHub](#EventHub)</code>  

| Param | Type | Description |
| --- | --- | --- |
| txid | <code>string</code> | string transaction id |
| callback | <code>function</code> | Function that takes a parameter which is a json object representation of type "message Transaction" from lib/proto/fabric.proto and a parameter which is a boolean that indicates if the transaction is invalid (true=invalid) |

<a name="EventHub+unregisterTxEvent"></a>

### eventHub.unregisterTxEvent(txid)
Unregister transactional event registration.

**Kind**: instance method of <code>[EventHub](#EventHub)</code>  

| Param | Description |
| --- | --- |
| txid | string transaction id |

<a name="EventHub+txCallback"></a>

### eventHub.txCallback(block)
private internal callback for processing tx events

**Kind**: instance method of <code>[EventHub](#EventHub)</code>  

| Param | Type | Description |
| --- | --- | --- |
| block | <code>object</code> | json object representing block of tx from the fabric |

<a name="CouchDBKeyValueStore"></a>

## CouchDBKeyValueStore
This is a sample database implementation of the [KeyValueStore](#module_api.KeyValueStore) API.
It uses a local or remote CouchDB database instance to store the keys.

**Kind**: global class  
<a name="new_CouchDBKeyValueStore_new"></a>

### new CouchDBKeyValueStore(options)
constructor


| Param | Type | Description |
| --- | --- | --- |
| options | <code>Object</code> | Contains the properties: <li>url - The CouchDB instance url. <li>name - Optional.  Identifies the name of the database if different from the default of 'member_db'. |

<a name="CryptoSuite_ECDSA_AES"></a>

## CryptoSuite_ECDSA_AES
The [CryptoSuite](#module_api.CryptoSuite) implementation for ECDSA, and AES algorithms using software key generation.
This class implements a software-based key generation (as opposed to Hardware Security Module based key management)

**Kind**: global class  

* [CryptoSuite_ECDSA_AES](#CryptoSuite_ECDSA_AES)
    * [new CryptoSuite_ECDSA_AES(keySize, opts, KVSImplClass, hash)](#new_CryptoSuite_ECDSA_AES_new)
    * [.generateKey()](#CryptoSuite_ECDSA_AES+generateKey) ⇒ <code>Key</code>
    * [.deriveKey()](#CryptoSuite_ECDSA_AES+deriveKey)
    * [.importKey()](#CryptoSuite_ECDSA_AES+importKey)
    * [.getKey()](#CryptoSuite_ECDSA_AES+getKey)
    * [.hash()](#CryptoSuite_ECDSA_AES+hash)
    * [.sign()](#CryptoSuite_ECDSA_AES+sign)
    * [.verify()](#CryptoSuite_ECDSA_AES+verify)
    * [.encrypt()](#CryptoSuite_ECDSA_AES+encrypt)
    * [.decrypt()](#CryptoSuite_ECDSA_AES+decrypt)

<a name="new_CryptoSuite_ECDSA_AES_new"></a>

### new CryptoSuite_ECDSA_AES(keySize, opts, KVSImplClass, hash)
constructor


| Param | Type | Description |
| --- | --- | --- |
| keySize | <code>number</code> | Key size for the ECDSA algorithm, can only be 256 or 384 |
| opts | <code>object</code> | Implementation-specific options object for the [KeyValueStore](#KeyValueStore) class to instantiate an instance |
| KVSImplClass | <code>string</code> | Optional. The built-in key store saves private keys. The key store may be backed by different [KeyValueStore](#KeyValueStore) implementations. If specified, the value of the argument must point to a module implementing the KeyValueStore interface. |
| hash | <code>string</code> | Optional. Hash algorithm, supported values are "SHA2" and "SHA3" |

<a name="CryptoSuite_ECDSA_AES+generateKey"></a>

### cryptoSuite_ECDSA_AES.generateKey() ⇒ <code>Key</code>
This is an implementation of [generateKey](#module_api.CryptoSuite+generateKey)
Returns an instance of [module.api.Key](module.api.Key) representing the private key, which also
encapsulates the public key. It'll also save the private key in the KeyValueStore

**Kind**: instance method of <code>[CryptoSuite_ECDSA_AES](#CryptoSuite_ECDSA_AES)</code>  
**Returns**: <code>Key</code> - Promise of an instance of [module:ECDSA_KEY](module:ECDSA_KEY) containing the private key and the public key  
<a name="CryptoSuite_ECDSA_AES+deriveKey"></a>

### cryptoSuite_ECDSA_AES.deriveKey()
This is an implementation of [deriveKey](#module_api.CryptoSuite+deriveKey)
To be implemented

**Kind**: instance method of <code>[CryptoSuite_ECDSA_AES](#CryptoSuite_ECDSA_AES)</code>  
<a name="CryptoSuite_ECDSA_AES+importKey"></a>

### cryptoSuite_ECDSA_AES.importKey()
This is an implementation of [importKey](#module_api.CryptoSuite+importKey)

**Kind**: instance method of <code>[CryptoSuite_ECDSA_AES](#CryptoSuite_ECDSA_AES)</code>  
<a name="CryptoSuite_ECDSA_AES+getKey"></a>

### cryptoSuite_ECDSA_AES.getKey()
This is an implementation of [getKey](#module_api.CryptoSuite+getKey)
Returns the key this CSP associates to the Subject Key Identifier ski.

**Kind**: instance method of <code>[CryptoSuite_ECDSA_AES](#CryptoSuite_ECDSA_AES)</code>  
<a name="CryptoSuite_ECDSA_AES+hash"></a>

### cryptoSuite_ECDSA_AES.hash()
This is an implementation of [hash](#module_api.CryptoSuite+hash)
Hashes messages msg using options opts.

**Kind**: instance method of <code>[CryptoSuite_ECDSA_AES](#CryptoSuite_ECDSA_AES)</code>  
<a name="CryptoSuite_ECDSA_AES+sign"></a>

### cryptoSuite_ECDSA_AES.sign()
This is an implementation of [sign](#module_api.CryptoSuite+sign)
Signs digest using key k.

The opts argument is not needed.

**Kind**: instance method of <code>[CryptoSuite_ECDSA_AES](#CryptoSuite_ECDSA_AES)</code>  
<a name="CryptoSuite_ECDSA_AES+verify"></a>

### cryptoSuite_ECDSA_AES.verify()
This is an implementation of [verify](#module_api.CryptoSuite+verify)
Verifies signature against key k and digest
The opts argument should be appropriate for the algorithm used.

**Kind**: instance method of <code>[CryptoSuite_ECDSA_AES](#CryptoSuite_ECDSA_AES)</code>  
<a name="CryptoSuite_ECDSA_AES+encrypt"></a>

### cryptoSuite_ECDSA_AES.encrypt()
This is an implementation of [encrypt](#module_api.CryptoSuite+encrypt)
Encrypts plaintext using key k.
The opts argument should be appropriate for the algorithm used.

**Kind**: instance method of <code>[CryptoSuite_ECDSA_AES](#CryptoSuite_ECDSA_AES)</code>  
<a name="CryptoSuite_ECDSA_AES+decrypt"></a>

### cryptoSuite_ECDSA_AES.decrypt()
This is an implementation of [decrypt](#module_api.CryptoSuite+decrypt)
Decrypts ciphertext using key k.
The opts argument should be appropriate for the algorithm used.

**Kind**: instance method of <code>[CryptoSuite_ECDSA_AES](#CryptoSuite_ECDSA_AES)</code>  
<a name="KeyValueStore"></a>

## KeyValueStore
This is a default implementation of the [KeyValueStore](#module_api.KeyValueStore) API.
It uses files to store the key values.

**Kind**: global class  
<a name="new_KeyValueStore_new"></a>

### new KeyValueStore(options)
constructor


| Param | Type | Description |
| --- | --- | --- |
| options | <code>Object</code> | contains a single property 'path' which points to the top-level directory for the store |

<a name="Identity"></a>

## Identity
This interface is shared within the peer and client API of the membership service provider.
Identity interface defines operations associated to a "certificate".
That is, the public part of the identity could be thought to be a certificate,
and offers solely signature verification capabilities. This is to be used
at the client side when validating certificates that endorsements are signed
with, and verifying signatures that correspond to these certificates.

**Kind**: global class  

* [Identity](#Identity)
    * [new Identity(id, certificate, publicKey, msp)](#new_Identity_new)
    * [.getId()](#Identity+getId) ⇒ <code>string</code>
    * [.getMSPId()](#Identity+getMSPId) ⇒ <code>string</code>
    * [.isValid()](#Identity+isValid) ⇒ <code>boolean</code>
    * [.getOrganizationUnits()](#Identity+getOrganizationUnits) ⇒ <code>string</code>
    * [.verify(msg, signature, opts)](#Identity+verify)
    * [.verifyAttributes()](#Identity+verifyAttributes)
    * [.serialize()](#Identity+serialize) ⇒ <code>Buffer</code>

<a name="new_Identity_new"></a>

### new Identity(id, certificate, publicKey, msp)

| Param | Type | Description |
| --- | --- | --- |
| id | <code>string</code> | Identifier of this identity object |
| certificate | <code>string</code> | HEX string for the PEM encoded certificate |
| publicKey | <code>Key</code> | The public key represented by the certificate |
| msp | <code>[MSP](#MSP)</code> | The associated MSP that manages this identity |

<a name="Identity+getId"></a>

### identity.getId() ⇒ <code>string</code>
Returns the identifier of this identity

**Kind**: instance method of <code>[Identity](#Identity)</code>  
<a name="Identity+getMSPId"></a>

### identity.getMSPId() ⇒ <code>string</code>
Returns the identifier of the Membser Service Provider that manages
this identity in terms of being able to understand the key algorithms
and have access to the trusted roots needed to validate it

**Kind**: instance method of <code>[Identity](#Identity)</code>  
<a name="Identity+isValid"></a>

### identity.isValid() ⇒ <code>boolean</code>
This uses the rules that govern this identity to validate it.
E.g., if it is a fabric TCert implemented as identity, validate
will check the TCert signature against the assumed root certificate
authority.

**Kind**: instance method of <code>[Identity](#Identity)</code>  
<a name="Identity+getOrganizationUnits"></a>

### identity.getOrganizationUnits() ⇒ <code>string</code>
Returns the organization units this identity is related to
as long as this is public information. In certain implementations
this could be implemented by certain attributes that are publicly
associated to that identity, or the identifier of the root certificate
authority that has provided signatures on this certificate.
Examples:
 - OrganizationUnit of a fabric-tcert that was signed by TCA under name
   "Organization 1", would be "Organization 1".
 - OrganizationUnit of an alternative implementation of tcert signed by a public
   CA used by organization "Organization 1", could be provided in the clear
   as part of that tcert structure that this call would be able to return.

**Kind**: instance method of <code>[Identity](#Identity)</code>  
<a name="Identity+verify"></a>

### identity.verify(msg, signature, opts)
Verify a signature over some message using this identity as reference

**Kind**: instance method of <code>[Identity](#Identity)</code>  

| Param | Type | Description |
| --- | --- | --- |
| msg | <code>Array.&lt;byte&gt;</code> | The message to be verified |
| signature | <code>Array.&lt;byte&gt;</code> | The signature generated against the message "msg" |
| opts | <code>Object</code> | Options include 'policy' and 'label' |

<a name="Identity+verifyAttributes"></a>

### identity.verifyAttributes()
Verify attributes against the given attribute spec
TODO: when this method's design is finalized

**Kind**: instance method of <code>[Identity](#Identity)</code>  
<a name="Identity+serialize"></a>

### identity.serialize() ⇒ <code>Buffer</code>
Converts this identity to bytes

**Kind**: instance method of <code>[Identity](#Identity)</code>  
**Returns**: <code>Buffer</code> - protobuf-based serialization with two fields: "mspid" and "certificate PEM bytes"  
<a name="Signer"></a>

## Signer
Signer is an interface for an opaque private key that can be used for signing operations

**Kind**: global class  

* [Signer](#Signer)
    * [new Signer(cryptoSuite, key)](#new_Signer_new)
    * [.getPublicKey()](#Signer+getPublicKey) ⇒ <code>Key</code>
    * [.sign(digest, opts)](#Signer+sign)

<a name="new_Signer_new"></a>

### new Signer(cryptoSuite, key)

| Param | Type | Description |
| --- | --- | --- |
| cryptoSuite | <code>CryptoSuite</code> | The underlying [CryptoSuite](CryptoSuite) implementation for the digital signature algorithm |
| key | <code>Key</code> | The private key |

<a name="Signer+getPublicKey"></a>

### signer.getPublicKey() ⇒ <code>Key</code>
Returns the public key corresponding to the opaque, private key

**Kind**: instance method of <code>[Signer](#Signer)</code>  
**Returns**: <code>Key</code> - The public key corresponding to the private key  
<a name="Signer+sign"></a>

### signer.sign(digest, opts)
Signs digest with the private key.

Hash implements the SignerOpts interface and, in most cases, one can
simply pass in the hash function used as opts. Sign may also attempt
to type assert opts to other types in order to obtain algorithm
specific values.

Note that when a signature of a hash of a larger message is needed,
the caller is responsible for hashing the larger message and passing
the hash (as digest) and the hash function (as opts) to Sign.

**Kind**: instance method of <code>[Signer](#Signer)</code>  

| Param | Type | Description |
| --- | --- | --- |
| digest | <code>Array.&lt;byte&gt;</code> | The message to sign |
| opts | <code>Object</code> | hashingFunction: the function to use to hash |

<a name="SigningIdentity"></a>

## SigningIdentity
SigningIdentity is an extension of Identity to cover signing capabilities. E.g., signing identity
should be requested in the case of a client who wishes to sign proposal responses and transactions

**Kind**: global class  

* [SigningIdentity](#SigningIdentity)
    * [new SigningIdentity(id, certificate, publicKey, signer, msp)](#new_SigningIdentity_new)
    * [.sign(msg, opts)](#SigningIdentity+sign)

<a name="new_SigningIdentity_new"></a>

### new SigningIdentity(id, certificate, publicKey, signer, msp)

| Param | Type | Description |
| --- | --- | --- |
| id | <code>string</code> | Identifier of this identity object |
| certificate | <code>string</code> | HEX string for the PEM encoded certificate |
| publicKey | <code>Key</code> | The public key represented by the certificate |
| signer | <code>[Signer](#Signer)</code> | The signer object encapsulating the opaque private key and the corresponding digital signature algorithm to be used for signing operations |
| msp | <code>[MSP](#MSP)</code> | The associated MSP that manages this identity |

<a name="SigningIdentity+sign"></a>

### signingIdentity.sign(msg, opts)
Signs digest with the private key contained inside the signer.

**Kind**: instance method of <code>[SigningIdentity](#SigningIdentity)</code>  

| Param | Type | Description |
| --- | --- | --- |
| msg | <code>Array.&lt;byte&gt;</code> | The message to sign |
| opts | <code>object</code> | Options object for the signing, contains one field 'hashFunction' that allows   different hashing algorithms to be used. If not present, will default to the hash function   configured for the identity's own crypto suite object |

<a name="MSPManager"></a>

## MSPManager
MSPManager is an interface defining a manager of one or more MSPs. This essentially acts
as a mediator to MSP calls and routes MSP related calls to the appropriate MSP. This object
is immutable, it is initialized once and never changed.

**Kind**: global class  

* [MSPManager](#MSPManager)
    * [.loadMSPs(mspConfigs)](#MSPManager+loadMSPs)
    * [.getMSPs()](#MSPManager+getMSPs)
    * [.deserializeIdentity(serializedIdentity)](#MSPManager+deserializeIdentity) ⇒ <code>Promise</code>

<a name="MSPManager+loadMSPs"></a>

### mspManager.loadMSPs(mspConfigs)
Instantiates MSPs for validating identities (like the endorsor in the ProposalResponse). The
MSPs loaded via this method require the CA certificate representing the Certificate
Authority that signed the identities to be validated. They also optionally contain the
certificates for the administrators of the organization that the CA certs represent.

**Kind**: instance method of <code>[MSPManager](#MSPManager)</code>  

| Param | Type | Description |
| --- | --- | --- |
| mspConfigs | <code>protos/msp/mspconfig.proto</code> | An array of MSPConfig objects as defined by the   protobuf protos/msp/mspconfig.proto |

<a name="MSPManager+getMSPs"></a>

### mspManager.getMSPs()
Returns the validating MSPs. Note that this does NOT return the local MSP

**Kind**: instance method of <code>[MSPManager](#MSPManager)</code>  
<a name="MSPManager+deserializeIdentity"></a>

### mspManager.deserializeIdentity(serializedIdentity) ⇒ <code>Promise</code>
DeserializeIdentity deserializes an identity

**Kind**: instance method of <code>[MSPManager](#MSPManager)</code>  
**Returns**: <code>Promise</code> - Promise for an [Identity](#Identity) instance  

| Param | Type | Description |
| --- | --- | --- |
| serializedIdentity | <code>Array.&lt;byte&gt;</code> | A protobuf-based serialization of an object with two fields: mspid and idBytes for certificate PEM bytes |

<a name="MSP"></a>

## MSP
MSP is the minimal Membership Service Provider Interface to be implemented
to manage identities (in terms of signing and signature verification) represented
by private keys and certificates generated from different algorithms (ECDSA, RSA, etc)
and PKIs (software-managed or HSM based)

**Kind**: global class  

* [MSP](#MSP)
    * [new MSP(config)](#new_MSP_new)
    * [.getId()](#MSP+getId) ⇒ <code>string</code>
    * [.getOrganizationUnits()](#MSP+getOrganizationUnits) ⇒ <code>Array.&lt;string&gt;</code>
    * [.getPolicy()](#MSP+getPolicy) ⇒ <code>Object</code>
    * [.getSigningIdentity(identifier)](#MSP+getSigningIdentity) ⇒ <code>[SigningIdentity](#SigningIdentity)</code>
    * [.getDefaultSigningIdentity()](#MSP+getDefaultSigningIdentity) ⇒ <code>[SigningIdentity](#SigningIdentity)</code>
    * [.deserializeIdentity(serializedIdentity)](#MSP+deserializeIdentity) ⇒ <code>Promise</code>
    * [.validate(id)](#MSP+validate) ⇒ <code>boolean</code>

<a name="new_MSP_new"></a>

### new MSP(config)
Setup the MSP instance according to configuration information


| Param | Type | Description |
| --- | --- | --- |
| config | <code>Object</code> | A configuration object specific to the implementation. For this implementation it uses the following fields: 		<br>`rootCerts`: array of [Identity](#Identity) representing trust anchors for validating           signing certificates. Required for MSPs used in verifying signatures 		<br>`intermediateCerts`: array of [Identity](#Identity) representing trust anchors for validating           signing certificates. optional for MSPs used in verifying signatures 		<br>`admins`: array of [Identity](#Identity) representing admin privileges 		<br>`signer`: [SigningIdentity](#SigningIdentity) signing identity. Required for MSPs used in signing 		<br>`id`: {string} value for the identifier of this instance 		<br>`orgs`: {string} array of organizational unit identifiers 		<br>`cryptoSuite': the underlying [CryptoSuite](#module_api.CryptoSuite) for crypto primitive operations |

<a name="MSP+getId"></a>

### msP.getId() ⇒ <code>string</code>
Get provider identifier

**Kind**: instance method of <code>[MSP](#MSP)</code>  
<a name="MSP+getOrganizationUnits"></a>

### msP.getOrganizationUnits() ⇒ <code>Array.&lt;string&gt;</code>
Get organizational unit identifiers

**Kind**: instance method of <code>[MSP](#MSP)</code>  
<a name="MSP+getPolicy"></a>

### msP.getPolicy() ⇒ <code>Object</code>
Obtain the policy to govern changes

**Kind**: instance method of <code>[MSP](#MSP)</code>  
<a name="MSP+getSigningIdentity"></a>

### msP.getSigningIdentity(identifier) ⇒ <code>[SigningIdentity](#SigningIdentity)</code>
Returns a signing identity corresponding to the provided identifier

**Kind**: instance method of <code>[MSP](#MSP)</code>  

| Param | Type | Description |
| --- | --- | --- |
| identifier | <code>string</code> | The identifier of the requested identity object |

<a name="MSP+getDefaultSigningIdentity"></a>

### msP.getDefaultSigningIdentity() ⇒ <code>[SigningIdentity](#SigningIdentity)</code>
Returns the default signing identity

**Kind**: instance method of <code>[MSP](#MSP)</code>  
<a name="MSP+deserializeIdentity"></a>

### msP.deserializeIdentity(serializedIdentity) ⇒ <code>Promise</code>
DeserializeIdentity deserializes an identity

**Kind**: instance method of <code>[MSP](#MSP)</code>  
**Returns**: <code>Promise</code> - Promise for an [Identity](#Identity) instance  

| Param | Type | Description |
| --- | --- | --- |
| serializedIdentity | <code>Array.&lt;byte&gt;</code> | A protobuf-based serialization of an object with two fields: mspid and idBytes for certificate PEM bytes |

<a name="MSP+validate"></a>

### msP.validate(id) ⇒ <code>boolean</code>
Checks whether the supplied identity is valid

**Kind**: instance method of <code>[MSP](#MSP)</code>  

| Param | Type |
| --- | --- |
| id | <code>[Identity](#Identity)</code> | 

<a name="Orderer"></a>

## Orderer
The Orderer class represents a peer in the target blockchain network to which
HFC sends a block of transactions of endorsed proposals requiring ordering.

**Kind**: global class  

* [Orderer](#Orderer)
    * [new Orderer(url, opts)](#new_Orderer_new)
    * [.sendBroadcast(envelope)](#Orderer+sendBroadcast) ⇒ <code>Promise</code>
    * [.sendDeliver(envelope)](#Orderer+sendDeliver) ⇒ <code>Promise</code>
    * [.toString()](#Orderer+toString)

<a name="new_Orderer_new"></a>

### new Orderer(url, opts)
Constructs an Orderer given its endpoint configuration settings.


| Param | Type | Description |
| --- | --- | --- |
| url | <code>string</code> | The orderer URL with format of 'grpcs://host:port'. |
| opts | <code>Object</code> | The options for the connection to the orderer. |

<a name="Orderer+sendBroadcast"></a>

### orderer.sendBroadcast(envelope) ⇒ <code>Promise</code>
Send a Broadcast message to the orderer service.

**Kind**: instance method of <code>[Orderer](#Orderer)</code>  
**Returns**: <code>Promise</code> - A Promise for a BroadcastResponse  
**See**

- the ./proto/orderer/ab.proto
- the ./proto/orderer/ab.proto


| Param | Type | Description |
| --- | --- | --- |
| envelope | <code>byte</code> | Byte data to be included in the Broadcast |

<a name="Orderer+sendDeliver"></a>

### orderer.sendDeliver(envelope) ⇒ <code>Promise</code>
Send a Deliver message to the orderer service.

**Kind**: instance method of <code>[Orderer](#Orderer)</code>  
**Returns**: <code>Promise</code> - A Promise for a Block  
**See**

- the ./proto/orderer/ab.proto
- the ./proto/orderer/common.proto


| Param | Type | Description |
| --- | --- | --- |
| envelope | <code>byte</code> | Byte data to be included in the Deliver |

<a name="Orderer+toString"></a>

### orderer.toString()
return a printable representation of this object

**Kind**: instance method of <code>[Orderer](#Orderer)</code>  
<a name="Peer"></a>

## Peer
The Peer class represents a peer in the target blockchain network to which
HFC sends endorsement proposals, transaction ordering or query requests.

The Peer class represents the remote Peer node and its network membership materials,
aka the ECert used to verify signatures. Peer membership represents organizations,
unlike User membership which represents individuals.

When constructed, a Peer instance can be designated as an event source, in which case
a “eventSourceUrl” attribute should be configured. This allows the SDK to automatically
attach transaction event listeners to the event stream.

It should be noted that Peer event streams function at the Peer level and not at the
chain and chaincode levels.

**Kind**: global class  

* [Peer](#Peer)
    * [new Peer(url, opts)](#new_Peer_new)
    * [.connectEventSource()](#Peer+connectEventSource) ⇒ <code>Promise</code>
    * [.isEventListened(eventName, chain)](#Peer+isEventListened)
    * [.addListener(eventType, eventTypeData, eventCallback)](#Peer+addListener) ⇒ <code>string</code>
    * [.removeListener(eventListenerRef)](#Peer+removeListener) ⇒ <code>boolean</code>
    * [.getName()](#Peer+getName) ⇒ <code>string</code>
    * [.setName(name)](#Peer+setName)
    * [.getRoles()](#Peer+getRoles) ⇒ <code>Array.&lt;string&gt;</code>
    * [.setRoles(roles)](#Peer+setRoles)
    * [.getEnrollmentCertificate()](#Peer+getEnrollmentCertificate) ⇒ <code>object</code>
    * [.setEnrollmentCertificate(enrollment)](#Peer+setEnrollmentCertificate)
    * [.sendProposal(proposal)](#Peer+sendProposal) ⇒
    * [.toString()](#Peer+toString)

<a name="new_Peer_new"></a>

### new Peer(url, opts)
Constructs a Peer given its endpoint configuration settings.


| Param | Type | Description |
| --- | --- | --- |
| url | <code>string</code> | The URL with format of "grpcs://host:port". |
| opts | <code>Object</code> | The options for the connection to the peer. |

<a name="Peer+connectEventSource"></a>

### peer.connectEventSource() ⇒ <code>Promise</code>
Since practically all Peers are event producers, when constructing a Peer instance,
an application can designate it as the event source for the application. Typically
only one of the Peers on a Chain needs to be the event source, because all Peers on
the Chain produce the same events. This method tells the SDK which Peer(s) to use as
the event source for the client application. It is the responsibility of the SDK to
manage the connection lifecycle to the Peer’s EventHub. It is the responsibility of
the Client Application to understand and inform the selected Peer as to which event
types it wants to receive and the call back functions to use.

**Kind**: instance method of <code>[Peer](#Peer)</code>  
**Returns**: <code>Promise</code> - This gives the app a handle to attach “success” and “error” listeners  
<a name="Peer+isEventListened"></a>

### peer.isEventListened(eventName, chain)
A network call that discovers if at least one listener has been connected to the target
Peer for a given event. This helps application instance to decide whether it needs to
connect to the event source in a crash recovery or multiple instance instantiation.

**Kind**: instance method of <code>[Peer](#Peer)</code>  
**Result**: <code>boolean</code> Whether the said event has been listened on by some application instance on that chain.  

| Param | Type | Description |
| --- | --- | --- |
| eventName | <code>string</code> | required |
| chain | <code>[Chain](#Chain)</code> | optional |

<a name="Peer+addListener"></a>

### peer.addListener(eventType, eventTypeData, eventCallback) ⇒ <code>string</code>
For a Peer that is connected to eventSource, the addListener registers an EventCallBack for a
set of event types. addListener can be invoked multiple times to support differing EventCallBack
functions receiving different types of events.

Note that the parameters below are optional in certain languages, like Java, that constructs an
instance of a listener interface, and pass in that instance as the parameter.

**Kind**: instance method of <code>[Peer](#Peer)</code>  
**Returns**: <code>string</code> - An ID reference to the event listener.  

| Param | Type | Description |
| --- | --- | --- |
| eventType | <code>string</code> | : ie. Block, Chaincode, Transaction |
| eventTypeData | <code>object</code> | : Object Specific for event type as necessary, currently needed for “Chaincode” event type, specifying a matching pattern to the event name set in the chaincode(s) being executed on the target Peer, and for “Transaction” event type, specifying the transaction ID |
| eventCallback | <code>class</code> | Client Application class registering for the callback. |

<a name="Peer+removeListener"></a>

### peer.removeListener(eventListenerRef) ⇒ <code>boolean</code>
Unregisters a listener.

**Kind**: instance method of <code>[Peer](#Peer)</code>  
**Returns**: <code>boolean</code> - Success / Failure status  

| Param | Type | Description |
| --- | --- | --- |
| eventListenerRef | <code>string</code> | Reference returned by SDK for event listener. |

<a name="Peer+getName"></a>

### peer.getName() ⇒ <code>string</code>
Get the Peer name. Required property for the instance objects.

**Kind**: instance method of <code>[Peer](#Peer)</code>  
**Returns**: <code>string</code> - The name of the Peer  
<a name="Peer+setName"></a>

### peer.setName(name)
Set the Peer name / id.

**Kind**: instance method of <code>[Peer](#Peer)</code>  

| Param | Type |
| --- | --- |
| name | <code>string</code> | 

<a name="Peer+getRoles"></a>

### peer.getRoles() ⇒ <code>Array.&lt;string&gt;</code>
Get the user’s roles the Peer participates in. It’s an array of possible values
in “client”, and “auditor”. The member service defines two more roles reserved
for peer membership: “peer” and “validator”, which are not exposed to the applications.

**Kind**: instance method of <code>[Peer](#Peer)</code>  
**Returns**: <code>Array.&lt;string&gt;</code> - The roles for this user.  
<a name="Peer+setRoles"></a>

### peer.setRoles(roles)
Set the user’s roles the Peer participates in. See getRoles() for legitimate values.

**Kind**: instance method of <code>[Peer](#Peer)</code>  

| Param | Type | Description |
| --- | --- | --- |
| roles | <code>Array.&lt;string&gt;</code> | The list of roles for the user. |

<a name="Peer+getEnrollmentCertificate"></a>

### peer.getEnrollmentCertificate() ⇒ <code>object</code>
Returns the Peer's enrollment certificate.

**Kind**: instance method of <code>[Peer](#Peer)</code>  
**Returns**: <code>object</code> - Certificate in PEM format signed by the trusted CA  
<a name="Peer+setEnrollmentCertificate"></a>

### peer.setEnrollmentCertificate(enrollment)
Set the Peer’s enrollment certificate.

**Kind**: instance method of <code>[Peer](#Peer)</code>  

| Param | Type | Description |
| --- | --- | --- |
| enrollment | <code>object</code> | Certificate in PEM format signed by the trusted CA |

<a name="Peer+sendProposal"></a>

### peer.sendProposal(proposal) ⇒
Send an endorsement proposal to an endorser.

**Kind**: instance method of <code>[Peer](#Peer)</code>  
**Returns**: Promise for a ProposalResponse  
**See**: /protos/peer/fabric_proposal.proto  

| Param | Type | Description |
| --- | --- | --- |
| proposal | <code>Proposal</code> | A proposal of type Proposal |

<a name="Peer+toString"></a>

### peer.toString()
return a printable representation of this object

**Kind**: instance method of <code>[Peer](#Peer)</code>  
<a name="Remote"></a>

## Remote
The Remote class represents a the base class for all remote nodes, Peer, Orderer , and MemberServicespeer.

**Kind**: global class  

* [Remote](#Remote)
    * [new Remote(url, opts)](#new_Remote_new)
    * [.getUrl()](#Remote+getUrl) ⇒ <code>string</code>
    * [.toString()](#Remote+toString)

<a name="new_Remote_new"></a>

### new Remote(url, opts)
Constructs an object with the endpoint configuration settings.


| Param | Type | Description |
| --- | --- | --- |
| url | <code>string</code> | The orderer URL with format of 'grpc(s)://host:port'. |
| opts | <code>object</code> | An Object that may contain options to pass to grpcs calls <br>- pem {string} The certificate file, in PEM format,    to use with the gRPC protocol (that is, with TransportCredentials).    Required when using the grpcs protocol. <br>- ssl-target-name-override {string} Used in test environment only, when the server certificate's    hostname (in the 'CN' field) does not match the actual host endpoint that the server process runs    at, the application can work around the client TLS verify failure by setting this property to the    value of the server certificate's hostname <br>- any other standard grpc call options will be passed to the grpc service calls directly |

<a name="Remote+getUrl"></a>

### remote.getUrl() ⇒ <code>string</code>
Get the URL of the orderer.

**Kind**: instance method of <code>[Remote](#Remote)</code>  
**Returns**: <code>string</code> - Get the URL associated with the Orderer.  
<a name="Remote+toString"></a>

### remote.toString()
return a printable representation of this object

**Kind**: instance method of <code>[Remote](#Remote)</code>  
<a name="User"></a>

## User
The User class represents users that have been enrolled and represented by
an enrollment certificate (ECert) and a signing key. The ECert must have
been signed by one of the CAs the blockchain network has been configured to trust.
An enrolled user (having a signing key and ECert) can conduct chaincode instantiate,
transactions and queries with the Chain.

User ECerts can be obtained from a CA beforehand as part of installing and instantiating
the application, or it can be obtained from the optional Fabric CA service via its
enrollment process.

Sometimes User identities are confused with Peer identities. User identities represent
signing capability because it has access to the private key, while Peer identities in
the context of the application/SDK only has the certificate for verifying signatures.
An application cannot use the Peer identity to sign things because the application doesn’t
have access to the Peer identity’s private key.

**Kind**: global class  

* [User](#User)
    * [new User(cfg)](#new_User_new)
    * [.getName()](#User+getName) ⇒ <code>string</code>
    * [.getRoles()](#User+getRoles) ⇒ <code>Array.&lt;string&gt;</code>
    * [.setRoles(roles)](#User+setRoles)
    * [.getAffiliation()](#User+getAffiliation) ⇒ <code>string</code>
    * [.setAffiliation(affiliation)](#User+setAffiliation)
    * [.getIdentity()](#User+getIdentity) ⇒ <code>[Identity](#Identity)</code>
    * [.getSigningIdentity()](#User+getSigningIdentity) ⇒ <code>[SigningIdentity](#SigningIdentity)</code>
    * [.setEnrollment(privateKey, certificate, mspId, opts)](#User+setEnrollment) ⇒ <code>Promise</code>
    * [.getTCertBatchSize()](#User+getTCertBatchSize) ⇒ <code>int</code>
    * [.setTCertBatchSize(batchSize)](#User+setTCertBatchSize)
    * [.isEnrolled()](#User+isEnrolled) ⇒ <code>boolean</code>
    * [.fromString()](#User+fromString) ⇒ <code>Member</code>
    * [.toString()](#User+toString) ⇒ <code>string</code>

<a name="new_User_new"></a>

### new User(cfg)
Constructor for a member.


| Param | Type | Description |
| --- | --- | --- |
| cfg | <code>string</code> | The member name or an object with the following attributes:   - enrollmentID {string}: user name   - name {string}: user name, if "enrollmentID" is also specified, the "name" is ignored   - roles {string[]}: optional. array of roles   - affiliation {string}: optional. affiliation with a group or organization |

<a name="User+getName"></a>

### user.getName() ⇒ <code>string</code>
Get the member name.

**Kind**: instance method of <code>[User](#User)</code>  
**Returns**: <code>string</code> - The member name.  
<a name="User+getRoles"></a>

### user.getRoles() ⇒ <code>Array.&lt;string&gt;</code>
Get the roles.

**Kind**: instance method of <code>[User](#User)</code>  
**Returns**: <code>Array.&lt;string&gt;</code> - The roles.  
<a name="User+setRoles"></a>

### user.setRoles(roles)
Set the roles.

**Kind**: instance method of <code>[User](#User)</code>  

| Param | Type | Description |
| --- | --- | --- |
| roles | <code>Array.&lt;string&gt;</code> | The roles. |

<a name="User+getAffiliation"></a>

### user.getAffiliation() ⇒ <code>string</code>
Get the affiliation.

**Kind**: instance method of <code>[User](#User)</code>  
**Returns**: <code>string</code> - The affiliation.  
<a name="User+setAffiliation"></a>

### user.setAffiliation(affiliation)
Set the affiliation.

**Kind**: instance method of <code>[User](#User)</code>  

| Param | Type | Description |
| --- | --- | --- |
| affiliation | <code>string</code> | The affiliation. |

<a name="User+getIdentity"></a>

### user.getIdentity() ⇒ <code>[Identity](#Identity)</code>
Get the [Identity](#Identity) object for this User instance, used to verify signatures

**Kind**: instance method of <code>[User](#User)</code>  
**Returns**: <code>[Identity](#Identity)</code> - the identity object that encapsulates the user's enrollment certificate  
<a name="User+getSigningIdentity"></a>

### user.getSigningIdentity() ⇒ <code>[SigningIdentity](#SigningIdentity)</code>
Get the [SigningIdentity](#SigningIdentity) object for this User instance, used to generate signatures

**Kind**: instance method of <code>[User](#User)</code>  
**Returns**: <code>[SigningIdentity](#SigningIdentity)</code> - the identity object that encapsulates the user's private key for signing  
<a name="User+setEnrollment"></a>

### user.setEnrollment(privateKey, certificate, mspId, opts) ⇒ <code>Promise</code>
Set the enrollment object for this User instance

**Kind**: instance method of <code>[User](#User)</code>  
**Returns**: <code>Promise</code> - Promise for successful completion of creating the user's signing Identity  

| Param | Type | Description |
| --- | --- | --- |
| privateKey | <code>Key</code> | the private key object |
| certificate | <code>string</code> | the PEM-encoded string of certificate |
| mspId | <code>string</code> | The Member Service Provider id for the local signing identity |
| opts | <code>object</code> | optional. an object with the following attributes, all optional:   - cryptoSettings: {object} an object with the following attributes:      - software {boolean}: Whether to load a software-based implementation (true) or HSM implementation (false) default is true (for software based implementation), specific implementation module is specified in the setting 'crypto-suite-software'      - keysize {number}: The key size to use for the crypto suite instance. default is value of the setting 'crypto-keysize'      - algorithm {string}: Digital signature algorithm, currently supporting ECDSA only with value "EC"      - hash {string}: 'SHA2' or 'SHA3'   - KVSImplClass: {function} the User class persists crypto keys in a [CryptoKeyStore](CryptoKeyStore), there is a file-based implementation that is provided as the default. Application can use this parameter to override the default, such as saving the keys in a key store backed by database. If present, the value must be the class for the alternative implementation.   - kvsOpts: {object}: an options object specific to the implementation in KVSImplClass |

<a name="User+getTCertBatchSize"></a>

### user.getTCertBatchSize() ⇒ <code>int</code>
Get the transaction certificate (tcert) batch size, which is the number of tcerts retrieved
from member services each time (i.e. in a single batch).

**Kind**: instance method of <code>[User](#User)</code>  
**Returns**: <code>int</code> - The tcert batch size.  
<a name="User+setTCertBatchSize"></a>

### user.setTCertBatchSize(batchSize)
Set the transaction certificate (tcert) batch size.

**Kind**: instance method of <code>[User](#User)</code>  

| Param | Type |
| --- | --- |
| batchSize | <code>int</code> | 

<a name="User+isEnrolled"></a>

### user.isEnrolled() ⇒ <code>boolean</code>
Determine if this name has been enrolled.

**Kind**: instance method of <code>[User](#User)</code>  
**Returns**: <code>boolean</code> - True if enrolled; otherwise, false.  
<a name="User+fromString"></a>

### user.fromString() ⇒ <code>Member</code>
Set the current state of this member from a string based JSON object

**Kind**: instance method of <code>[User](#User)</code>  
**Returns**: <code>Member</code> - Promise of the unmarshalled Member object represented by the serialized string  
<a name="User+toString"></a>

### user.toString() ⇒ <code>string</code>
Save the current state of this member as a string

**Kind**: instance method of <code>[User](#User)</code>  
**Returns**: <code>string</code> - The state of this member as a string  
<a name="sjcl"></a>

## sjcl
Implement hash primitives.
Currently SHA3 is implemented, but needs to also add SHA2.

NOTE: This is in pure java script to be compatible with the sjcl.hmac function.

**Kind**: global variable  
<a name="bitsToBytes"></a>

## bitsToBytes(a) ⇒ <code>bytes</code>
Convert from a bitArray to bytes (using SJCL's codec)

**Kind**: global function  
**Returns**: <code>bytes</code> - the bytes converted from the bitArray  

| Param | Type | Description |
| --- | --- | --- |
| a | <code>bits</code> | bitArray to convert from |

<a name="bytesToBits"></a>

## bytesToBits(a) ⇒ <code>bitArray</code>
Convert from bytes to a bitArray (using SJCL's codec)

**Kind**: global function  
**Returns**: <code>bitArray</code> - the bitArray converted from bytes  

| Param | Type | Description |
| --- | --- | --- |
| a | <code>bytes</code> | bytes to convert from |

<a name="package"></a>

## package(chaincodePath, chaincodeType, devmode) ⇒ <code>Promise</code>
Utility function to package a chaincode. The contents will be returned as a byte array.

**Kind**: global function  
**Returns**: <code>Promise</code> - A promise for the data as a byte array  

| Param | Type | Description |
| --- | --- | --- |
| chaincodePath | <code>Object</code> | required - String of the path to location of                the source code of the chaincode |
| chaincodeType | <code>Object</code> | optional - String of the type of chaincode                 ['golang', 'car', 'java'] (default 'golang') |
| devmode | <code>boolean</code> | optional - True if using dev mode |

