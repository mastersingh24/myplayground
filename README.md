#  



### fabric-client/index.js


#### module.exports() 

This is the main module for the "fabric-client" package. It provides the convenience
APIs to the classes of the package including [Chain]{@link module:api.Chain}






##### Returns


- `Void`




### fabric-client/lib/api.js


#### utils() 

This module defines the API for the pluggable components of the node.js SDK. The APIs are defined
according to the Hyperledger Fabric's [common SDK specification]{@link https://docs.google.com/document/d/1R5RtIBMW9fZpli37E5Li5_Q9ve3BnQ4q3gWmGZj6Sv4/edit?usp=sharing}






##### Returns


- `Void`



#### KeyValueStore() 

Abstract class for a Key-Value store. The Chain class uses this store
to save sensitive information such as authenticated user's private keys,
certificates, etc.

The SDK provides a default implementation based on files. An alternative
implementation can be specified using the "KEY_VALUE_STORE" environment
variable pointing to a full path to the require() package for the module.






##### Returns


- `Void`



#### getValue(name) 

Get the value associated with name.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| name | `string`  | of the key | &nbsp; |




##### Returns


-  Promise for the value corresponding to the key. If the value does not exist in the store, returns null without rejecting the promise



#### setValue(name, value) 

Set the value associated with name.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| name | `string`  | of the key to save | &nbsp; |
| value | `string`  | to save | &nbsp; |




##### Returns


- `Promise`  Promise for the 'value' object upon successful write operation



#### CryptoSuite() 

Abstract class for a suite of crypto algorithms used by the SDK to perform encryption,
decryption and secure hashing. A complete suite includes libraries for asymmetric
keys (such as ECDSA or RSA), symmetric keys (such as AES) and secure hash (such as
SHA2/3).

The SDK provides a default implementation based on ECDSA + AES + SHA2/3. An alternative
implementation can be specified using the "CRYPTO_SUITE" environment variable, pointing
to a full path to the require() package for the module.






##### Returns


- `Void`



#### generateKey(opts) 

Generate a key using the opts




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| opts | `Object`  |      algorithm: an identifier for the algorithm to be used, such as "ECDSA"
     ephemeral: true if the key to generate has to be ephemeral | &nbsp; |




##### Returns


- `Key`  Promise of an instance of the Key class



#### deriveKey(key, opts) 

Derives a key from k using opts.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| key | `Key`  | the source key | &nbsp; |
| opts | `Object`  |      algorithm: an identifier for the algorithm to be used
     ephemeral: true if the key to generate has to be ephemeral | &nbsp; |




##### Returns


- `Key`  derived key



#### importKey(raw, opts) 

Imports a key from its raw representation using opts. If the `opts.ephemeral`
parameter is false, the method, in addition to returning the imported {@link Key}
instance, also saves the imported key in the key store as PEM files that can be
retrieved using the 'getKey()' method




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| raw | `Array.&lt;byte&gt;`  | Raw bytes of the key to import | &nbsp; |
| opts | `Object`  |      <br>`type`: type of information that 'raw' represents: x509 certificate,
     <br>`algorithm`: an identifier for the algorithm to be used
     <br>`ephemeral`: true if the key to generate has to be ephemeral | &nbsp; |




##### Returns


- `Key`  Promise of an instance of the Key class wrapping the raw key bytes



#### getKey(ski) 

Returns the key this CSP associates to the Subject Key Identifier ski.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| ski | `Array.&lt;byte&gt;`  | Subject Key Identifier specific to a Crypto Suite implementation | &nbsp; |




##### Returns


- `Key`  Promise of an instance of the Key class corresponding to the ski



#### hash(msg, opts) 

Hashes messages msg using options opts.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| msg | `Array.&lt;byte&gt;`  | Source message to be hashed | &nbsp; |
| opts | `Object`  |      algorithm: an identifier for the algorithm to be used, such as "SHA3" | &nbsp; |




##### Returns


- `string`  The hashed digest in hexidecimal string encoding



#### sign(key, digest, opts) 

Signs digest using key k.
The opts argument should be appropriate for the algorithm used.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| key | `Key`  | Signing key (private key) | &nbsp; |
| digest | `Array.&lt;byte&gt;`  | The message digest to be signed. Note that when a signature of a hash of a larger message is needed, the caller is responsible
for hashing the larger message and passing the hash (as digest) and the hash
function (as opts) to sign. | &nbsp; |
| opts | `Object`  |      hashingFunction: the function to use to hash | &nbsp; |




##### Returns


- `Array.&lt;byte&gt;`  the resulting signature



#### verify(key, signature, digest) 

Verifies signature against key k and digest
The opts argument should be appropriate for the algorithm used.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| key | `Key`  | Signing verification key (public key) | &nbsp; |
| signature | `Array.&lt;byte&gt;`  | The signature to verify | &nbsp; |
| digest | `Array.&lt;byte&gt;`  | The digest that the signature was created for | &nbsp; |




##### Returns


- `boolean`  true if the signature verifies successfully



#### encrypt(key, plainText, opts) 

Encrypts plaintext using key k.
The opts argument should be appropriate for the algorithm used.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| key | `Key`  | Encryption key (public key) | &nbsp; |
| plainText | `Array.&lt;byte&gt;`  | Plain text to encrypt | &nbsp; |
| opts | `Object`  | Encryption options | &nbsp; |




##### Returns


- `Array.&lt;byte&gt;`  Cipher text after encryption



#### decrypt(key, cipherText, opts) 

Decrypts ciphertext using key k.
The opts argument should be appropriate for the algorithm used.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| key | `Key`  | Decryption key (private key) | &nbsp; |
| cipherText | `Array.&lt;byte&gt;`  | Cipher text to decrypt | &nbsp; |
| opts | `Object`  | Decrypt options | &nbsp; |




##### Returns


- `Array.&lt;byte&gt;`  Plain text after decryption



#### Key() 

Key represents a cryptographic key. It can be symmetric or asymmetric. In the case of an
asymmetric key, the key can be public or private. In the case of a private asymmetric
key, the getPublicKey() method allows to retrieve the corresponding public-key.
A key can be referenced via the Subject Key Identifier in DER or PEM encoding






##### Returns


- `Void`



#### getSKI() 

Returns the subject key identifier of this key in DER encoding for private keys or PEM encoding for public keys.






##### Returns


- `Array.&lt;byte&gt;`  the subject key identifier of this key



#### isSymmetric() 

Returns true if this key is a symmetric key, false is this key is asymmetric






##### Returns


- `boolean`  if this key is a symmetric key



#### isPrivate() 

Returns true if this key is an asymmetric private key, false otherwise.






##### Returns


- `boolean`  if this key is an asymmetric private key



#### getPublicKey() 

Returns the corresponding public key if this key is an asymmetric private key.
If this key is already public, PublicKey returns this key itself.






##### Returns


- `Key`  the corresponding public key if this key is an asymmetric private key. If this key is already public, PublicKey returns this key itself.



#### toBytes() 

Converts this key to its byte representation, if this operation is allowed.






##### Returns


- `Array.&lt;byte&gt;`  the byte representation of the key




### fabric-client/lib/impl/FileKeyValueStore.js


#### KeyValueStore() 

This is a default implementation of the [KeyValueStore]{@link module:api.KeyValueStore} API.
It uses files to store the key values.






##### Returns


- `Void`



#### constructor(options) 

constructor




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| options | `Object`  | contains a single property 'path' which points to the top-level directory for the store | &nbsp; |




##### Returns


- `Void`



#### getValue(name) 

Get the value associated with name.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| name | `string`  |  | &nbsp; |




##### Returns


-  Promise for the value



#### setValue(name, value) 

Set the value associated with name.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| name | `string`  |  | &nbsp; |
| value | `string`  |  | &nbsp; |




##### Returns


-  Promise for a "true" value on successful completion




### fabric-client/lib/impl/CouchDBKeyValueStore.js


#### CouchDBKeyValueStore() 

This is a sample database implementation of the [KeyValueStore]{@link module:api.KeyValueStore} API.
It uses a local or remote CouchDB database instance to store the keys.






##### Returns


- `Void`



#### constructor(options) 

constructor




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| options | `Object`  | Contains the properties: <li>url - The CouchDB instance url.
<li>name - Optional.  Identifies the name of the database if different from the default of 'member_db'. | &nbsp; |




##### Returns


- `Void`



#### getValue(name) 

Get the value associated with name.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| name | `string`  |  | &nbsp; |




##### Returns


-  Promise for the value



#### setValue(name, value) 

Set the value associated with name.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| name | `string`  |  | &nbsp; |
| value | `string`  |  | &nbsp; |




##### Returns


-  Promise for a 'true' value on successful completion




### fabric-client/lib/impl/CryptoSuite_ECDSA_AES.js


#### CryptoSuite_ECDSA_AES() 

The {@link module:api.CryptoSuite} implementation for ECDSA, and AES algorithms using software key generation.
This class implements a software-based key generation (as opposed to Hardware Security Module based key management)






##### Returns


- `Void`



#### constructor(keySize, opts, KVSImplClass, hash) 

constructor




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| keySize | `number`  | Key size for the ECDSA algorithm, can only be 256 or 384 | &nbsp; |
| opts | `object`  | Implementation-specific options object for the {@link KeyValueStore} class to instantiate an instance | &nbsp; |
| KVSImplClass | `string`  | Optional. The built-in key store saves private keys. The key store may be backed by different {@link KeyValueStore} implementations. If specified, the value of the argument must point to a module implementing the
KeyValueStore interface. | &nbsp; |
| hash | `string`  | Optional. Hash algorithm, supported values are "SHA2" and "SHA3" | &nbsp; |




##### Returns


- `Void`



#### generateKey() 

This is an implementation of {@link module:api.CryptoSuite#generateKey}
Returns an instance of {@link module.api.Key} representing the private key, which also
encapsulates the public key. It'll also save the private key in the KeyValueStore






##### Returns


- `Key`  Promise of an instance of {@link module:ECDSA_KEY} containing the private key and the public key



#### deriveKey() 

This is an implementation of {@link module:api.CryptoSuite#deriveKey}
To be implemented






##### Returns


- `Void`



#### importKey() 

This is an implementation of {@link module:api.CryptoSuite#importKey}






##### Returns


- `Void`



#### getKey() 

This is an implementation of {@link module:api.CryptoSuite#getKey}
Returns the key this CSP associates to the Subject Key Identifier ski.






##### Returns


- `Void`



#### hash() 

This is an implementation of {@link module:api.CryptoSuite#hash}
Hashes messages msg using options opts.






##### Returns


- `Void`



#### sign() 

This is an implementation of {@link module:api.CryptoSuite#sign}
Signs digest using key k.

The opts argument is not needed.






##### Returns


- `Void`



#### verify() 

This is an implementation of {@link module:api.CryptoSuite#verify}
Verifies signature against key k and digest
The opts argument should be appropriate for the algorithm used.






##### Returns


- `Void`



#### encrypt() 

This is an implementation of {@link module:api.CryptoSuite#encrypt}
Encrypts plaintext using key k.
The opts argument should be appropriate for the algorithm used.






##### Returns


- `Void`



#### decrypt() 

This is an implementation of {@link module:api.CryptoSuite#decrypt}
Decrypts ciphertext using key k.
The opts argument should be appropriate for the algorithm used.






##### Returns


- `Void`




### fabric-client/lib/impl/ecdsa/key.js


#### module.exports() 

This module implements the {@link module:api.Key} interface, for ECDSA.






##### Returns


- `Void`



#### constructor(key) 

this class represents the private or public key of an ECDSA key pair.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| key | `Object`  | This must be the "privKeyObj" or "pubKeyObj" part of the object generated by jsrsasign.KEYUTIL.generateKeypair() | &nbsp; |




##### Returns


- `Void`



#### getSKI() 








##### Returns


- `string`  a string representation of the hash from a sequence based on the private key bytes



#### generateCSR(subjectDN) 

Generates a CSR/PKCS#10 certificate signing request for this key




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| subjectDN | `string`  | The X500Name for the certificate request in LDAP(RFC 2253) format | &nbsp; |




##### Returns


- `string`  PEM-encoded PKCS#10 certificate signing request




### fabric-client/lib/impl/bccsp_pkcs11.js


#### __func() 

Function name and line number for logger.






##### Returns


- `Void`



#### constructor() 

Option is the form { lib: string, slot: number, pin: string }

If lib is not specified or null, its value will be taken from the
CRYPTO_PKCS11_LIB env var, and if the env var is not set, its value will
be taken from the crypto-pkcs11-lib key in the configuration file.

If slot is not specified or null, its value will be taken from the
CRYPTO_PKCS11_SLOT env var, and if the env var is not set, its value will
be taken from the crypto-pkcs11-slot key in the configuration file.

If pin is not specified or null, its value will be taken from the
CRYPTO_PKCS11_PIN env var, and if the env var is not set, its value will
be taken from the crypto-pkcs11-pin key in the configuration file.






##### Returns


- `Void`



#### pkcs11Lib() 

If no lib specified, get it from env var or config file.






##### Returns


- `Void`



#### pkcs11Slot() 

If no slot specified, get it from env var or config file.






##### Returns


- `Void`



#### pkcs11Pin() 

If no pin specified, get it from env var or config file.






##### Returns


- `Void`



#### this._pkcs11() 

Load native PKCS11 library, open PKCS11 session and login.






##### Returns


- `Void`



#### this._skiToKey() 

SKI to key cache for getKey(ski) function.






##### Returns


- `Void`



#### _tod() 

16-byte front 0 padded time of day in hex for computing SKI.






##### Returns


- `Void`



#### _ski() 

sha256 of tod as SKI.






##### Returns


- `Void`



#### _fixEcpt() 

Workaround for opencryptoki bug.






##### Returns


- `Void`



#### _pkcs11OpenSession() 

Open pkcs11 session and login.






##### Returns


- `Void`



#### this._pkcs11Session() 

Open session.






##### Returns


- `Void`



#### _pkcs11GenerateKey() 

Generate PKCS11 AES key.

Return SKI and key handle.






##### Returns


- `Void`



#### handle() 

Call PKCS11 API to generate the key.






##### Returns


- `Void`



#### objectTemplate() 

Template for querying key attributes (debug only).






##### Returns


- `Void`



#### _pkcs11GenerateECKeyPair() 

Generate PKCS11 ECDSA key pair.

Return SKI, EC point, and key handles.






##### Returns


- `Void`



#### handles() 

Call PKCS11 API to generate the key pair.

Return public and private key handles.






##### Returns


- `Void`



#### objectTemplate() 

Template for querying key attributes (debug only).






##### Returns


- `Void`



#### ecpt() 

Get the public key EC point.






##### Returns


- `Void`



#### ski() 

Set CKA_ID of public and private key to be SKI.






##### Returns


- `Void`



#### _pkcs11SkiToHandle() 

Search PKCS11 for AES secret key or ECDSA key pair with given SKI.

Return key handle(s) if found.






##### Returns


- `Void`



#### secretKeyHandle() 

First look for AES key.






##### Returns


- `Void`



#### privKeyHandle() 

Then look for ECDSA key pair.






##### Returns


- `Void`



#### _pkcs11QueryEcparamsEcpt() 

Query PKCS11 EC params (OID) and EC point of an ECDSA key pair.






##### Returns


- `Void`



#### attribs() 

Get EC params (to derive key size) and EC point.






##### Returns


- `Void`



#### _pkcs11Sign() 

PKCS11 signing digest with an ECDSA private key.






##### Returns


- `Void`



#### r() 

ASN1 DER encoding against malleability.






##### Returns


- `Void`



#### _pkcs11Verify() 

PKCS11 verify signature of digest signed with an ECDSA private key.






##### Returns


- `Void`



#### rns() 

Restore ASN1 DER signature to raw signature.
Error will be thrown if signature is not properly encoded.






##### Returns


- `Void`



#### if() 

Error is thrown when signature verification fails.






##### Returns


- `Void`



#### _pkcs11Encrypt() 

PKCS11 encrypt plain text with an AES key.






##### Returns


- `Void`



#### iv() 

key has been checked to be an AES key.






##### Returns


- `Void`



#### _pkcs11Decrypt() 

PKCS11 decrypt cipher text encrypted with an AES key.






##### Returns


- `Void`



#### iv() 

key has been checked to be an AES key.






##### Returns


- `Void`



#### _pkcs11DeriveKey() 

PKCS11 derive key with ECDH mechanism.






##### Returns


- `Void`



#### _pkcs11GetAttributeValue() 

Query PKCS11 object attributes.

Return array of [ { type:..., value:... }, ... ]






##### Returns


- `Void`



#### _pkcs11SetAttributeValue() 

Set PKCS11 object attributes.






##### Returns


- `Void`



#### _pkcs11FindObjects() 

Find PKCS11 objects matching attribute template.

Return array of object handles.






##### Returns


- `Void`



#### generateKey() 

This is an implementation of {@link module:api.CryptoSuite#generateKey}
Returns an instance of {@link module.api.Key} representing the private key,
which also encapsulates the public key. By default the generated key (keypar)
is (are) ephemeral unless opts.ephemeral is set to false, in which case the
key (keypair) will be saved across PKCS11 sessions by the HSM hardware.






##### Returns


- `Key`  Promise of an instance of {@link module:PKCS11_ECDSA_KEY} containing the private key and the public key.



#### key() 

Put key in the session cache and return
promise of the key.






##### Returns


- `Void`



#### key() 

Put key in the session cache and return
promise of the key.






##### Returns


- `Void`



#### getKey() 

This is an implementation of {@link module:api.CryptoSuite#getKey}
Returns the key this CSP associates to the Subject Key Identifier ski.






##### Returns


- `Void`



#### hit() 

Found the ski in the session key cache.






##### Returns


- `Void`



#### sign() 

This is an implementation of {@link module:api.CryptoSuite#sign}
Signs digest using key k.

The opts argument is not needed.






##### Returns


- `Void`



#### verify() 

This is an implementation of {@link module:api.CryptoSuite#verify}
Verifies signature against key k and digest






##### Returns


- `Void`



#### encrypt() 

This is an implementation of {@link module:api.CryptoSuite#encrypt}
Encrypts plainText using key.
The opts argument should be appropriate for the algorithm used.






##### Returns


- `Void`



#### decrypt() 

This is an implementation of {@link module:api.CryptoSuite#decrypt}
Decrypts cipherText using key.
The opts argument should be appropriate for the algorithm used.






##### Returns


- `Void`



#### deriveKey() 

This is an implementation of {@link module:api.CryptoSuite#deriveKey}






##### Returns


- `Void`



#### importKey() 

This is an implementation of {@link module:api.CryptoSuite#importKey}






##### Returns


- `Void`



#### key() 

Put key in the session cache and return
promise of the key.






##### Returns


- `Void`




### fabric-client/lib/impl/ecdsa/pkcs11_key.js


#### this._ski() 

Common for both private and public key.






##### Returns


- `Void`



#### if() 

private key: ski set, ecpt set, priv set,   pub set
public  key: ski set, ecpt set, priv unset, pub set






##### Returns


- `Void`




### fabric-client/lib/impl/aes/pkcs11_key.js


#### this._block() 

bits






##### Returns


- `Void`




### fabric-client/lib/Chain.js


#### Chain() 

The class representing a chain with which the client SDK interacts.

The “Chain” object captures settings for a channel, which is created by
the orderers to isolate transactions delivery to peers participating on channel.
A chain must be initialized after it has been configured with the list of peers
and orderers. The initialization sends a get configuration block request to the
primary orderer to retrieve the configuration settings for this channel.






##### Returns


- `Void`



#### constructor(name, clientContext) 






##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| name | `string`  | to identify different chain instances. The naming of chain instances is enforced by the ordering service and must be unique within the blockchain network | &nbsp; |
| clientContext | `Client`  | An instance of {@link Client} that provides operational context such as submitting User etc. | &nbsp; |




##### Returns


- `Void`



#### initialize() 

Retrieve the configuration from the primary orderer and initialize this chain (channel)
with those values. Currently only the MSP config value of the channel is loaded
into this chain.






##### Returns


- `Void`



#### getName() 

Get the chain name.






##### Returns


- `string`  The name of the chain.



#### isSecurityEnabled() 

Determine if security is enabled.






##### Returns


- `Void`



#### isPreFetchMode() 

Determine if pre-fetch mode is enabled to prefetch tcerts.






##### Returns


- `Void`



#### setPreFetchMode() 

Set prefetch mode to true or false.






##### Returns


- `Void`



#### isDevMode() 

Determine if dev mode is enabled.






##### Returns


- `Void`



#### setDevMode() 

Set dev mode to true or false.






##### Returns


- `Void`



#### getTCertBatchSize() 

Get the tcert batch size.






##### Returns


- `Void`



#### setTCertBatchSize() 

Set the tcert batch size.






##### Returns


- `Void`



#### getOrganizationUnits() 

Get organizational unit identifiers from
the MSP's for this channel






##### Returns


- `Array.&lt;string&gt;`  



#### setMSPManager(the) 

Set the MSP Manager for this channel
This utility method will not normally be use as the
`initialize()` method will read this channel's
current configuration and reset MSPManager with
the MSP's found.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| the | `MSPManager`  | msp manager for this channel | &nbsp; |




##### Returns


- `Void`



#### getMSPManager() 

Get the MSP Manager for this channel






##### Returns


- `MSPManager`  



#### addPeer(peer) 

Add peer endpoint to chain.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| peer | `Peer`  | An instance of the Peer class that has been initialized with URL, TLC certificate, and enrollment certificate. | &nbsp; |




##### Returns


- `Void`



#### removePeer(peer) 

Remove peer endpoint from chain.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| peer | `Peer`  | An instance of the Peer class. | &nbsp; |




##### Returns


- `Void`



#### getPeers() 

Get peers of a chain from local information.






##### Returns


- `Array.&lt;Peer&gt;`  The peer list on the chain.



#### setPrimaryPeer(peer) 

Set the primary peer
The peer to use for doing queries.
Peer must be a peer on this chain's peer list.
Default: When no primary peer has been set the first peer
on the list will be used.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| peer | `Peer`  | An instance of the Peer class. | &nbsp; |




##### Returns


- `Void`



#### getPrimaryPeer() 

Get the primary peer
The peer to use for doing queries.
Default: When no primary peer has been set the first peer
on the list will be used.






##### Returns


- `Peer`  peer An instance of the Peer class.



#### addOrderer(orderer) 

Add orderer endpoint to a chain object, this is a local-only operation.
A chain instance may choose to use a single orderer node, which will broadcast
requests to the rest of the orderer network. Or if the application does not trust
the orderer nodes, it can choose to use more than one by adding them to the chain instance.
All APIs concerning the orderer will broadcast to all orderers simultaneously.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| orderer | `Orderer`  | An instance of the Orderer class. | &nbsp; |




##### Returns


- `Void`



#### removeOrderer(orderer) 

Remove orderer endpoint from a chain object, this is a local-only operation.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| orderer | `Orderer`  | An instance of the Orderer class. | &nbsp; |




##### Returns


- `Void`



#### getOrderers() 

Get orderers of a chain.






##### Returns


- `Void`



#### createChannel(request) 

Calls the orderer(s) to start building the new chain.
Only one of the application instances needs to call this method.
Once the chain is successfully created, this and other application
instances only need to call joinChannel() to participate on the channel.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| request | `Object`  | - An object containing the following field: 		<br>`envelope` : required - byte[] of the envelope object containing
                         all required settings to initialize this channel | &nbsp; |




##### Returns


- `boolean`  Whether the chain initialization process was successful.



#### joinChannel(request) 

Sends a join channel proposal to one or more endorsing peers
Will get the genesis block from the defined orderer to be used
in the proposal.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| request | `Object`  | - An object containing the following fields: 		<br>`targets` : required - An array of `Peer` objects that will join
                     this channel
		<br>`txId` : required - String of the transaction id
		<br>`nonce` : required - Integer of the once time number | &nbsp; |




##### Returns


- `Promise`  A Promise for a `ProposalResponse`



#### getChannelConfig() 

Queries for the current config block for this chain(channel).
This transaction will be made to the orderer.






##### Returns


- `ConfigEnvelope`  Object containing the configuration items.



#### loadConfigEnvelope(the) 

Utility method to load this chain with configuration information
from a Configuration block




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| the | `ConfigEnvelope`  | envelope with the configuration items | &nbsp; |




##### Returns


- `Void`



#### loadConfigGroup(-, -) 

utility method to load in a config group




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| - | `bool`  | top - to handle the differences in the structure of groups | &nbsp; |
| - | `bool`  | keep_children - once we start keeping a group, want to keep all                 children's settings | &nbsp; |




##### Returns


- `Void`



#### loadConfigValue() 

utility method to load in a config value






##### Returns


- `Void`



#### loadConfigPolicy() 

utility method to load in a config policy






##### Returns


- `Void`



#### updateChain() 

Calls the orderer(s) to update an existing chain. This allows the addition and
deletion of Peer nodes to an existing chain, as well as the update of Peer
certificate information upon certificate renewals.






##### Returns


- `boolean`  Whether the chain update process was successful.



#### isReadonly() 

Get chain status to see if the underlying channel has been terminated,
making it a read-only chain, where information (transactions and states)
can be queried but no new transactions can be submitted.






##### Returns


- `boolean`  Is read-only, true or not.



#### queryInfo() 

Queries for various useful information on the state of the Chain
(height, known peers).
This query will be made to the primary peer.






##### Returns


- `object`  With height, currently the only useful info.



#### queryBlockByHash(block) 

Queries the ledger for Block by block hash.
This query will be made to the primary peer.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| block | `Array.&lt;byte&gt;`  | hash of the Block. | &nbsp; |




##### Returns


- `object`  Object containing the block.



#### queryBlock(blockNumber) 

Queries the ledger for Block by block number.
This query will be made to the primary peer.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| blockNumber | `number`  | The number which is the ID of the Block. | &nbsp; |




##### Returns


- `object`  Object containing the block.



#### queryTransaction(transactionID) 

Queries the ledger for Transaction by number.
This query will be made to the primary peer.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| transactionID | `number`  |  | &nbsp; |




##### Returns


- `object`  Transaction information containing the transaction.



#### queryInstalledChaincodes(peer) 

Queries the installed chaincodes on a peer
returning the details of all chaincodes
installed on a peer.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| peer | `Peer`  |  | &nbsp; |




##### Returns


- `object`  ChaincodeQueryResponse proto



#### queryInstantiatedChaincodes() 

Queries the instantiated chaincodes on this channel.






##### Returns


- `object`  ChaincodeQueryResponse proto



#### queryChannels(peer) 

Queries the names of all the channels that a
peer has joined.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| peer | `Peer`  |  | &nbsp; |




##### Returns


- `object`  ChannelQueryResponse proto



#### sendInstallProposal(request) 

Sends an install proposal to one or more endorsing peers.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| request | `Object`  | - An object containing the following fields: 		<br>`chaincodePath` : required - String of the path to location of
                           the source code of the chaincode
		<br>`chaincodeId` : required - String of the name of the chaincode
		<br>`chaincodeVersion` : required - String of the version of the chaincode
		<br>`chaincodePackage` : optional - Byte array of the archive content for
                              the chaincode source. The archive must have a 'src'
                              folder containing subfolders corresponding to the
                              'chaincodePath' field. For instance, if the chaincodePath
                              is 'mycompany/myproject', then the archive must contain a
                              folder at the path 'src/mycompany/myproject', where the
                              GO source code resides.
		<br>`chaincodeType` : optional - Type of chaincode ['golang', 'car', 'java']
                  (default 'golang')
		<br>`txId` : required - String of the transaction id
		<br>`nonce` : required - Integer of the once time number | &nbsp; |




##### Returns


- `Promise`  A Promise for a `ProposalResponse`



#### sendInstantiateProposal(request) 

Sends an instantiate proposal to one or more endorsing peers.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| request | `Object`  | - An object containing the following fields: 		<br>`chaincodeType` : optional -- Type of chaincode ['golang', 'car', 'java']
                           (default 'golang')
		<br>`chaincodePath` : required - String of the path to location of
                           the source code of the chaincode
		<br>`chaincodeId` : required - String of the name of the chaincode
		<br>`chaincodeVersion` : required - String of the version of the chaincode
		<br>`chainId` : required - String of the name of the chain
		<br>`txId` : required - String of the transaction id
		<br>`nonce` : required - Integer of the once time number
		<br>`fcn` : optional - String of the function to be called on
                 the chaincode once instantiated (default 'init')
		<br>`args` : optional - String Array arguments specific to
                  the chaincode being instantiated | &nbsp; |




##### Returns


- `Promise`  A Promise for a `ProposalResponse`



#### sendTransactionProposal(request) 

Sends a transaction proposal to one or more endorsing peers.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| request | `Object`  | 		<br>`chaincodeId` : The id of the chaincode to perform the transaction proposal
		<br>`chainId` : required - String of the name of the chain
		<br>`txId` : required - String of the transaction id
		<br>`nonce` : required - Integer of the once time number
		<br>`args` : an array of arguments specific to the chaincode 'invoke' | &nbsp; |




##### Returns


- `Promise`  A Promise for a `ProposalResponse`



#### sendTransaction(proposalResponses, chaincodeProposal) 

Sends the orderer an endorsed proposal.
The caller must use the proposal response returned from the endorser along
with the original proposal request sent to the endorser.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| proposalResponses | `Array`  | - An array or single {ProposalResponse} objects containing        the response from the endorsement | &nbsp; |
| chaincodeProposal | `Proposal`  | - A Proposal object containing the original        request for endorsement(s) | &nbsp; |




##### Returns


- `Promise`  A Promise for a `BroadcastResponse`.         This will be an acknowledgement from the orderer of successfully submitted transaction.



#### queryByChaincode(request) 

Sends a proposal to one or more endorsing peers that will be handled by the chaincode.
This request will be presented to the chaincode 'invoke' and must understand
from the arguments that this is a query request. The chaincode must also return
results in the byte array format and the caller will have to be able to decode
these results




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| request | `Object`  | A JSON object with the following 		<br>targets : An array or single Endorsing {@link Peer} objects as the targets of the request
		<br>chaincodeId : The id of the chaincode to perform the query
		<br>`args` : an array of arguments specific to the chaincode 'innvoke'
            that represent a query invocation on that chaincode | &nbsp; |




##### Returns


- `Promise`  A Promise for an array of byte array results from the chaincode on all Endorsing Peers



#### _buildProposal()  *private method*








##### Returns


- `Void`



#### _sendPeersProposal()  *private method*








##### Returns


- `Void`



#### _signProposal()  *private method*








##### Returns


- `Void`



#### _checkProposalRequest()  *private method*








##### Returns


- `Void`



#### _checkInstallRequest()  *private method*








##### Returns


- `Void`



#### _checkInstantiateRequest()  *private method*








##### Returns


- `Void`



#### buildTransactionID(nonce, userContext) 

Utility method to build an unique transaction id
based on a nonce and this chain's user.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| nonce | `int`  | - a one time use number | &nbsp; |
| userContext | `User`  | - the user context | &nbsp; |




##### Returns


- `string`  An unique string



#### buildTransactionID_getUserContext(nonce) 

Utility method to build an unique transaction id
based on a nonce and this chain's user.
Gets the user context.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| nonce | `int`  | - a one time use number | &nbsp; |




##### Returns


- `Promise`  A promise for the transaction id



#### _getChaincodePackageData()  *private method*








##### Returns


- `Void`



#### toString() 

return a printable representation of this object






##### Returns


- `Void`




### fabric-client/lib/Peer.js


#### Peer() 

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






##### Returns


- `Void`



#### constructor(url, opts) 

Constructs a Peer given its endpoint configuration settings.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| url | `string`  | The URL with format of "grpcs://host:port". | &nbsp; |
| opts | `Object`  | The options for the connection to the peer. | &nbsp; |




##### Returns


- `Void`



#### connectEventSource() 

Since practically all Peers are event producers, when constructing a Peer instance,
an application can designate it as the event source for the application. Typically
only one of the Peers on a Chain needs to be the event source, because all Peers on
the Chain produce the same events. This method tells the SDK which Peer(s) to use as
the event source for the client application. It is the responsibility of the SDK to
manage the connection lifecycle to the Peer’s EventHub. It is the responsibility of
the Client Application to understand and inform the selected Peer as to which event
types it wants to receive and the call back functions to use.






##### Returns


- `Promise`  This gives the app a handle to attach “success” and “error” listeners



#### isEventListened(eventName, chain) 

A network call that discovers if at least one listener has been connected to the target
Peer for a given event. This helps application instance to decide whether it needs to
connect to the event source in a crash recovery or multiple instance instantiation.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| eventName | `string`  | required | &nbsp; |
| chain | `Chain`  | optional | &nbsp; |




##### Returns


- `Void`



#### addListener(eventType, eventTypeData, eventCallback) 

For a Peer that is connected to eventSource, the addListener registers an EventCallBack for a
set of event types. addListener can be invoked multiple times to support differing EventCallBack
functions receiving different types of events.

Note that the parameters below are optional in certain languages, like Java, that constructs an
instance of a listener interface, and pass in that instance as the parameter.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| eventType | `string`  | : ie. Block, Chaincode, Transaction | &nbsp; |
| eventTypeData | `object`  | : Object Specific for event type as necessary, currently needed for “Chaincode” event type, specifying a matching pattern to the event name set in the chaincode(s)
being executed on the target Peer, and for “Transaction” event type, specifying the transaction ID | &nbsp; |
| eventCallback | `class`  | Client Application class registering for the callback. | &nbsp; |




##### Returns


- `string`  An ID reference to the event listener.



#### removeListener(eventListenerRef) 

Unregisters a listener.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| eventListenerRef | `string`  | Reference returned by SDK for event listener. | &nbsp; |




##### Returns


- `boolean`  Success / Failure status



#### getName() 

Get the Peer name. Required property for the instance objects.






##### Returns


- `string`  The name of the Peer



#### setName(name) 

Set the Peer name / id.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| name | `string`  |  | &nbsp; |




##### Returns


- `Void`



#### getRoles() 

Get the user’s roles the Peer participates in. It’s an array of possible values
in “client”, and “auditor”. The member service defines two more roles reserved
for peer membership: “peer” and “validator”, which are not exposed to the applications.






##### Returns


- `Array.&lt;string&gt;`  The roles for this user.



#### setRoles(roles) 

Set the user’s roles the Peer participates in. See getRoles() for legitimate values.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| roles | `Array.&lt;string&gt;`  | The list of roles for the user. | &nbsp; |




##### Returns


- `Void`



#### getEnrollmentCertificate() 

Returns the Peer's enrollment certificate.






##### Returns


- `object`  Certificate in PEM format signed by the trusted CA



#### setEnrollmentCertificate(enrollment) 

Set the Peer’s enrollment certificate.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| enrollment | `object`  | Certificate in PEM format signed by the trusted CA | &nbsp; |




##### Returns


- `Void`



#### sendProposal(proposal) 

Send an endorsement proposal to an endorser.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| proposal | `Proposal`  | A proposal of type Proposal | &nbsp; |




##### Returns


-  Promise for a ProposalResponse



#### toString() 

return a printable representation of this object






##### Returns


- `Void`




### fabric-client/lib/User.js


#### User() 

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






##### Returns


- `Void`



#### constructor(cfg) 

Constructor for a member.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| cfg | `string`  | - The member name or an object with the following attributes:   - enrollmentID {string}: user name
  - name {string}: user name, if "enrollmentID" is also specified, the "name" is ignored
  - roles {string[]}: optional. array of roles
  - affiliation {string}: optional. affiliation with a group or organization | &nbsp; |




##### Returns


- `Void`



#### getName() 

Get the member name.






##### Returns


- `string`  The member name.



#### getRoles() 

Get the roles.






##### Returns


- `Array.&lt;string&gt;`  The roles.



#### setRoles(roles) 

Set the roles.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| roles |  | {string[]} The roles. | &nbsp; |




##### Returns


- `Void`



#### getAffiliation() 

Get the affiliation.






##### Returns


- `string`  The affiliation.



#### setAffiliation(affiliation) 

Set the affiliation.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| affiliation | `string`  | The affiliation. | &nbsp; |




##### Returns


- `Void`



#### getIdentity() 

Get the {@link Identity} object for this User instance, used to verify signatures






##### Returns


- `Identity`  the identity object that encapsulates the user's enrollment certificate



#### getSigningIdentity() 

Get the {@link SigningIdentity} object for this User instance, used to generate signatures






##### Returns


- `SigningIdentity`  the identity object that encapsulates the user's private key for signing



#### setEnrollment(privateKey, certificate, mspId, opts) 

Set the enrollment object for this User instance




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| privateKey | `Key`  | the private key object | &nbsp; |
| certificate | `string`  | the PEM-encoded string of certificate | &nbsp; |
| mspId | `string`  | The Member Service Provider id for the local signing identity | &nbsp; |
| opts | `object`  | optional. an object with the following attributes, all optional:   - cryptoSettings: {object} an object with the following attributes:
     - software {boolean}: Whether to load a software-based implementation (true) or HSM implementation (false)
default is true (for software based implementation), specific implementation module is specified
in the setting 'crypto-suite-software'
     - keysize {number}: The key size to use for the crypto suite instance. default is value of the setting 'crypto-keysize'
     - algorithm {string}: Digital signature algorithm, currently supporting ECDSA only with value "EC"
     - hash {string}: 'SHA2' or 'SHA3'
  - KVSImplClass: {function} the User class persists crypto keys in a {@link CryptoKeyStore}, there is a file-based implementation
that is provided as the default. Application can use this parameter to override the default, such as saving the keys in a key store
backed by database. If present, the value must be the class for the alternative implementation.
  - kvsOpts: {object}: an options object specific to the implementation in KVSImplClass | &nbsp; |




##### Returns


- `Promise`  Promise for successful completion of creating the user's signing Identity



#### getTCertBatchSize() 

Get the transaction certificate (tcert) batch size, which is the number of tcerts retrieved
from member services each time (i.e. in a single batch).






##### Returns


- `int`  The tcert batch size.



#### setTCertBatchSize(batchSize) 

Set the transaction certificate (tcert) batch size.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| batchSize | `int`  |  | &nbsp; |




##### Returns


- `Void`



#### isEnrolled() 

Determine if this name has been enrolled.






##### Returns


- `boolean`  True if enrolled; otherwise, false.



#### fromString() 

Set the current state of this member from a string based JSON object






##### Returns


- `Member`  Promise of the unmarshalled Member object represented by the serialized string



#### toString() 

Save the current state of this member as a string






##### Returns


- `string`  The state of this member as a string




### fabric-client/lib/Client.js


#### Client() 

Main interaction handler with end user. A client instance provides a handler to interact
with a network of peers, orderers and optionally member services. An application using the
SDK may need to interact with multiple networks, each through a separate instance of the Client.

Each client when initially created should be initialized with configuration data from the
consensus service, which includes a list of trusted roots, orderer certificates and IP addresses,
and a list of peer certificates and IP addresses that it can access. This must be done out of band
as part of bootstrapping the application environment. It is also the responsibility of the application
to maintain the configuration of a client as the SDK does not persist this object.

Each Client instance can maintain several {@link Chain} instances representing channels and the associated
private ledgers.






##### Returns


- `Void`



#### newChain(name) 

Returns a chain instance with the given name. This represents a channel and its associated ledger
(as explained above), and this call returns an empty object. To initialize the chain in the blockchain network,
a list of participating endorsers and orderer peers must be configured first on the returned object.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| name | `string`  | The name of the chain. Recommend using namespaces to avoid collision. | &nbsp; |




##### Returns


- `Chain`  The uninitialized chain instance.



#### getChain(name) 

Get a {@link Chain} instance from the state storage. This allows existing chain instances to be saved
for retrieval later and to be shared among instances of the application. Note that it’s the
application/SDK’s responsibility to record the chain information. If an application is not able
to look up the chain information from storage, it may call another API that queries one or more
Peers for that information.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| name | `string`  | The name of the chain. | &nbsp; |




##### Returns


- `Chain`  The chain instance



#### queryChainInfo(name, peers) 

This is a network call to the designated Peer(s) to discover the chain information.
The target Peer(s) must be part of the chain to be able to return the requested information.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| name | `string`  | The name of the chain. | &nbsp; |
| peers | `Array.&lt;Peer&gt;`  | Array of target Peers to query. | &nbsp; |




##### Returns


- `Chain`  The chain instance for the name or error if the target Peer(s) does not know anything about the chain.



#### setStateStore(keyValueStore) 

The enrollment materials for Users that have appeared in the instances of the application.

The SDK should have a built-in key value store file-based implementation to allow easy setup during
development. Production systems would use a store backed by database for more robust storage and
clustering, so that multiple app instances can share app state via the database.
This API makes this pluggable so that different store implementations can be selected by the application.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| keyValueStore | `KeyValueStore`  | Instance of an alternative KeyValueStore implementation provided by the consuming app. | &nbsp; |




##### Returns


- `Void`



#### saveUserToStateStore() 

Save the state of this member to the key value store.






##### Returns


- `Promise`  A Promise for the user context object upon successful save



#### setUserContext(user, skipPersistence) 

Sets an instance of the User class as the security context of self client instance. This user’s
credentials (ECert), or special transaction certificates that are derived from the user's ECert,
will be used to conduct transactions and queries with the blockchain network.
Upon setting the user context, the SDK saves the object in a persistence cache if the “state store”
has been set on the Client instance. If no state store has been set, this cache will not be established
and the application is responsible for setting the user context again if the application crashes and is recovered.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| user | `User`  | An instance of the User class encapsulating the authenticated user’s signing materials (private key and enrollment certificate) | &nbsp; |
| skipPersistence | `boolean`  | Whether to skip saving the user object into persistence. Default is false and the method will attempt to save the user object to the state store. | &nbsp; |




##### Returns


- `Promise`  Promise of the 'user' object upon successful persistence of the user to the state store



#### getUserContext(name) 

As explained above, the client instance can have an optional state store. The SDK saves enrolled users
in the storage which can be accessed by authorized users of the application (authentication is done by
the application outside of the SDK). This function attempts to load the user by name from the local storage
(via the KeyValueStore interface). The loaded user object must represent an enrolled user with a valid
enrollment certificate signed by a trusted CA (such as the CA server).




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| name | `String`  | Optional. If not specified, will only return the in-memory user context object, or null if not found in memory. If "name" is specified, will also attempt to load it from the state store if search
in memory failed. | &nbsp; |




##### Returns


- `Promise`  The user object corresponding to the name, or null if the user does not exist or if the state store has not been set.



#### loadUserFromStateStore() 

Restore the state of this member from the key value store (if found).  If not found, do nothing.






##### Returns


- `Promise`  A Promise for a {User} object upon successful restore, or if the user by the name does not exist in the state store, returns null without rejecting the promise



#### getStateStore() 

A convenience method for obtaining the state store object in use for this client.






##### Returns


- `KeyValueStore`  The KeyValueStore implementation object set within this Client, or null if it does not exist.



#### newDefaultKeyValueStore(options) 

Obtains an instance of the [KeyValueStore]{@link module:api.KeyValueStore} class. By default
it returns the built-in implementation, which is based on files ([FileKeyValueStore]{@link module:api.FileKeyValueStore}).
This can be overriden with an environment variable KEY_VALUE_STORE, the value of which is the
full path of a CommonJS module for the alternative implementation.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| options | `Object`  | is whatever the implementation requires for initializing the instance. For the built-in file-based implementation, this requires a single property "path" to the top-level folder for the store | &nbsp; |




##### Returns


-  [KeyValueStore]{@link module:api.KeyValueStore} an instance of the KeyValueStore implementation



#### setLogger(logger) 

Configures a logger for the entire HFC SDK to use and override the default logger. Unless this method is called,
HFC uses a default logger (based on winston). When using the built-in "winston" based logger, use the environment
variable HFC_LOGGING to pass in configurations in the following format:

{
  'error': 'error.log',				// 'error' logs are printed to file 'error.log' relative of the current working dir for node.js
  'debug': '/tmp/myapp/debug.log',	// 'debug' and anything more critical ('info', 'warn', 'error') can also be an absolute path
  'info': 'console'					// 'console' is a keyword for logging to console
}




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| logger | `Object`  | a logger instance that defines the following methods: debug(), info(), warn(), error() with string interpolation methods like [util.format]{@link https://nodejs.org/api/util.html#util_util_format_format}. | &nbsp; |




##### Returns


- `Void`



#### addConfigFile(path) 

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




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| path | `String`  | - The path to the file to be added to the top of list of configuration files | &nbsp; |




##### Returns


- `Void`



#### setConfigSetting(name, value) 

Adds a setting to override all settings that are
part of the hierarchical configuration.

hierarchy search order:
 1. memory - settings added with this call
 2. Command-line arguments
 3. Environment variables (names will be change from AAA-BBB to aaa-bbb)
 4. Custom Files - all files added with the addConfigFile(path)
    will be ordered by when added, were last one added will override previously added files
 5. The file located at 'config/default.json' with default settings




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| name | `String`  | - The name of a setting | &nbsp; |
| value | `Object`  | - The value of a setting | &nbsp; |




##### Returns


- `Void`



#### getConfigSetting(name, default_value) 

Retrieves a setting from the hierarchical configuration and if not found
will return the provided default value.

hierarchy search order:
 1. memory - settings added with sdkUtils.setConfigSetting(name,value)
 2. Command-line arguments
 3. Environment variables (names will be change from AAA-BBB to aaa-bbb)
 4. Custom Files - all files added with the addConfigFile(path)
    will be ordered by when added, were last one added will override previously added files
 5. The file located at 'config/default.json' with default settings




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| name | `String`  | - The name of a setting | &nbsp; |
| default_value | `Object`  | - The value of a setting if not found in the hierarchical configuration | &nbsp; |




##### Returns


- `Void`




### fabric-client/lib/EventHub.js


#### ChainCodeCBE() 

The ChainCodeCBE is used internal to the EventHub to hold chaincode
event registration callbacks.






##### Returns


- `Void`



#### constructor(ccid, eventNameFilter, cb) 

Constructs a chaincode callback entry




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| ccid | `string`  | chaincode id | &nbsp; |
| eventNameFilter | `string`  | The regex used to filter events | &nbsp; |
| cb | `function`  | Callback for filter matches | &nbsp; |




##### Returns


- `Void`



#### EventHub() 

The EventHub class is used to distribute events from an
event source(peer)






##### Returns


- `Void`



#### constructor() 

Constructs an unconnected EventHub






##### Returns


- `Void`



#### setPeerAddr(peeraddr, opts) 

Set peer url for event source<p>
Note: Only use this if creating your own EventHub. The chain
class creates a default eventHub that most Node clients can
use (see eventHubConnect, eventHubDisconnect and getEventHub).




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| peeraddr | `string`  | peer url | &nbsp; |
| opts | `object`  | An Object that may contain options to pass to grpcs calls <br>- pem {string} The certificate file, in PEM format,
   to use with the gRPC protocol (that is, with TransportCredentials).
   Required when using the grpcs protocol.
<br>- ssl-target-name-override {string} Used in test environment only, when the server certificate's
   hostname (in the 'CN' field) does not match the actual host endpoint that the server process runs
   at, the application can work around the client TLS verify failure by setting this property to the
   value of the server certificate's hostname
<br>- any other standard grpc call options will be passed to the grpc service calls directly | &nbsp; |




##### Returns


- `Void`



#### isconnected() 

Get connected state of eventhub






##### Returns


-  true if connected to event source, false otherwise



#### connect() 

Establishes connection with peer event source<p>
Note: Only use this if creating your own EventHub. The chain
class creates a default eventHub that most Node clients can
use (see eventHubConnect, eventHubDisconnect and getEventHub).






##### Returns


- `Void`



#### disconnect() 

Disconnects peer event source<p>
Note: Only use this if creating your own EventHub. The chain
class creates a default eventHub that most Node clients can
use (see eventHubConnect, eventHubDisconnect and getEventHub).






##### Returns


- `Void`



#### registerChaincodeEvent(ccid, eventname, callback) 

Register a callback function to receive chaincode events.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| ccid | `string`  | string chaincode id | &nbsp; |
| eventname | `string`  | string The regex string used to filter events | &nbsp; |
| callback | `function`  | Function Callback function for filter matches that takes a single parameter which is a json object representation
of type "message ChaincodeEvent" from lib/proto/chaincodeevent.proto | &nbsp; |




##### Returns


- `object`  ChainCodeCBE object that should be treated as an opaque handle used to unregister (see unregisterChaincodeEvent)



#### unregisterChaincodeEvent(ChainCodeCBE) 

Unregister chaincode event registration




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| ChainCodeCBE | `object`  | handle returned from call to registerChaincodeEvent. | &nbsp; |




##### Returns


- `Void`



#### registerBlockEvent(callback) 

Register a callback function to receive block events.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| callback | `function`  | Function that takes a single parameter which is a json object representation of type "message Block"
from lib/proto/fabric.proto | &nbsp; |




##### Returns


- `Void`



#### unregisterBlockEvent(callback) 

Unregister block event registration




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| callback | `function`  | Function to unregister | &nbsp; |




##### Returns


- `Void`



#### registerTxEvent(txid, callback) 

Register a callback function to receive transactional events.<p>
Note: transactional event registration is primarily used by
the sdk to track instantiate and invoke completion events. Nodejs
clients generally should not need to call directly.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| txid | `string`  | string transaction id | &nbsp; |
| callback | `function`  | Function that takes a parameter which is a json object representation of type "message Transaction"
from lib/proto/fabric.proto and a parameter which is a boolean
that indicates if the transaction is invalid (true=invalid) | &nbsp; |




##### Returns


- `Void`



#### unregisterTxEvent(txid) 

Unregister transactional event registration.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| txid |  | string transaction id | &nbsp; |




##### Returns


- `Void`



#### txCallback(block) 

private internal callback for processing tx events




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| block | `object`  | json object representing block of tx from the fabric | &nbsp; |




##### Returns


- `Void`




### fabric-client/lib/Remote.js


#### Remote() 

The Remote class represents a the base class for all remote nodes, Peer, Orderer , and MemberServicespeer.






##### Returns


- `Void`



#### constructor(url, opts) 

Constructs an object with the endpoint configuration settings.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| url | `string`  | The orderer URL with format of 'grpc(s)://host:port'. | &nbsp; |
| opts | `object`  | An Object that may contain options to pass to grpcs calls <br>- pem {string} The certificate file, in PEM format,
   to use with the gRPC protocol (that is, with TransportCredentials).
   Required when using the grpcs protocol.
<br>- ssl-target-name-override {string} Used in test environment only, when the server certificate's
   hostname (in the 'CN' field) does not match the actual host endpoint that the server process runs
   at, the application can work around the client TLS verify failure by setting this property to the
   value of the server certificate's hostname
<br>- any other standard grpc call options will be passed to the grpc service calls directly | &nbsp; |




##### Returns


- `Void`



#### getUrl() 

Get the URL of the orderer.






##### Returns


- `string`  Get the URL associated with the Orderer.



#### toString() 

return a printable representation of this object






##### Returns


- `Void`




### fabric-ca-client/index.js


#### module.exports() 

This is the main module for the "fabric-ca-client" package. It communicates with the
"fabric-ca" server to manage user certificates lifecycle including register, enroll,
renew and revoke, so that the application can use the properly signed certificates to
authenticate with the fabric






##### Returns


- `Void`




### fabric-ca-client/lib/FabricCAClientImpl.js


#### FabricCAServices() 

This is an implementation of the member service client which communicates with the Fabric CA server.






##### Returns


- `Void`



#### constructor(url, tlsOptions, cryptoSetting, KVSImplClass, opts) 

constructor




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| url | `string`  | The endpoint URL for Fabric CA services of the form: "http://host:port" or "https://host:port" | &nbsp; |
| tlsOptions | `TLSOptions`  | The TLS settings to use when the Fabric CA services endpoint uses "https" | &nbsp; |
| cryptoSetting | `object`  | This optional parameter is an object with the following optional properties: - software {boolean}: Whether to load a software-based implementation (true) or HSM implementation (false)
	default is true (for software based implementation), specific implementation module is specified
	in the setting 'crypto-suite-software'
- keysize {number}: The key size to use for the crypto suite instance. default is value of the setting 'crypto-keysize'
- algorithm {string}: Digital signature algorithm, currently supporting ECDSA only with value "EC" | &nbsp; |
| KVSImplClass | `function`  | Optional. The built-in key store saves private keys. The key store may be backed by different {@link KeyValueStore} implementations. If specified, the value of the argument must point to a module implementing the
KeyValueStore interface. | &nbsp; |
| opts | `object`  | Implementation-specific options object for the {@link KeyValueStore} class to instantiate an instance | &nbsp; |




##### Returns


- `Void`



#### register(req, registrar) 

Register the member and return an enrollment secret.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| req | `Object`  | Registration request with the following fields: <br> - enrollmentID {string}. ID which will be used for enrollment
<br> - role {string}. An arbitrary string representing a role value for the user
<br> - affiliation {string}. Affiliation with which this user will be associated, like a company or an organization
<br> - maxEnrollments {number}. The maximum number of times this user will be permitted to enroll
<br> - attrs {{@link KeyValueAttribute}[]}. Array of key/value attributes to assign to the user. | &nbsp; |
| registrar |  | {User}. The identity of the registrar (i.e. who is performing the registration) | &nbsp; |




##### Returns


- `Promise`  The enrollment secret to use when this user enrolls



#### enroll(req) 

Enroll the member and return an opaque member object.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| req |  | Enrollment request | &nbsp; |
| req.enrollmentID | `string`  | The registered ID to use for enrollment | &nbsp; |
| req.enrollmentSecret | `string`  | The secret associated with the enrollment ID | &nbsp; |




##### Returns


-  Promise for an object with "key" for private key and "certificate" for the signed certificate



#### revoke(request, registrar) 

Revoke an existing certificate (enrollment certificate or transaction certificate), or revoke
all certificates issued to an enrollment id. If revoking a particular certificate, then both
the Authority Key Identifier and serial number are required. If revoking by enrollment id,
then all future requests to enroll this id will be rejected.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| request | `Object`  | Request object with the following fields: <br> - enrollmentID {string}. ID to revoke
<br> - aki {string}. Authority Key Identifier string, hex encoded, for the specific certificate to revoke
<br> - serial {string}. Serial number string, hex encoded, for the specific certificate to revoke
<br> - reason {string}. The reason for revocation. See https://godoc.org/golang.org/x/crypto/ocsp
 for valid values. The default value is 0 (ocsp.Unspecified). | &nbsp; |
| registrar | `User`  | The identity of the registrar (i.e. who is performing the revocation) | &nbsp; |




##### Returns


- `Promise`  The revocation results



#### _parseURL(url) 

Utility function which parses an HTTP URL into its component parts




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| url | `string`  | HTTP or HTTPS url including protocol, host and port | &nbsp; |




##### Returns


- `HTTPEndpoint`  



#### toString() 

return a printable representation of this object






##### Returns


- `Void`



#### FabricCAClient() 

Client for communciating with the Fabric CA APIs






##### Returns


- `Void`



#### constructor(connect_opts) 

constructor




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| connect_opts | `object`  | Connection options for communciating with the Fabric CA server | &nbsp; |
| connect_opts.protocol | `string`  | The protocol to use (either HTTP or HTTPS) | &nbsp; |
| connect_opts.hostname | `string`  | The hostname of the Fabric CA server endpoint | &nbsp; |
| connect_opts.port | `number`  | The port of the Fabric CA server endpoint | &nbsp; |
| connect_opts.tlsOptions | `TLSOptions`  | The TLS settings to use when the Fabric CA endpoint uses "https" | &nbsp; |




##### Returns


- `Void`



#### register(enrollmentID, role, affiliation, maxEnrollments, attrs, signingIdentity) 

Register a new user and return the enrollment secret




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| enrollmentID | `string`  | ID which will be used for enrollment | &nbsp; |
| role | `string`  | Type of role for this user | &nbsp; |
| affiliation | `string`  | Affiliation with which this user will be associated | &nbsp; |
| maxEnrollments | `number`  | The maximum number of times the user is permitted to enroll | &nbsp; |
| attrs | `Array.&lt;KeyValueAttribute&gt;`  | Array of key/value attributes to assign to the user | &nbsp; |
| signingIdentity | `SigningIdentity`  | The instance of a SigningIdentity encapsulating the signing certificate, hash algorithm and signature algorithm | &nbsp; |




##### Returns


- `Promise`  The enrollment secret to use when this user enrolls



#### revoke(enrollmentID, aki, serial, reason, signingIdentity) 

Revoke an existing certificate (enrollment certificate or transaction certificate), or revoke
all certificates issued to an enrollment id. If revoking a particular certificate, then both
the Authority Key Identifier and serial number are required. If revoking by enrollment id,
then all future requests to enroll this id will be rejected.




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| enrollmentID | `string`  | ID to revoke | &nbsp; |
| aki | `string`  | Authority Key Identifier string, hex encoded, for the specific certificate to revoke | &nbsp; |
| serial | `string`  | Serial number string, hex encoded, for the specific certificate to revoke | &nbsp; |
| reason | `string`  | The reason for revocation. See https://godoc.org/golang.org/x/crypto/ocsp  for valid values | &nbsp; |
| signingIdentity | `SigningIdentity`  | The instance of a SigningIdentity encapsulating the signing certificate, hash algorithm and signature algorithm | &nbsp; |




##### Returns


- `Promise`  The revocation results



#### generateAuthToken() 

Generate authorization token required for accessing fabric-ca APIs






##### Returns


- `Void`



#### enroll(enrollmentID, enrollmentSecret, csr) 

Enroll a registered user in order to receive a signed X509 certificate




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| enrollmentID | `string`  | The registered ID to use for enrollment | &nbsp; |
| enrollmentSecret | `string`  | The secret associated with the enrollment ID | &nbsp; |
| csr | `string`  | PEM-encoded PKCS#10 certificate signing request | &nbsp; |




##### Returns


- `Promise`  {@link EnrollmentResponse}



#### pemToDER({string) pem PEM encoded public or private key) 

Convert a PEM encoded certificate to DER format




##### Parameters

| Name | Type | Description |  |
| ---- | ---- | ----------- | -------- |
| {string) pem PEM encoded public or private key |  |  | &nbsp; |




##### Returns


- `string`  hex Hex-encoded DER bytes



#### _validateConnectionOpts() 

Validate the connection options






##### Returns


- `Void`




*Documentation generated with [doxdox](https://github.com/neogeek/doxdox).*
