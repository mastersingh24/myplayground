## Modules

<dl>
<dt><a href="#module_fabric-ca-client">fabric-ca-client</a></dt>
<dd><p>This is the main module for the &quot;fabric-ca-client&quot; package. It communicates with the
&quot;fabric-ca&quot; server to manage user certificates lifecycle including register, enroll,
renew and revoke, so that the application can use the properly signed certificates to
authenticate with the fabric</p>
</dd>
<dt><a href="#module_api">api</a></dt>
<dd><p>This module defines the API for the pluggable components of the node.js SDK. The APIs are defined
according to the Hyperledger Fabric&#39;s <a href="https://docs.google.com/document/d/1R5RtIBMW9fZpli37E5Li5_Q9ve3BnQ4q3gWmGZj6Sv4/edit?usp=sharing">common SDK specification</a></p>
</dd>
</dl>

## Classes

<dl>
<dt><a href="#FabricCAServices">FabricCAServices</a></dt>
<dd><p>This is an implementation of the member service client which communicates with the Fabric CA server.</p>
</dd>
<dt><a href="#FabricCAClient">FabricCAClient</a></dt>
<dd><p>Client for communciating with the Fabric CA APIs</p>
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

## Typedefs

<dl>
<dt><a href="#TLSOptions">TLSOptions</a> : <code>Object</code></dt>
<dd></dd>
<dt><a href="#HTTPEndpoint">HTTPEndpoint</a> : <code>Object</code></dt>
<dd></dd>
<dt><a href="#KeyValueAttribute">KeyValueAttribute</a> : <code>Object</code></dt>
<dd></dd>
<dt><a href="#EnrollmentResponse">EnrollmentResponse</a> : <code>Object</code></dt>
<dd></dd>
</dl>

<a name="module_fabric-ca-client"></a>

## fabric-ca-client
This is the main module for the "fabric-ca-client" package. It communicates with the
"fabric-ca" server to manage user certificates lifecycle including register, enroll,
renew and revoke, so that the application can use the properly signed certificates to
authenticate with the fabric

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
<a name="FabricCAServices"></a>

## FabricCAServices
This is an implementation of the member service client which communicates with the Fabric CA server.

**Kind**: global class  

* [FabricCAServices](#FabricCAServices)
    * [new FabricCAServices(url, tlsOptions, cryptoSetting, KVSImplClass, opts)](#new_FabricCAServices_new)
    * [.register(req, registrar)](#FabricCAServices+register) ⇒ <code>Promise</code>
    * [.enroll(req)](#FabricCAServices+enroll) ⇒
    * [.revoke(request, registrar)](#FabricCAServices+revoke) ⇒ <code>Promise</code>
    * [.toString()](#FabricCAServices+toString)

<a name="new_FabricCAServices_new"></a>

### new FabricCAServices(url, tlsOptions, cryptoSetting, KVSImplClass, opts)
constructor


| Param | Type | Description |
| --- | --- | --- |
| url | <code>string</code> | The endpoint URL for Fabric CA services of the form: "http://host:port" or "https://host:port" |
| tlsOptions | <code>[TLSOptions](#TLSOptions)</code> | The TLS settings to use when the Fabric CA services endpoint uses "https" |
| cryptoSetting | <code>object</code> | This optional parameter is an object with the following optional properties: - software {boolean}: Whether to load a software-based implementation (true) or HSM implementation (false) 	default is true (for software based implementation), specific implementation module is specified 	in the setting 'crypto-suite-software' - keysize {number}: The key size to use for the crypto suite instance. default is value of the setting 'crypto-keysize' - algorithm {string}: Digital signature algorithm, currently supporting ECDSA only with value "EC" |
| KVSImplClass | <code>function</code> | Optional. The built-in key store saves private keys. The key store may be backed by different [KeyValueStore](KeyValueStore) implementations. If specified, the value of the argument must point to a module implementing the KeyValueStore interface. |
| opts | <code>object</code> | Implementation-specific options object for the [KeyValueStore](KeyValueStore) class to instantiate an instance |

<a name="FabricCAServices+register"></a>

### fabricCAServices.register(req, registrar) ⇒ <code>Promise</code>
Register the member and return an enrollment secret.

**Kind**: instance method of <code>[FabricCAServices](#FabricCAServices)</code>  
**Returns**: <code>Promise</code> - The enrollment secret to use when this user enrolls  

| Param | Type | Description |
| --- | --- | --- |
| req | <code>Object</code> | Registration request with the following fields: <br> - enrollmentID {string}. ID which will be used for enrollment <br> - role {string}. An arbitrary string representing a role value for the user <br> - affiliation {string}. Affiliation with which this user will be associated, like a company or an organization <br> - maxEnrollments {number}. The maximum number of times this user will be permitted to enroll <br> - attrs {[KeyValueAttribute](#KeyValueAttribute)[]}. Array of key/value attributes to assign to the user. |
| registrar | <code>[User](#User)</code> | . The identity of the registrar (i.e. who is performing the registration) |

<a name="FabricCAServices+enroll"></a>

### fabricCAServices.enroll(req) ⇒
Enroll the member and return an opaque member object.

**Kind**: instance method of <code>[FabricCAServices](#FabricCAServices)</code>  
**Returns**: Promise for an object with "key" for private key and "certificate" for the signed certificate  

| Param | Type | Description |
| --- | --- | --- |
| req |  | Enrollment request |
| req.enrollmentID | <code>string</code> | The registered ID to use for enrollment |
| req.enrollmentSecret | <code>string</code> | The secret associated with the enrollment ID |

<a name="FabricCAServices+revoke"></a>

### fabricCAServices.revoke(request, registrar) ⇒ <code>Promise</code>
Revoke an existing certificate (enrollment certificate or transaction certificate), or revoke
all certificates issued to an enrollment id. If revoking a particular certificate, then both
the Authority Key Identifier and serial number are required. If revoking by enrollment id,
then all future requests to enroll this id will be rejected.

**Kind**: instance method of <code>[FabricCAServices](#FabricCAServices)</code>  
**Returns**: <code>Promise</code> - The revocation results  

| Param | Type | Description |
| --- | --- | --- |
| request | <code>Object</code> | Request object with the following fields: <br> - enrollmentID {string}. ID to revoke <br> - aki {string}. Authority Key Identifier string, hex encoded, for the specific certificate to revoke <br> - serial {string}. Serial number string, hex encoded, for the specific certificate to revoke <br> - reason {string}. The reason for revocation. See https://godoc.org/golang.org/x/crypto/ocsp  for valid values. The default value is 0 (ocsp.Unspecified). |
| registrar | <code>[User](#User)</code> | The identity of the registrar (i.e. who is performing the revocation) |

<a name="FabricCAServices+toString"></a>

### fabricCAServices.toString()
return a printable representation of this object

**Kind**: instance method of <code>[FabricCAServices](#FabricCAServices)</code>  
<a name="FabricCAClient"></a>

## FabricCAClient
Client for communciating with the Fabric CA APIs

**Kind**: global class  

* [FabricCAClient](#FabricCAClient)
    * [new FabricCAClient(connect_opts)](#new_FabricCAClient_new)
    * _instance_
        * [.register(enrollmentID, role, affiliation, maxEnrollments, attrs, signingIdentity)](#FabricCAClient+register) ⇒ <code>Promise</code>
        * [.revoke(enrollmentID, aki, serial, reason, signingIdentity)](#FabricCAClient+revoke) ⇒ <code>Promise</code>
        * [.enroll(enrollmentID, enrollmentSecret, csr)](#FabricCAClient+enroll) ⇒ <code>Promise</code>
    * _static_
        * [.pemToDER({string))](#FabricCAClient.pemToDER) ⇒ <code>string</code>

<a name="new_FabricCAClient_new"></a>

### new FabricCAClient(connect_opts)
constructor

**Throws**:

- Will throw an error if connection options are missing or invalid


| Param | Type | Description |
| --- | --- | --- |
| connect_opts | <code>object</code> | Connection options for communciating with the Fabric CA server |
| connect_opts.protocol | <code>string</code> | The protocol to use (either HTTP or HTTPS) |
| connect_opts.hostname | <code>string</code> | The hostname of the Fabric CA server endpoint |
| connect_opts.port | <code>number</code> | The port of the Fabric CA server endpoint |
| connect_opts.tlsOptions | <code>[TLSOptions](#TLSOptions)</code> | The TLS settings to use when the Fabric CA endpoint uses "https" |

<a name="FabricCAClient+register"></a>

### fabricCAClient.register(enrollmentID, role, affiliation, maxEnrollments, attrs, signingIdentity) ⇒ <code>Promise</code>
Register a new user and return the enrollment secret

**Kind**: instance method of <code>[FabricCAClient](#FabricCAClient)</code>  
**Returns**: <code>Promise</code> - The enrollment secret to use when this user enrolls  

| Param | Type | Description |
| --- | --- | --- |
| enrollmentID | <code>string</code> | ID which will be used for enrollment |
| role | <code>string</code> | Type of role for this user |
| affiliation | <code>string</code> | Affiliation with which this user will be associated |
| maxEnrollments | <code>number</code> | The maximum number of times the user is permitted to enroll |
| attrs | <code>[Array.&lt;KeyValueAttribute&gt;](#KeyValueAttribute)</code> | Array of key/value attributes to assign to the user |
| signingIdentity | <code>SigningIdentity</code> | The instance of a SigningIdentity encapsulating the signing certificate, hash algorithm and signature algorithm |

<a name="FabricCAClient+revoke"></a>

### fabricCAClient.revoke(enrollmentID, aki, serial, reason, signingIdentity) ⇒ <code>Promise</code>
Revoke an existing certificate (enrollment certificate or transaction certificate), or revoke
all certificates issued to an enrollment id. If revoking a particular certificate, then both
the Authority Key Identifier and serial number are required. If revoking by enrollment id,
then all future requests to enroll this id will be rejected.

**Kind**: instance method of <code>[FabricCAClient](#FabricCAClient)</code>  
**Returns**: <code>Promise</code> - The revocation results  

| Param | Type | Description |
| --- | --- | --- |
| enrollmentID | <code>string</code> | ID to revoke |
| aki | <code>string</code> | Authority Key Identifier string, hex encoded, for the specific certificate to revoke |
| serial | <code>string</code> | Serial number string, hex encoded, for the specific certificate to revoke |
| reason | <code>string</code> | The reason for revocation. See https://godoc.org/golang.org/x/crypto/ocsp  for valid values |
| signingIdentity | <code>SigningIdentity</code> | The instance of a SigningIdentity encapsulating the signing certificate, hash algorithm and signature algorithm |

<a name="FabricCAClient+enroll"></a>

### fabricCAClient.enroll(enrollmentID, enrollmentSecret, csr) ⇒ <code>Promise</code>
Enroll a registered user in order to receive a signed X509 certificate

**Kind**: instance method of <code>[FabricCAClient](#FabricCAClient)</code>  
**Returns**: <code>Promise</code> - [EnrollmentResponse](#EnrollmentResponse)  
**Throws**:

- Will throw an error if all parameters are not provided
- Will throw an error if calling the enroll API fails for any reason


| Param | Type | Description |
| --- | --- | --- |
| enrollmentID | <code>string</code> | The registered ID to use for enrollment |
| enrollmentSecret | <code>string</code> | The secret associated with the enrollment ID |
| csr | <code>string</code> | PEM-encoded PKCS#10 certificate signing request |

<a name="FabricCAClient.pemToDER"></a>

### FabricCAClient.pemToDER({string)) ⇒ <code>string</code>
Convert a PEM encoded certificate to DER format

**Kind**: static method of <code>[FabricCAClient](#FabricCAClient)</code>  
**Returns**: <code>string</code> - hex Hex-encoded DER bytes  
**Throws**:

- Will throw an error if the conversation fails


| Param | Description |
| --- | --- |
| {string) | pem PEM encoded public or private key |

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
    * [.getIdentity()](#User+getIdentity) ⇒ <code>Identity</code>
    * [.getSigningIdentity()](#User+getSigningIdentity) ⇒ <code>SigningIdentity</code>
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

### user.getIdentity() ⇒ <code>Identity</code>
Get the [Identity](Identity) object for this User instance, used to verify signatures

**Kind**: instance method of <code>[User](#User)</code>  
**Returns**: <code>Identity</code> - the identity object that encapsulates the user's enrollment certificate  
<a name="User+getSigningIdentity"></a>

### user.getSigningIdentity() ⇒ <code>SigningIdentity</code>
Get the [SigningIdentity](SigningIdentity) object for this User instance, used to generate signatures

**Kind**: instance method of <code>[User](#User)</code>  
**Returns**: <code>SigningIdentity</code> - the identity object that encapsulates the user's private key for signing  
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
<a name="TLSOptions"></a>

## TLSOptions : <code>Object</code>
**Kind**: global typedef  
**Properties**

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| trustedRoots | <code>Array.&lt;string&gt;</code> |  | Array of PEM-encoded trusted root certificates |
| verify | <code>boolean</code> | <code>true</code> | Determines whether or not to verify the server certificate when using TLS |

<a name="HTTPEndpoint"></a>

## HTTPEndpoint : <code>Object</code>
**Kind**: global typedef  
**Properties**

| Name | Type |
| --- | --- |
| hostname | <code>string</code> | 
| port | <code>number</code> | 
| protocol | <code>string</code> | 

<a name="KeyValueAttribute"></a>

## KeyValueAttribute : <code>Object</code>
**Kind**: global typedef  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| name | <code>string</code> | The key used to reference the attribute |
| value | <code>string</code> | The value of the attribute |

<a name="EnrollmentResponse"></a>

## EnrollmentResponse : <code>Object</code>
**Kind**: global typedef  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| enrollmentCert | <code>string</code> | PEM-encoded X509 enrollment certificate |
| caCertChain | <code>string</code> | PEM-encoded X509 certificate chain for the issuing certificate authority |

