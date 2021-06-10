<?php

namespace SimpleSAML\Module\clave;

// TODO (IdP still stork-clave1). Make it dual mode, both at SP and IdP, just response generatin lacking


use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use SimpleSAML\Logger;

class SPlib
{
    public const VERSION = '2.0.3';

    /************ Usable constants and static vars *************/

    public const DSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1';

    public const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';

    public const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

    public const RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';

    public const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';

    public const AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';

    public const AES192_CBC = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc';

    public const AES256_CBC = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';

    public const AES128_GCM = 'http://www.w3.org/2009/xmlenc11#aes128-gcm';

    public const AES192_GCM = 'http://www.w3.org/2009/xmlenc11#aes192-gcm';

    public const AES256_GCM = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';

    public const RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';

    public const SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';

    public const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

    public const SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';

    public const SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512';

    public const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';

    public const C14N_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';

    public const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    public const EXC_C14N_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

    public const CNS_OBT = 'urn:oasis:names:tc:SAML:2.0:consent:obtained';

    public const CNS_UNS = 'urn:oasis:names:tc:SAML:2.0:consent:unspecified';

    public const CNS_PRI = 'urn:oasis:names:tc:SAML:2.0:consent:prior';

    public const CNS_IMP = 'urn:oasis:names:tc:SAML:2.0:consent:current-implicit';

    public const CNS_EXP = 'urn:oasis:names:tc:SAML:2.0:consent:current-explicit';

    public const CNS_UNA = 'urn:oasis:names:tc:SAML:2.0:consent:unavailable';

    public const CNS_INA = 'urn:oasis:names:tc:SAML:2.0:consent:inapplicable';

    public const NS_SAML2 = 'urn:oasis:names:tc:SAML:2.0:assertion';

    public const NS_SAML2P = 'urn:oasis:names:tc:SAML:2.0:protocol';

    public const NS_XMLDSIG = 'http://www.w3.org/2000/09/xmldsig#';

    public const NS_STORK = 'urn:eu:stork:names:tc:STORK:1.0:assertion';

    public const NS_STORKP = 'urn:eu:stork:names:tc:STORK:1.0:protocol';

    public const NS_XMLSCH = 'http://www.w3.org/2001/XMLSchema';

    public const NS_XSI = 'http://www.w3.org/2001/XMLSchema-instance';

    public const NS_EIDAS = 'http://eidas.europa.eu/saml-extensions';

    //TODO this one I don't know very well what it looks like. When I receive a req with data I will know it,
    // and I will know if there are 2 or 4 and it changes and how to do it if there are several
    // (I think there will be only 2 and they will be alternative, or the same one of natural and another of legal and they can be together).
    // It is used for the attribute value: transliyterated langInfo ... and for the semantic of the attrs in the xs: type, but the latter is already out of scope.
    public const NS_EIDASATT = 'http://eidas.europa.eu/attributes/naturalperson';

    public const ST_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

    public const ST_REQUESTER = 'urn:oasis:names:tc:SAML:2.0:status:Requester';

    public const ST_RESPONDER = 'urn:oasis:names:tc:SAML:2.0:status:Responder';

    public const ST_ERR_AUTH = 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed';

    public const ST_ERR_ATTR = 'urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue';

    public const ST_ERR_NIDPOL = 'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy';

    public const ST_ERR_DENIED = 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied';

    public const ATST_AVAIL = 'Available';

    public const ATST_NOTAVAIL = 'NotAvailable';

    public const ATST_WITHLD = 'Withheld';

    public const LOA_LOW = 'http://eidas.europa.eu/LoA/low';

    public const LOA_SUBST = 'http://eidas.europa.eu/LoA/substantial';

    public const LOA_HIGH = 'http://eidas.europa.eu/LoA/high';

    public const EIDAS_SPTYPE_PUBLIC = 'public';

    public const EIDAS_SPTYPE_PRIVATE = 'private';

    public const NAMEID_FORMAT_PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

    public const NAMEID_FORMAT_TRANSIENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';

    public const NAMEID_FORMAT_UNSPECIFIED = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';

    /*************************  Error treatment, log and debug  *************************/
    public const LOG_TRACE = 0;

    public const LOG_DEBUG = 1;

    public const LOG_INFO = 2;

    public const LOG_WARN = 3;

    public const LOG_ERROR = 4;

    public const LOG_CRITICAL = 5;

    public const ERR_RSA_KEY_READ = 1;

    public const ERR_X509_CERT_READ = 2;

    public const ERR_RESP_NO_MAND_ATTR = 3;

    public const ERR_BAD_XML_SYNTAX = 4;

    public const ERR_NONEXIST_STORK_ATTR = 5;

    public const ERR_NEEDED_SPEPS = 6;

    public const ERR_NEEDED_RADDR = 7;

    public const ERR_NEEDED_SPROVN = 8;

    public const ERR_BAD_ASSERT_SUBJ = 9;

    public const ERR_DUP_ASSERT_ID = 10;

    public const ERR_ASSERT_NO_ATTRS = 11;

    public const ERR_NO_COUNTRYCODE = 12;

    public const ERR_EMPTY_CERT = 13;

    public const ERR_EMPTY_KEY = 14;

    public const ERR_SAMLRESP_BADXML = 15;

    public const ERR_SAMLRESP_EMPTY = 16;

    public const ERR_SAMLRESP_STILLNOTVALID = 17;

    public const ERR_SAMLRESP_EXPIRED = 18;

    public const ERR_SAMLRESP_NOSTATUS = 19;

    public const ERR_BAD_ASSERTION = 20;

    public const ERR_NO_ASSERT_ID = 21;

    public const ERR_NO_ASSERT_ISSUER = 22;

    public const ERR_NO_ASSERT_SUBJECT = 23;

    public const ERR_SIG_VERIF_FAIL = 24;

    public const ERR_RESP_SUCC_NO_ASSERTIONS = 25;

    public const ERR_NO_SIGNATURE = 26;

    public const ERR_RESP_NO_DESTINATION = 27;

    public const ERR_RESP_NO_REQ_ID = 28;

    public const ERR_UNEXP_DEST = 29;

    public const ERR_MISSING_SIG_INFO = 30;

    public const ERR_REF_VALIDATION = 31;

    public const ERR_BAD_PUBKEY_CERT = 32;

    public const ERR_NO_INT_EXT_CERT = 33;

    public const ERR_BAD_PARAMETER = 34;

    public const ERR_UNEXP_ROOT_NODE = 35;

    public const ERR_UNEXP_REQ_ID = 36;

    public const ERR_RESP_NO_ISSUER = 37;

    public const ERR_UNEXP_ISSUER = 38;

    public const ERR_NONAUTH_ISSUER = 39;

    public const ERR_SLOREQ_EMPTY = 40;

    public const ERR_GENERIC = 99;

    private static $ATTRIBUTES = [
        'givenName' => 'http://www.stork.gov.eu/1.0/givenName',
        'surname' => 'http://www.stork.gov.eu/1.0/surname',
        'eIdentifier' => 'http://www.stork.gov.eu/1.0/eIdentifier',
        'countryCodeOfBirth' => 'http://www.stork.gov.eu/1.0/countryCodeOfBirth',
        'canonicalResidenceAddress' => 'http://www.stork.gov.eu/1.0/canonicalResidenceAddress',
        'dateOfBirth' => 'http://www.stork.gov.eu/1.0/dateOfBirth',
        'textResidenceAddress' => 'http://www.stork.gov.eu/1.0/textResidenceAddress',
        'maritalStatus' => 'http://www.stork.gov.eu/1.0/maritalStatus',
        'pseudonym' => 'http://www.stork.gov.eu/1.0/pseudonym',
        'citizenQAAlevel' => 'http://www.stork.gov.eu/1.0/citizenQAAlevel',
        'adoptedFamilyName' => 'http://www.stork.gov.eu/1.0/adoptedFamilyName',
        'title' => 'http://www.stork.gov.eu/1.0/title',
        'residencePermit' => 'http://www.stork.gov.eu/1.0/residencePermit',
        'nationalityCode' => 'http://www.stork.gov.eu/1.0/nationalityCode',
        'gender' => 'http://www.stork.gov.eu/1.0/gender',
        'fiscalNumber' => 'http://www.stork.gov.eu/1.0/fiscalNumber',
        'inheritedFamilyName' => 'http://www.stork.gov.eu/1.0/inheritedFamilyName',
        'age' => 'http://www.stork.gov.eu/1.0/age',
        'eMail' => 'http://www.stork.gov.eu/1.0/eMail',
        'signedDoc' => 'http://www.stork.gov.eu/1.0/signedDoc',
        'isAgeOver' => 'http://www.stork.gov.eu/1.0/isAgeOver',

        'placeOfBirth' => 'http://www.stork.gov.eu/1.0/placeOfBirth',

        'diplomaSupplement' => 'http://www.stork.gov.eu/1.0/diplomaSupplement',
        'currentStudiesSupplement' => 'http://www.stork.gov.eu/1.0/currentStudiesSupplement',
        'isStudent' => 'http://www.stork.gov.eu/1.0/isStudent',
        'isAcademicStaff' => 'http://www.stork.gov.eu/1.0/isAcademicStaff',
        'isTeacherOf' => 'http://www.stork.gov.eu/1.0/isTeacherOf',
        'isCourseCoordinator' => 'http://www.stork.gov.eu/1.0/isCourseCoordinator',
        'isAdminStaff' => 'http://www.stork.gov.eu/1.0/isAdminStaff',
        'habilitation' => 'http://www.stork.gov.eu/1.0/habilitation',
        'languageQualification' => 'http://www.stork.gov.eu/1.0/languageQualification',
        'academicRecommendation' => 'http://www.stork.gov.eu/1.0/academicRecommendation',
        'hasDegree' => 'http://www.stork.gov.eu/1.0/hasDegree',


        'afirmaResponse' => 'http://www.stork.gov.eu/1.0/afirmaResponse',
        'isdnie' => 'http://www.stork.gov.eu/1.0/isdnie',
        'registerType' => 'http://www.stork.gov.eu/1.0/registerType',
        'citizenQAALevel' => 'http://www.stork.gov.eu/1.0/citizenQAALevel',



        'usedIdP' => 'http://www.stork.gov.eu/1.0/usedIdP',
    ];

    private static $eIdasAttributes = [
        'PersonIdentifier' => 'http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier',
        'FirstName' => 'http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName',
        'FamilyName' => 'http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName',
        'DateOfBirth' => 'http://eidas.europa.eu/attributes/naturalperson/DateOfBirth',
        'AdditionalAttribute' => 'http://eidas.europa.eu/attributes/naturalperson/AdditionalAttribute',
        'BirthName' => 'http://eidas.europa.eu/attributes/naturalperson/BirthName',
        'CurrentAddress' => 'http://eidas.europa.eu/attributes/naturalperson/CurrentAddress',
        'Gender' => 'http://eidas.europa.eu/attributes/naturalperson/Gender',
        'PlaceOfBirth' => 'http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth',

        'D-2012-17-EUIdentifier' => 'http://eidas.europa.eu/attributes/legalperson/D-2012-17-EUIdentifier',
        'EORI' => 'http://eidas.europa.eu/attributes/legalperson/EORI',
        'LEI' => 'http://eidas.europa.eu/attributes/legalperson/LEI',
        'LegalAdditionalAttribute' => 'http://eidas.europa.eu/attributes/legalperson/LegalAdditionalAttribute',
        'LegalAddress' => 'http://eidas.europa.eu/attributes/legalperson/LegalAddress',
        'LegalName' => 'http://eidas.europa.eu/attributes/legalperson/LegalName',
        'LegalPersonIdentifier' => 'http://eidas.europa.eu/attributes/legalperson/LegalPersonIdentifier',
        'SEED' => 'http://eidas.europa.eu/attributes/legalperson/SEED',
        'SIC' => 'http://eidas.europa.eu/attributes/legalperson/SIC',
        'TaxReference' => 'http://eidas.europa.eu/attributes/legalperson/TaxReference',
        'VATRegistration' => 'http://eidas.europa.eu/attributes/legalperson/VATRegistration',

        'RepresentativeD-2012-17-EUIdentifier' => 'http://eidas.europa.eu/attributes/legalperson/representative/D-2012-17-EUIdentifier',
        'RepresentativeEORI' => 'http://eidas.europa.eu/attributes/legalperson/representative/EORI',
        'RepresentativeLEI' => 'http://eidas.europa.eu/attributes/legalperson/representative/LEI',
        'RepresentativeLegalAddress' => 'http://eidas.europa.eu/attributes/legalperson/representative/LegalAddress',
        'RepresentativeLegalName' => 'http://eidas.europa.eu/attributes/legalperson/representative/LegalName',
        'RepresentativeLegalPersonIdentifier' => 'http://eidas.europa.eu/attributes/legalperson/representative/LegalPersonIdentifier',
        'RepresentativeSEED' => 'http://eidas.europa.eu/attributes/legalperson/representative/SEED',
        'RepresentativeSIC' => 'http://eidas.europa.eu/attributes/legalperson/representative/SIC',
        'RepresentativeTaxReference' => 'http://eidas.europa.eu/attributes/legalperson/representative/TaxReference',
        'RepresentativeVATRegistration' => 'http://eidas.europa.eu/attributes/legalperson/representative/VATRegistration',

        'RepresentativeBirthName' => 'http://eidas.europa.eu/attributes/naturalperson/representative/BirthName',
        'RepresentativeCurrentAddress' => 'http://eidas.europa.eu/attributes/naturalperson/representative/CurrentAddress',
        'RepresentativeFamilyName' => 'http://eidas.europa.eu/attributes/naturalperson/representative/CurrentFamilyName',
        'RepresentativeFirstName' => 'http://eidas.europa.eu/attributes/naturalperson/representative/CurrentGivenName',
        'RepresentativeDateOfBirth' => 'http://eidas.europa.eu/attributes/naturalperson/representative/DateOfBirth',
        'RepresentativeGender' => 'http://eidas.europa.eu/attributes/naturalperson/representative/Gender',
        'RepresentativePersonIdentifier' => 'http://eidas.europa.eu/attributes/naturalperson/representative/PersonIdentifier',
        'RepresentativePlaceOfBirth' => 'http://eidas.europa.eu/attributes/naturalperson/representative/PlaceOfBirth',



        'AFirmaIdP' => 'http://es.minhafp.clave/AFirmaIdP',
        'GISSIdP' => 'http://es.minhafp.clave/GISSIdP',
        'AEATIdP' => 'http://es.minhafp.clave/AEATIdP',
        'EIDASIdP' => 'http://es.minhafp.clave/EIDASIdP',
        'PartialAfirma' => 'http://es.minhafp.clave/PartialAfirma',
        'RelayState' => 'http://es.minhafp.clave/RelayState',

        'RegisterType' => 'http://es.minhafp.clave/RegisterType',


        'usedIdP' => 'http://es.minhafp.clave/usedIdP',
    ];

    /************ Internal config vars *************/

    private static $referenceIds = ['ID', 'Id', 'id'];

    private static $AttrNamePrefix = 'http://www.stork.gov.eu/1.0/';

    private static $AttrNF = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';

    private $mode;

    /*********** Request attributes **************/

    private $ID;

    private $TSTAMP;

    private $signCert;

    private $signKey;

    private $signKeyType;

    private $c14nMethod;

    private $digestMethod;

    private $ServiceProviderName;

    private $Issuer;

    private $ReturnAddr;

    private $SPEPS;

    private $QAALevel;

    private $forceAuth;

    private $sectorShare;

    private $crossSectorShare;

    private $crossBorderShare;

    private $ServiceProviderCountry;

    private $ServiceProviderSector;

    private $ServiceProviderInstitution;

    private $ServiceProviderApplication;

    private $ServiceProviderID;

    private $CitizenCountry;

    private $AttrList;

    private $samlAuthReq;

    private $encryptCert;

    private $doCipher;

    private $keyAlgorithm;

    private $decryptPrivateKey;

    private $doDecipher;

    private $onlyEncrypted;

    private $idplist;

    /*********** Response attributes **************/

    private $trustedCerts;

    private $SAMLResponseToken;

    private $signingCert;

    private $responseAssertions;

    private $inResponseTo;

    private $responseIssuer;

    private $responseNameId;

    private $responseNameIdFrm;

    private $AuthnInstant;

    private $AuthnContextClassRef;

    private $responseDestination;

    private $responseSuccess;

    private $responseStatus;

    private $consent;

    private $requestId;

    private $assertionConsumerUrl;

    private $expectedIssuers;

    private $mandatoryAttrList;

    /*********** Request attributes **************/

    private $trustedIssuers;

    private $SAMLAuthnReqToken;

    private $SLOReqToken;

    /************ eIDAS ***************/

    private $spType;

    private $nameIdFormat;

    private static $logLevels = [
        self::LOG_TRACE => 'TRACE',
        self::LOG_DEBUG => 'DEBUG',
        self::LOG_INFO => 'INFO',
        self::LOG_WARN => 'WARN',
        self::LOG_ERROR => 'ERROR',
        self::LOG_CRITICAL => 'CRITICAL',
    ];

    private static $logLevel = self::LOG_TRACE;

    private static $logFile = '/tmp/storkLog';

    private static $logToFile = true;

    private static $logToStdout = false;

    private $defaultLang = 'EN';

    private $msgLang;

    private $ERR_MESSAGES = [
        'EN' => [
            0 => 'OK.',
            1 => 'Key param not a valid PEM RSA private key.',
            2 => 'Cert param not a valid PEM X509 certificate.',
            3 => 'Missing mandatory attributes on response.',
            4 => 'Bad XML syntax on entry data.',
            5 => "This STORK Attribute doesn't exist.",
            6 => 'Peps URL parameter must be provided.',
            7 => 'Return Address parameter must be provided.',
            8 => 'Service Provider readable name parameter must be provided.',
            9 => 'Error parsing assertion subject.',
            10 => 'Duplicate Assertion ID.',
            11 => 'Assertion without Attribute Statement on response',
            12 => 'Destination 2 letter country code must be provided.',
            13 => 'No cert provided',
            14 => 'No key provided',
            15 => 'SAML Response XML badly formed',
            16 => 'SAML Response empty',
            17 => 'SAML Response still not valid',
            18 => 'SAML Response validity has expired',
            19 => 'SAML Response has no status',
            20 => 'Error parsing assertion.',
            21 => 'Assertion without ID on response.',
            22 => 'Assertion without Issuer on response.',
            23 => 'Assertion without Subject on response.',
            24 => 'Signature verification failed',
            25 => 'No plain assertions on a successful response.',
            26 => 'No signature node found',
            27 => 'No Destination attribute found on response.',
            28 => 'No InResponseTo attribute found on response.',
            29 => "The Destination of the response  doesn't match the expected one.",
            30 => 'No signature method information found',
            31 => 'Error validating references.',
            32 => 'Error parsing public key or certificate',
            33 => 'No keyinfo found, no external pubkey/cert provided.',
            34 => 'Bad parameter or parameter type.',
            35 => 'Unexpected document root node.',
            36 => "The ID of the request at which this response addresses doesnt' match the expected one.",
            37 => 'No Issuer node found on response.',
            38 => "The Issuer of the response  doesn't match the expected one.",
            39 => 'The Issuer of the request is not authorised.',
            40 => 'The SLO request is empty.',
            99 => 'Error.',
        ],
    ];

    public function __construct()
    {
        self::trace(__CLASS__ . '.' . __FUNCTION__ . '()');

        $this->mode = 0;

        $this->digestMethod = self::SHA512;
        $this->c14nMethod = self::EXC_C14N;

        $this->trustedCerts = [];

        $this->forceAuth = false;

        $this ->encryptCert = null;
        $this ->doCipher = false;
        $this ->keyAlgorithm = self::AES256_CBC;

        $this->decryptPrivateKey = null;
        $this->doDecipher = false;
        $this->onlyEncrypted = false;

        $this->spType = null;
        $this->nameIdFormat = self::NAMEID_FORMAT_PERSISTENT;

        $this->responseSuccess = false;

        $this->idplist = null;

        $this->ID = self::generateID();
    }

    /**
     * Get the friendly name for a eIDAS attribute name
     */
    public static function getEidasFriendlyName($attributeName): string
    {
        if ($attributeName === null || $attributeName === '') {
            //TODO: turn again to self::fail when fal is made static (as it should be)
            self::critical('[Code ' . self::ERR_GENERIC . '] ' . __FUNCTION__ . '::' . 'Empty or null attribute name.');
            throw new Exception(__FUNCTION__ . '::' . 'Empty or null attribute name', self::ERR_GENERIC);
        }

        foreach (self::$eIdasAttributes as $friendlyName => $name) {
            if ($name === $attributeName) {
                return $friendlyName;
            }
        }

        return '';
    }

    /**
     * Set the language in which the erorr codes will be shown
     */
    public function setErrorMessageLanguage($langcode)
    {
        $this->msgLang = strtoupper($langcode);
    }

    /**
     * Add message translation.
     */
    public function addErrorMessageTranslation($langcode, $messages)
    {
        $this->ERR_MESSAGES[strtoupper($langcode)] = $messages;
    }

    /**
     * @return int[]|string[] Returns the list of supported STORK attribute friendly names
     */
    public function listSupportedAttributes()
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        return array_keys(self::$ATTRIBUTES);
    }

    /**
     * @return int[]|string[] Returns the list of supported eIDAS attribute friendly names
     */
    public function listEidasSupportedAttributes()
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        return array_keys(self::$eIdasAttributes);
    }

    /**
     * @param $friendlyName: the name of the attribute, from the supported list.
     * @throws Exception
     * Notice that this could provoke validation issues.
     */
    public function addRequestAttribute($friendlyName, $required = false, $values = null, $escape = true)
    {
        self::debug('Adding attribute ' . $friendlyName . ' required(' . self::bts($required) . ')');

        if ($this->mode === 0) {
            $prefix = 'stork';
        }
        if ($this->mode === 1) {
            $prefix = 'eidas';
        }

        if ($this->mode === 0) {
            if (! $required) {
                self::$ATTRIBUTES[$friendlyName] or $this->fail(
                    __FUNCTION__,
                    self::ERR_NONEXIST_STORK_ATTR,
                    $friendlyName
                );
            }
        }

        if ($values) {
            if (! is_array($values)) {
                if (is_object($values)) {
                    $this->fail(__FUNCTION__, self::ERR_BAD_PARAMETER, 'values: ' . $values);
                } else {
                    $values = [$values];
                }
            }
        }

        if ($values === null || count($values) <= 0) {
            $values = [];
            $tagClose = '/>';
            $closeTag = '';
        } else {
            $tagClose = '>';
            $closeTag = '</' . $prefix . ':RequestedAttribute>';
        }
        $valueAddition = '';
        foreach ($values as $value) {
            $transformedValue = $value;
            if ($escape) {
                $transformedValue = htmlspecialchars($value);
            }

            $valueType = 'xs:string';

            //TODO: Workaround for terrible clave-2.0 design. still not definitive
            //Seems it is not necessary. Will leave it commented just in case.
            //if($friendlyName === 'RelayState' )
            //    $valueType = 'eidas-natural:PersonIdentifierType';

            $valueAddition .= '<' . $prefix . ':AttributeValue '
        . 'xmlns:xs="' . self::NS_XMLSCH . '" '
        . 'xmlns:xsi="' . self::NS_XSI . '" '
        . 'xsi:type="' . $valueType . '">'
        . $transformedValue . '</' . $prefix . ':AttributeValue>';
        }

        if ($this->mode === 0) {
            $attrName = $friendlyName;
            if (array_key_exists($friendlyName, self::$ATTRIBUTES)) {
                $attrName = self::$ATTRIBUTES[$friendlyName];
            }

            $attrLine = '<stork:RequestedAttribute'
            . ' Name="' . $attrName . '"'
            . ' NameFormat="' . self::$AttrNF . '"'
            . ' isRequired="' . self::bts($required) . '"'
            . $tagClose
            . $valueAddition
            . $closeTag;
        } elseif ($this->mode === 1) {
            $name = $friendlyName;
            if (array_key_exists($friendlyName, self::$eIdasAttributes)) {
                $name = self::$eIdasAttributes[$friendlyName];
            }

            $attrLine = '<' . $prefix . ':RequestedAttribute'
            . ' FriendlyName="' . $friendlyName . '"'
            . ' Name="' . $name . '"'
            . ' NameFormat="' . self::$AttrNF . '"'
            . ' isRequired="' . self::bts($required) . '"'
            . $tagClose
            . $valueAddition
            . $closeTag;
        }

        if (isset($attrLine) && $attrLine !== '') {
            $this->AttrList[] = $attrLine;
        }
    }

    /**
     * Set the key that will be used to sign requests.
     *
     * @param x509 $cert certificate associated with the key, to be included on the keyinfo
     * @param private $key key, of a supported public key cryptosystem.
     * @param string $keytype Kind of key [See constants]
     * @throws Exception
     */
    public function setSignatureKeyParams($cert, $key, $keytype = self::RSA_SHA512)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        $this->signKey = $this->checkKey($key);
        $this->signCert = $this->checkCert($cert);
        $this->signKeyType = $keytype;
    }

    /**
     * Set the digest and canonicalization methods to be used for request signature. See constants for allowed values.
     */
    public function setSignatureParams($digestMethod, $c14nMethod)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        $this->digestMethod = $digestMethod;
        $this->c14nMethod = $c14nMethod;
    }

    /**
     * @param string $issuer  SP identifier towards S-PEPS (usually a URL)
     */
    public function setServiceProviderParams($name, $issuer, $returnAddr)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        $this->ServiceProviderName = $name;
        $this->Issuer = $issuer;
        $this->ReturnAddr = $returnAddr;
    }

    /**
     * Enables the force authentication flag on the request (default false)
     */
    public function forceAuthn()
    {
        $this->forceAuth = true;
    }

    /**
     * Params with more specific and leveled SP ID information. Mandatory if the request is addressed to a country which
     * performs eID derivation.
     *
     * @param $countryCode: The country code of the SP
     * @param $sector: The sector (like a group of institutions) ID (must be settled by someone)
     * @param $institution: The institution ID of the SP (must be settled by someone)
     * @param $application: The SP most specific ID, per application (must be settled by someone).
     */
    public function setSPLocationParams($countryCode, $sector, $institution, $application)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        $this->ServiceProviderCountry = $countryCode;
        $this->ServiceProviderSector = $sector;
        $this->ServiceProviderInstitution = $institution;
        $this->ServiceProviderApplication = $application;
    }

    /**
     * Params needed when the request is addressed to a country that uses V-IDP
     *
     * @param $spId: Unique SP identifier, usually spcountry-sp-sector-spinst-spapp
     * @param $citizenCountryCode: The country code of the citizen
     */
    public function setSPVidpParams($spId, $citizenCountryCode)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        $this->ServiceProviderID = $spId;
        $this->CitizenCountry = $citizenCountryCode;
    }

    /**
     * @param $EntryURL: String. S-PEPS URL.
     */
    public function setSTORKParams(
        $EntryURL,
        $QAALevel = 1,
        $sectorShare = true,
        $crossSectorShare = true,
        $crossBorderShare = true
    ) {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        $this->SPEPS = $EntryURL;
        $this->QAALevel = $QAALevel;
        $this->sectorShare = $sectorShare;
        $this->crossSectorShare = $crossSectorShare;
        $this->crossBorderShare = $crossBorderShare;
    }

    /**
     * If the request needs to have a scoping of the allowed idps when proxying this request
     *
     * @param $IdpList
     */
    public function setIdpList($IdpList)
    {
        $this->idplist = $IdpList;
    }

    /**
     * Establishes an equivalence between Stork QAA levels and eIDAS LoA levels
     *
     * @param $QAA
     */
    public static function qaaToLoA($QAA): string
    {
        if ($QAA === null || $QAA === '') {
            return '';
        }

        if (is_string($QAA) === true) {
            $QAA = (int) $QAA;
        }

        if ($QAA <= 2) {
            return self::LOA_LOW;
        }
        if ($QAA === 3) {
            return self::LOA_SUBST;
        }
        if ($QAA >= 4) {
            return self::LOA_HIGH;
        }

        return '';
    }

    public static function loaToQaa($LoA)
    {
        if ($LoA === null || $LoA === '') {
            return '';
        }

        if (is_string($LoA) === false) {
            return '';
        }

        if ($LoA === self::LOA_LOW) {
            return 2;
        }
        if ($LoA === self::LOA_SUBST) {
            return 3;
        }
        if ($LoA >= self::LOA_HIGH) {
            return 4;
        }

        return 1;
    }

    /**
     * @param bool $signed Wether if the generated request has to be digitally signed or not.
     * @return false|string String The STORK SAML Auth request token.
     * @throws Exception
     */
    public function generateStorkAuthRequest($signed = true)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        //ISO Timestamp
        $this->TSTAMP = self::generateTimestamp();

        self::info('Generating request at: ' . $this->TSTAMP);

        if ($this->SPEPS === null || $this->SPEPS === '') {
            $this->fail(__FUNCTION__, self::ERR_NEEDED_SPEPS);
        }

        if ($this->mode === 0) {
            if ($this->ReturnAddr === null || $this->ReturnAddr === '') {
                $this->fail(__FUNCTION__, self::ERR_NEEDED_RADDR);
            }
        }

        if ($this->ServiceProviderName === null || $this->ServiceProviderName === '') {
            $this->fail(__FUNCTION__, self::ERR_NEEDED_SPROVN);
        }

        if ($this->signCert === null || $this->signCert === ''
       || $this->signKey === null || $this->signKey === ''
       || $this->signKeyType === null || $this->signKeyType === '') {
            $this->fail(__FUNCTION__, self::ERR_EMPTY_KEY);
        }

        $specificNamespaces = 'xmlns:stork="' . self::NS_STORK . '" ' . 'xmlns:storkp="' . self::NS_STORKP . '" ';
        if ($this->mode === 1) {
            $specificNamespaces = 'xmlns:eidas="' . self::NS_EIDAS . '" ' . 'xmlns:eidas-natural="http://eidas.europa.eu/attributes/naturalperson" ';
        }

        $assertionConsumerServiceURL = 'AssertionConsumerServiceURL="' . htmlspecialchars($this->ReturnAddr) . '" ';
        //if($this->mode === 1)  //On eIDAS, this SHOULD NOT be sent. //
        // TODO: but on Clave-2.0, it must. eIDAS supports sending it just as the address stated in the metadata. We'll do so.
        //$assertionConsumerServiceURL = "";

        $protocolBinding = 'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ';
        if ($this->mode === 1) {
            $protocolBinding = '';
        }

        $nsPrefix1 = 'stork';
        $nsPrefix2 = 'storkp';
        if ($this->mode === 1) {
            $nsPrefix1 = 'eidas';
            $nsPrefix2 = 'eidas';
        }

        self::debug('Setting request header.');
        //Header of the SAML Auth Request
        $RootTagOpen = '<?xml version="1.0" encoding="UTF-8"?>'
        . '<saml2p:AuthnRequest '
        . 'xmlns:saml2p="' . self::NS_SAML2P . '" '
        . 'xmlns:ds="' . self::NS_XMLDSIG . '" '
        . 'xmlns:saml2="' . self::NS_SAML2 . '" '
        . $specificNamespaces
        . $assertionConsumerServiceURL
        . 'Consent="' . self::CNS_UNS . '" '
        . 'Destination="' . htmlspecialchars($this->SPEPS) . '" '
        . 'ForceAuthn="' . self::bts($this->forceAuth) . '" '
        . 'ID="' . $this->ID . '" '
        . 'IsPassive="false" '
        . 'IssueInstant="' . $this->TSTAMP . '" '
        . $protocolBinding
        . 'ProviderName="' . htmlspecialchars($this->ServiceProviderName) . '" '
        . 'Version="2.0">';

        self::debug('Setting request issuer.');

        $Issuer = '<saml2:Issuer '
      . 'Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">'
      . htmlspecialchars($this->Issuer)
      . '</saml2:Issuer>';

        //Stork profile extensions: requested attributes
        self::debug('Setting request attributes.');
        $RequestedAttributes = '';

        if (count($this->AttrList) > 0) {
            $RequestedAttributes = '<' . $nsPrefix2 . ':RequestedAttributes>';
            foreach ($this->AttrList as $attr) {
                $RequestedAttributes .= $attr;
            }
            $RequestedAttributes .= '</' . $nsPrefix2 . ':RequestedAttributes>';
        }

        if ($this->mode === 0) {
            $StorkExtAuthAttrs = '';
            if ($this->ServiceProviderID !== null && $this->ServiceProviderID !== ''
        && $this->CitizenCountry !== null && $this->CitizenCountry !== ''
        ) {
                self::debug('Setting profile extensions: authentication additional attributes (optional).');

                $StorkExtAuthAttrs = '<storkp:AuthenticationAttributes>'
                . '<storkp:VIDPAuthenticationAttributes>';

                if ($this->CitizenCountry !== null && $this->CitizenCountry !== '') {
                    $StorkExtAuthAttrs .= '<storkp:CitizenCountryCode>'
                    . htmlspecialchars($this->CitizenCountry)
                    . '</storkp:CitizenCountryCode>';
                }

                $StorkExtAuthAttrs .= '<storkp:SPInformation>'
                . '<storkp:SPID>'
                . htmlspecialchars($this->ServiceProviderID)
                . '</storkp:SPID>'
                . '</storkp:SPInformation>'
                . '</storkp:VIDPAuthenticationAttributes>'
                . '</storkp:AuthenticationAttributes>';
            }

            self::debug('Setting request QAA.');
            $QAA = '<stork:QualityAuthenticationAssuranceLevel>'
            . htmlspecialchars($this->QAALevel)
            . '</stork:QualityAuthenticationAssuranceLevel>';

            if ($this->ServiceProviderCountry !== null && $this->ServiceProviderCountry !== ''
        && $this->ServiceProviderSector !== null && $this->ServiceProviderSector !== ''
        && $this->ServiceProviderInstitution !== null && $this->ServiceProviderInstitution !== ''
        && $this->ServiceProviderApplication !== null && $this->ServiceProviderApplication !== ''
        ) {
                self::debug('Setting request SP info (optional).');

                $SPinfo = '<stork:spSector>' . htmlspecialchars($this->ServiceProviderSector) . '</stork:spSector>'
                . '<stork:spInstitution>' . htmlspecialchars(
                    $this->ServiceProviderInstitution
                ) . '</stork:spInstitution>'
                . '<stork:spApplication>' . htmlspecialchars(
                    $this->ServiceProviderApplication
                ) . '</stork:spApplication>'
                . '<stork:spCountry>' . htmlspecialchars($this->ServiceProviderCountry) . '</stork:spCountry>';
            }

            self::debug('Setting request eID sharing permissions.');
            $eIdShareInfo = '<storkp:eIDSectorShare>' . htmlspecialchars(
                self::bts($this->sectorShare)
            ) . '</storkp:eIDSectorShare>'
            . '<storkp:eIDCrossSectorShare>' . htmlspecialchars(
                self::bts($this->crossSectorShare)
            ) . '</storkp:eIDCrossSectorShare>'
            . '<storkp:eIDCrossBorderShare>' . htmlspecialchars(
                self::bts($this->crossBorderShare)
            ) . '</storkp:eIDCrossBorderShare>';
        }

        $SPtype = '';
        if ($this->mode === 1) {
            if ($this->spType !== null && $this->spType !== '') {
                $SPtype = '<eidas:SPType>' . $this->spType . '</eidas:SPType>';
            }
            $QAA = '';
            $SPinfo = '';
            $eIdShareInfo = '';
            $StorkExtAuthAttrs = '';
        }

        $Extensions = '<saml2p:Extensions>'
      . $SPtype  //eIDAS
      . $QAA  //Stork
      . $SPinfo  //Stork
      . $eIdShareInfo  //Stork
      . $RequestedAttributes
      . $StorkExtAuthAttrs  //Stork
      . '</saml2p:Extensions>';

        $NameIDPolicy = '';
        $AuthnContext = '';
        if ($this->mode === 1) {
            $NameIDPolicy = '<saml2p:NameIDPolicy'
            . ' AllowCreate="true"'
            . ' Format="' . $this->nameIdFormat . '"'
            . ' />';

            $LoA = $this->QAALevel;
            if (is_int($this->QAALevel)) {
                $LoA = self::qaaToLoA($this->QAALevel);
            }
            if ($LoA !== '') {
                $AuthnContext = '<saml2p:RequestedAuthnContext'
                . ' Comparison="minimum">'
                . '<saml2:AuthnContextClassRef>' . htmlspecialchars($LoA) . '</saml2:AuthnContextClassRef>'
                . '</saml2p:RequestedAuthnContext>';
            }
        }

        $Scoping = '';
        if ($this->idplist !== null) {
            $idpList = '';
            foreach ($this->idplist as $idp) {
                $idpList .= '<samlp:IDPEntry ProviderID="' . $idp . '" />';
            }

            if ($idpList !== '') {
                $Scoping = '<samlp:Scoping>'
            . '  <samlp:IDPList>'
            . $idpList
            . '  </samlp:IDPList>'
            . '</samlp:Scoping>';
            }
        }

        $this->samlAuthReq = $RootTagOpen
      . $Issuer
      . $Extensions
      . $NameIDPolicy
      . $AuthnContext
      . $Scoping
      . '</saml2p:AuthnRequest>';

        if ($signed) {
            self::debug('Proceeding to sign the request.');
            $this->samlAuthReq = $this->calculateXMLDsig($this->samlAuthReq);
            self::debug('Request signed.');
        }

        self::info('Generated SamlAuth request.');
        self::trace($this->samlAuthReq);

        return $this->samlAuthReq;
    }

    public function getRequestId(): string
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        return $this->ID;
    }

    public function setRequestId($id)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        $this->ID = $id;
    }

    public function getRequestTimestamp()
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        return $this->TSTAMP;
    }

    /**
     * @return string Returns the generated SAMLAuthRequest
     */
    public function getSamlAuthReqToken(): string
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($this->samlAuthReq !== null) {
            return $this->samlAuthReq;
        }

        return '';
    }

    /**
     * Builds a POST request body (for user convenience)
     *
     * @param $DestCountryCode: The C-PEPS country code.
     * @throws Exception
     */
    public function buildPOSTBody($DestCountryCode): string
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($DestCountryCode === '') {
            $this->fail(__FUNCTION__, self::ERR_NO_COUNTRYCODE);
        }

        return 'country=' . $DestCountryCode . '&SAMLRequest=' . urlencode(base64_encode($this->samlAuthReq));
    }

    /**
     * Bool to string
     *
     * @param $boolVar
     */
    public static function bts($boolVar): string
    {
        self::trace(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($boolVar === true) {
            return 'true';
        }
        return 'false';
    }

    /**
     * String to Bool
     *
     * @param $stringVar
     */
    public static function stb($stringVar): bool
    {
        self::trace(__CLASS__ . '.' . __FUNCTION__ . '()');

        if (strtolower($stringVar) === 'true') {
            return true;
        }
        return false;
    }

    /*******************  SAML RESPONSE PARSING AND VALIDATION  *******************/

    /**
     * Checks if a x509 private key is valid and adds PEM headers if necessary
     *
     * @throws Exception
     */
    public function checkKey($key)
    {
        if ($key === null || $key === '') {
            $this->fail(__FUNCTION__, self::ERR_EMPTY_KEY);
        }

        $keyPem = $key;

        try {
            @openssl_pkey_get_private($keyPem) or $this->fail(__FUNCTION__, self::ERR_RSA_KEY_READ);
        } catch (Exception $e) {
            $keyPem = str_replace("\n", '', $keyPem);
            $keyPem =
        "-----BEGIN PRIVATE KEY-----\n"
        . chunk_split($keyPem, 64)
        . "-----END PRIVATE KEY-----\n";
        }
        @openssl_pkey_get_private($keyPem) or $this->fail(__FUNCTION__, self::ERR_RSA_KEY_READ);

        return $keyPem;
    }

    /**
     * Checks if X509 cert is valid and adds PEM headers if necessary
     *
     * @param $cert
     * @return mixed|string
     * @throws Exception
     */
    public function checkCert($cert)
    {
        if ($cert === null || $cert === '') {
            $this->fail(__FUNCTION__, self::ERR_EMPTY_CERT);
        }

        $certPem = $cert;

        if (! @openssl_x509_read($certPem)) {
            $certPem = str_replace("\n", '', $certPem);
            $certPem =
              "-----BEGIN CERTIFICATE-----\n"
              . chunk_split($certPem, 64)
              . "-----END CERTIFICATE-----\n";
        }
        @openssl_x509_read($certPem) or $this->fail(__FUNCTION__, self::ERR_X509_CERT_READ);

        return $certPem;
    }

    /**
     * Turns a PEM certificate into a one-line b64 string (removing headers, if any, and chunk splitting)
     *
     * @param $cert
     * @return array|string|string[]
     */
    public static function implodeCert($cert)
    {
        $certLine = str_replace("\n", '', $cert);
        $certLine = str_replace('-----BEGIN CERTIFICATE-----', '', $certLine);
        $certLine = str_replace('-----END CERTIFICATE-----', '', $certLine);

        return $certLine;
    }

    /**
     * Adds a certificate to the trusted certificate list
     *
     * @param $cert
     * @throws Exception
     */
    public function addTrustedCert($cert)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($cert === null || $cert === '') {
            $this->fail(__FUNCTION__, self::ERR_EMPTY_CERT);
        }

        $this->trustedCerts[] = $this->checkCert($cert);
    }

    /**
     * Set all values that may be compared
     *
     * @param $requestId
     * @param null $assertionConsumerUrl
     * @param null $expectedIssuers
     * @param null $mandatoryAttrList List of attribute friendly names thar were mandatory on the request.
     */
    public function setValidationContext(
        $requestId,
        $assertionConsumerUrl = null,
        $expectedIssuers = null,
        $mandatoryAttrList = null
    ) {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        $this->requestId = $requestId;
        $this->assertionConsumerUrl = $assertionConsumerUrl;
        $this->expectedIssuers = $expectedIssuers;
        $this->mandatoryAttrList = $mandatoryAttrList;
    }

    /**
     * Validates the received SamlResponse by comparing it to the request  // TODO adapt for eIDAs: review
     *
     * @param $storkSamlResponseToken
     * @param bool $checkDates
     * @param bool $checkSignature
     * @throws Exception
     */
    public function validateStorkResponse($storkSamlResponseToken, $checkDates = true, $checkSignature = true)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($storkSamlResponseToken === null || $storkSamlResponseToken === '') {
            $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
        }

        self::debug('Parsing response.');
        $samlResponse = $this->parseXML($storkSamlResponseToken);

        if ($checkSignature) {
            self::debug('Checking response signature.');
            $this->validateXMLDSignature($storkSamlResponseToken);
        }

        self::debug('Checking response validity.');
        if (strtolower($samlResponse->getName()) !== 'response') {
            $this->fail(__FUNCTION__, self::ERR_UNEXP_ROOT_NODE);
        }

        $this->inResponseTo = '' . $samlResponse['InResponseTo'];
        $this->responseDestination = '' . $samlResponse['Destination'];
        $this->responseIssuer = '' . $samlResponse->children(self::NS_SAML2)->Issuer;

        self::trace('inResponseTo:         ' . $this->inResponseTo);
        self::trace('responseDestination:  ' . $this->responseDestination);
        self::trace('responseIssuer:       ' . $this->responseIssuer);

        if (! $this->inResponseTo || $this->inResponseTo === '') {
            $this->fail(__FUNCTION__, self::ERR_RESP_NO_REQ_ID);
        }
        if (! $this->responseDestination || $this->responseDestination === '') {
            $this->fail(__FUNCTION__, self::ERR_RESP_NO_DESTINATION);
        }
        if (! $this->responseIssuer || $this->responseIssuer === '') {
            $this->fail(__FUNCTION__, self::ERR_RESP_NO_ISSUER);
        }

        self::debug('Comparing with context values if set.');
        if ($this->requestId) {
            self::debug('Comparing with requestID.');
            if (trim($this->requestId) !== trim($this->inResponseTo)) {
                $this->fail(__FUNCTION__, self::ERR_UNEXP_REQ_ID, $this->requestId . ' != ' . $this->inResponseTo);
            }
        }
        if ($this->assertionConsumerUrl) {
            self::debug('Comparing with assertionConsumerURL.');
            if (trim($this->assertionConsumerUrl) !== trim($this->responseDestination)) {
                $this->fail(
                    __FUNCTION__,
                    self::ERR_UNEXP_DEST,
                    $this->assertionConsumerUrl . ' != ' . $this->responseDestination
                );
            }
        }
        if ($this->expectedIssuers) {
            foreach ($this->expectedIssuers as $expectedIssuer) {
                self::debug("Comparing with expected Issuer: ${expectedIssuer}");
                if (trim($expectedIssuer) === trim($this->responseIssuer)) {
                    $found = true;
                }
            }
            if (! $found) {
                $this->fail(__FUNCTION__, self::ERR_UNEXP_ISSUER, 'response issuer: ' . $this->responseIssuer);
            }
        }

        self::debug('Parsing response status.');
        self::parseStatus($samlResponse);

        if (self::isSuccess($aux)) {
            self::debug('Response Successful.');

            if ($this->doDecipher === true) {
                self::debug('Searching for encrypted assertions...');
                $samlResponse = $this->decryptAssertions($storkSamlResponseToken);
            }

            self::debug('Searching for assertions.');
            $assertions = $samlResponse->children(self::NS_SAML2)->Assertion;

            self::trace("Assertions SimpleXML node: \n" . print_r($assertions, true));
            if (! $assertions || count($assertions) <= 0) {
                $this->fail(__FUNCTION__, self::ERR_RESP_SUCC_NO_ASSERTIONS);
            }

            self::debug('Parsing response assertions.');
            self::parseAssertions($assertions);

            self::debug('Checking validity dates for each assertion.');
            $now = time();
            foreach ($assertions as $assertion) {
                if ($checkDates) {
                    $NotBefore = '' . $assertion->Conditions->attributes()->NotBefore;
                    $NotOnOrAfter = '' . $assertion->Conditions->attributes()->NotOnOrAfter;

                    self::checkDates($now, $NotBefore, $NotOnOrAfter);
                }
            }

            if ($samlResponse->children(self::NS_SAML2)->Assertion[0]->Subject) {
                $this->responseNameId = '' . $samlResponse->children(self::NS_SAML2)->Assertion[0]->Subject->NameID;
                $this->responseNameIdFrm = '' . $samlResponse->children(
                    self::NS_SAML2
                )->Assertion[0]->Subject->NameID->attributes()->Format;
            }
            $this->AuthnInstant = '' . $samlResponse->children(
                self::NS_SAML2
            )->Assertion[0]->AuthnStatement->attributes()->AuthnInstant;
            $this->AuthnContextClassRef = '' . $samlResponse->children(
                self::NS_SAML2
            )->Assertion[0]->AuthnStatement->AuthnContext->AuthnContextClassRef;

            self::trace('responseNameId:       ' . $this->responseNameId);
            self::trace('responseNameIdFrm:    ' . $this->responseNameIdFrm);
            self::trace('AuthnInstant:         ' . $this->AuthnInstant);
            self::trace('AuthnContextClassRef: ' . $this->AuthnContextClassRef);
        }

        if ($this->mandatoryAttrList) {
            self::debug('Checking that mandatory attributes were served.');
            foreach ($this->mandatoryAttrList as $mAttr) {
                self::trace("Searching attribute: ${mAttr}");
                $found = false;
                foreach ($this->responseAssertions as $assertion) {
                    foreach ($assertion['Attributes'] as $attr) {
                        if (trim($attr['friendlyName']) === trim($mAttr)
                    && $attr['AttributeStatus'] === self::ATST_AVAIL) {
                            self::trace("${mAttr} found.");
                            $found = true;
                            break 2;
                        }
                    }
                }
                if (! $found) {
                    $this->fail(__FUNCTION__, self::ERR_RESP_NO_MAND_ATTR);
                }
            }
        }

        $this->SAMLResponseToken = $storkSamlResponseToken;
    }

    /**
     * Returns whether the request was in success status.
     *
     * @param $statusInfo: Status primary and secondary (if exists) codes will be returned here.
     */
    public function isSuccess(&$statusInfo): bool
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        $statusInfo = $this->responseStatus;

        return $this->responseSuccess;
    }

    /**
     * @return mixed Returns the status array
     */
    public function getResponseStatus()
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        return $this->responseStatus;
    }

    /**
     * @return mixed Returns the signing certificate for the response that came
     * embedded on the keyinfo node, so the user can compare it.
     * Returns the certificate in PEM format or NULL.
     * Won't be set if signature validation is skipped.
     */
    public function getEmbeddedSigningCert()
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        return $this->signingCert;
    }

    /**
     * @return mixed Returns the issuer ID of the S-PEPS.
     * @throws Exception
     */
    public function getRespIssuer()
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($this->SAMLResponseToken === null) {
            $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
        }

        return $this->responseIssuer;
    }

    public function getRespNameID()
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($this->SAMLResponseToken === null) {
            $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
        }

        return $this->responseNameId;
    }

    public function getRespNameIDFormat()
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($this->SAMLResponseToken === null) {
            $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
        }

        return $this->responseNameIdFrm;
    }

    public function getAuthnInstant()
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($this->SAMLResponseToken === null) {
            $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
        }

        return $this->AuthnInstant;
    }

    public function getAuthnContextClassRef()
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($this->SAMLResponseToken === null) {
            $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
        }

        return $this->AuthnContextClassRef;
    }

    /**
     * @return mixed Returns the ID of the request this response is addressed to.
     * @throws Exception
     */
    public function getInResponseTo()
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($this->SAMLResponseToken === null) {
            $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
        }

        return $this->inResponseTo;
    }

    /**
     * @return mixed Returns the URL at which this response was addressed to.
     * @throws Exception
     */
    public function getResponseDestination()
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($this->SAMLResponseToken === null) {
            $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
        }

        return $this->responseDestination;
    }

    /**
     * @return mixed Returns an array of assertions with all relevant information: subject, issuer, attributes
     * @throws Exception
     */
    public function getAssertions()
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($this->SAMLResponseToken === null || $this->responseAssertions === null) {
            $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
        }

        return $this->responseAssertions;
    }

    /**
     * @return array Returns a list containing all the attributes stated on all the
     * assertions merged, for each attribute, a list of values is provided
     * @throws Exception
     */
    public function getAttributes(): array
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($this->SAMLResponseToken === null || $this->responseAssertions === null) {
            $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
        }

        $attributes = [];
        foreach ($this->responseAssertions as $assertion) {
            foreach ($assertion['Attributes'] as $attr) {
                $attributeName = $attr['friendlyName'];

                //If we haven't found an attribute with the same name, we create the value array
                if (! isset($attributes[$attributeName])) {
                    $attributes[$attributeName] = [];
                }

                if ($attr['values']) {
                    foreach ($attr['values'] as $value) {
                        $attributes[$attributeName][] = $value;
                    }
                }
            }
        }

        return $attributes;
    }

    /**
     * @return array Returns a list containing the pairing between attribute names and
     * friendly names, if available
     * @throws Exception
     */
    public function getAttributeNames(): array
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($this->SAMLResponseToken === null || $this->responseAssertions === null) {
            $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
        }

        $pairings = [];
        foreach ($this->responseAssertions as $assertion) {
            foreach ($assertion['Attributes'] as $attr) {
                if (isset($attr['friendlyName'])
              && isset($attr['Name'])) {
                    $pairings[$attr['friendlyName']] = $attr['Name'];
                }
            }
        }

        return $pairings;
    }

    public function getInResponseToFromReq($storkSamlResponseToken): string
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($storkSamlResponseToken === null || $storkSamlResponseToken === '') {
            $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
        }

        self::debug('Parsing response.');
        $samlResponse = $this->parseXML($storkSamlResponseToken);

        return '' . $samlResponse['InResponseTo'];
    }

    /*******************  SAML AUTHN REQUEST PARSING AND VALIDATION  *********************/

    /**
     * Adds a trusted request issuer to the list. Must
     *
     * @param $issuer
     * @param $certs
     * @throws Exception
     */
    public function addTrustedRequestIssuer($issuer, $certs)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($issuer === null || $issuer === '') {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Missing or empty issuer entityId.');
        }

        if ($certs === null || $certs === []) {
            $this->fail(__FUNCTION__, self::ERR_EMPTY_CERT);
        }

        $this->trustedIssuers[$issuer] = [];
        foreach ($certs as $cert) {
            $this->trustedIssuers[$issuer][] = $this->checkCert($cert);
        }
    }

    /**
     * Validates the received SamlAuthnReq towards the list of authorised issuers.
     *
     * @param $storkSamlRequestToken
     * @throws Exception
     */
    public function validateStorkRequest($storkSamlRequestToken)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($storkSamlRequestToken === null || $storkSamlRequestToken === '') {
            $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
        }

        self::debug('Parsing request.');
        $samlReq = $this->parseXML($storkSamlRequestToken);

        self::debug('Checking request validity.');
        if (strtolower($samlReq->getName()) !== 'authnrequest') {
            $this->fail(__FUNCTION__, self::ERR_UNEXP_ROOT_NODE);
        }

        $issuer = '' . $samlReq->children(self::NS_SAML2)->Issuer;
        if ($issuer === '') {
            $issuer = '' . $samlReq['ProviderName'];
        } // Dirty workaround for Clave 2.0 java SPs not using issuers TODO: verify.

        self::debug('Checking request signature. Issuer: ' . $issuer);

        $verified = false;
        foreach ($this->trustedIssuers[$issuer] as $cert) {
            if ($cert === null || $cert === '') {
                $this->fail(__FUNCTION__, self::ERR_NONAUTH_ISSUER);
            }

            if ($this->verifySignature($storkSamlRequestToken, $cert)) {
                $verified = true;
            }
        }
        if (! $verified) {
            self::trace('Cert validation failure.');
            $this->fail(__FUNCTION__, self::ERR_SIG_VERIF_FAIL);
        }

        $this->SAMLAuthnReqToken = $storkSamlRequestToken;
    }

    /**
     * @param null $SAMLAuthnReqToken
     * @return array Returns an array with the important parameters of the received request
     * If a Request is passed on the parameter, then the return is related
     * to it and not to the request in the object state
     * TODO test eIDAS support
     */
    public function getStorkRequestData($SAMLAuthnReqToken = null): array
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        $ret = [];

        $request = $this->SAMLAuthnReqToken;
        if ($SAMLAuthnReqToken !== null) {
            self::debug('Notice that you are parsing an external token and not the internal state one');
            $request = $SAMLAuthnReqToken;
        }

        $samlReq = $this->parseXML($request);

        $ret['id'] = '' . $samlReq['ID'];
        $ret['destination'] = '' . $samlReq['Destination'];
        $ret['protocolBinding'] = '' . $samlReq['ProtocolBinding'];
        $ret['ProviderName'] = '' . $samlReq['ProviderName'];
        $ret['forceAuthn'] = self::stb('' . $samlReq['ForceAuthn']);
        $ret['isPassive'] = self::stb('' . $samlReq['IsPassive']);

        if (isset($samlReq['AssertionConsumerServiceURL'])) {
            $ret['assertionConsumerService'] = '' . $samlReq['AssertionConsumerServiceURL'];
        }

        $ret['issuer'] = '' . $samlReq->children(self::NS_SAML2)->Issuer;

        $ext = $samlReq->children(self::NS_SAML2P)->Extensions;

        $ret['idplist'] = $this->parseScoping($samlReq);
        // TODO: SEGUIR: funciona?

        if ($this->mode === 0) {
            self::debug('Mode 0');

            $authAttrs = $ext->children(self::NS_STORKP, false)->AuthenticationAttributes->VIDPAuthenticationAttributes;
            $reqAttrs = $ext->children(self::NS_STORKP, false)->RequestedAttributes->children(self::NS_STORK, false);

            $ret['QAA'] = '' . $ext->children(self::NS_STORK, false)->QualityAuthenticationAssuranceLevel;
            $ret['spSector'] = '' . $ext->children(self::NS_STORK, false)->spSector;
            $ret['spInstitution'] = '' . $ext->children(self::NS_STORK, false)->spInstitution;
            $ret['spApplication'] = '' . $ext->children(self::NS_STORK, false)->spApplication;
            $ret['spCountry'] = '' . $ext->children(self::NS_STORK, false)->spCountry;
            $ret['eIDSectorShare'] = '' . $ext->children(self::NS_STORKP, false)->eIDSectorShare;
            $ret['eIDCrossSectorShare'] = '' . $ext->children(self::NS_STORKP, false)->eIDCrossSectorShare;
            $ret['eIDCrossBorderShare'] = '' . $ext->children(self::NS_STORKP, false)->eIDCrossBorderShare;
            $ret['citizenCountryCode'] = '' . $authAttrs->CitizenCountryCode;
            $ret['spID'] = '' . $authAttrs->SPInformation->SPID;

            $ret['requestedAttributes'] = [];  // TODO: SEGUIR soportar aquí que se lean y retransmitan los values de los attr solicitados
            foreach ($reqAttrs as $reqAttr) {
                $values = [];
                foreach ($reqAttr->AttributeValue as $val) {
                    $values[] = '' . $val;
                }

                $ret['requestedAttributes'][] = [
                    'name' => '' . $reqAttr->attributes()->Name,
                    'isRequired' => strtolower('' . $reqAttr->attributes()->isRequired) === 'true',
                    'values' => $values,
                ];
            }
        }

        if ($this->mode === 1) {
            self::debug('Mode 1');

            $authContext = $samlReq->children(self::NS_SAML2P)->RequestedAuthnContext;
            $nameIDPolicy = $samlReq->children(self::NS_SAML2P)->NameIDPolicy;
            $reqAttrs = $ext->children(self::NS_EIDAS, false)->RequestedAttributes->children(self::NS_EIDAS, false);

            $ret['spSector'] = '';
            $ret['spInstitution'] = '';
            $ret['spApplication'] = '';
            $ret['spCountry'] = '';
            $ret['eIDSectorShare'] = '';
            $ret['eIDCrossSectorShare'] = '';
            $ret['eIDCrossBorderShare'] = '';
            $ret['citizenCountryCode'] = '';
            $ret['spID'] = '';

            $ret['Comparison'] = '' . $authContext->attributes()->Comparison;
            $ret['LoA'] = '' . $authContext->children(self::NS_SAML2, false)->AuthnContextClassRef;
            $ret['SPType'] = '' . $ext->children(self::NS_EIDAS, false)->SPType;

            $ret['QAA'] = self::loaToQaa($ret['LoA']);

            $ret['IdAllowCreate'] = '' . $nameIDPolicy->attributes()->AllowCreate;
            $ret['IdFormat'] = '' . $nameIDPolicy->attributes()->Format;

            $ret['requestedAttributes'] = [];
            foreach ($reqAttrs as $reqAttr) {
                $values = [];
                foreach ($reqAttr->AttributeValue as $val) {
                    $values[] = '' . $val;
                }

                $ret['requestedAttributes'][] = [
                    'friendlyName' => '' . $reqAttr->attributes()->FriendlyName,
                    'name' => '' . $reqAttr->attributes()->Name,
                    'isRequired' => strtolower('' . $reqAttr->attributes()->isRequired) === 'true',
                    'values' => $values,
                ];
            }
        }

        $ret['spCert'] = '' . $samlReq->children(self::NS_XMLDSIG)->Signature->KeyInfo->X509Data->X509Certificate;

        return $ret;
    }

    /*******************  SAML RESPONSE GENERATION  *********************/

    /**
     * @return array Returns an array with the assertions from the response in the shape of xml strings
     * @throws Exception
     */
    public function getRawAssertions(): array
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($this->doDecipher === true) {
            self::debug('Decrypt assertions before returning them...');
            $samlResponse = $this->decryptAssertions($this->SAMLResponseToken);
        } else {
            $samlResponse = $this->parseXML($this->SAMLResponseToken);
        }

        $assertions = $samlResponse->children(self::NS_SAML2)->Assertion;

        if (! $assertions || count($assertions) <= 0) {
            $this->fail(__FUNCTION__, self::ERR_RESP_SUCC_NO_ASSERTIONS);
        }

        $ret = [];
        foreach ($assertions as $assertion) {
            $ret[] = $assertion->asXML();
        }
        return $ret;
    }

    public function getRawStatus()
    {
        $samlResponse = $this->parseXML($this->SAMLResponseToken);

        $status = $samlResponse->children(self::NS_SAML2)->Status;

        if (! $status || count($status) <= 0) {
            $this->fail(__FUNCTION__, self::ERR_SAMLRESP_NOSTATUS);
        }

        return $status;
    }

    /**
     * @return string randomly generated 128 bits request ID
     */
    public static function generateID(): string
    {
        return '_' . md5(uniqid(mt_rand(), true));
    }

    public static function generateTimestamp($time = null)
    {
        if ($time === null) {
            $time = time();
        }

        return gmdate('Y-m-d\TH:i:s\Z', $time);
    }

    public function setResponseParameters($consent, $destination, $inResponseTo, $issuer)
    {
        if ($consent === null || $consent === '') {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Missing or empty consent on response building.');
        }
        if ($destination === null || $destination === '') {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Missing or empty destination on response building.');
        }
        if ($inResponseTo === null || $inResponseTo === '') {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Missing or empty inResponseTo on response building.');
        }
        if ($issuer === null || $issuer === '') {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Missing or empty issuer on response building.');
        }

        $this->consent = $consent;
        $this->responseDestination = $destination;
        $this->inResponseTo = $inResponseTo;
        $this->responseIssuer = $issuer;
    }

    /**
     * @param $status
     * @param false $isRaw If raw, it is a string, return and we're done.
     * @throws Exception
     */
    public function generateStatus($status, $isRaw = false): string
    {
        if ($isRaw) {
            if (! is_string($status) || $status === '') {
                $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Status should be a string.');
            } else {
                return $status;
            }
        }

        $statusInfo = $status;

        $statusTagEnd = '/>';
        $statusCodeCloseTag = '';
        $secondaryStatus = '';
        if (isset($statusInfo['SecondaryStatusCode']) && $statusInfo['SecondaryStatusCode'] !== null) {
            $statusTagEnd = '>';
            $statusCodeCloseTag = '</saml2p:StatusCode>';
            $secondaryStatus = '<saml2p:StatusCode Value="' . htmlspecialchars(
                $statusInfo['SecondaryStatusCode']
            ) . '" />';
        }

        $statusMessage = '';
        if (isset($statusInfo['StatusMessage']) && $statusInfo['StatusMessage'] !== null) {
            $statusMessage = '<saml2p:StatusMessage>' . htmlspecialchars(
                $statusInfo['StatusMessage']
            ) . '</saml2p:StatusMessage>';
        }

        $statusNode =
          '<saml2p:Status>'
          . '<saml2p:StatusCode Value="' . htmlspecialchars($statusInfo['MainStatusCode']) . '" ' . $statusTagEnd
          . $secondaryStatus
          . $statusCodeCloseTag
          . $statusMessage
          . '</saml2p:Status>';

        return $statusNode;
    }

    /**
     * @param $assertionData
     * @param false $isRaw If raw, it is a string, return as is or add the namespaces if needed.
     * @param bool $storkize
     * @return mixed|string
     * @throws Exception
     */
    public function generateAssertion($assertionData, $isRaw = false, $storkize = true)
    {
        $assertion = null;
        $now = time();

        if ($isRaw) {
            if (! is_string($assertionData) || $assertionData === '') {
                $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Assertion should be a string.');
            }

            $assertion = $assertionData;
            if ($storkize === true) {
                $xml = '<root '
                  . 'xmlns:saml2p="' . self::NS_SAML2P . '" '
                  . 'xmlns:ds="' . self::NS_XMLDSIG . '" '
                  . 'xmlns:saml2="' . self::NS_SAML2 . '" '
                  . 'xmlns:stork="' . self::NS_STORK . '" '
                  . 'xmlns:storkp="' . self::NS_STORKP . '" '
                  . 'xmlns:xsi="' . self::NS_XSI . '" '
                  . 'xmlns:eidas="' . self::NS_EIDASATT . '" '
                  . 'xmlns:eidas-natural="' . self::NS_EIDASATT . '" '
                  . 'xmlns:xs="' . self::NS_XMLSCH . '">'
                  . $assertionData
                  . '</root>';
                $rootObj = $this->parseXML($xml);

                $assertionObj = $rootObj->children(self::NS_SAML2)->Assertion;
                foreach ($assertionObj->AttributeStatement->Attribute as $attribute) {
                    $attribute->addAttribute('stork:AttributeStatus', 'Available', self::NS_STORK);
                }
                $assertion = $assertionObj->saveXML();
            }
        } else {
            $NameID = '';
            $nameQualifier = '';
            $clientAddress = '';
            $inResponseTo = '';
            $recipient = '';
            $audienceRestriction = '';

            $id = self::generateID();
            $IssueInstant = self::generateTimestamp($now);
            $NotBefore = $IssueInstant;
            $NotOnOrAfter = self::generateTimestamp($now + 300);
            $AuthnInstant = $IssueInstant;

            $AuthnContextClassRef = self::LOA_LOW;
            $NameIDFormat = self::NAMEID_FORMAT_UNSPECIFIED;

            if (! isset($assertionData['Issuer'])) {
                $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Issuer not defined on assertion input.');
            }
            $Issuer = $assertionData['Issuer'];

            if (isset($assertionData['ID'])) {
                $id = $assertionData['ID'];
            }

            if (isset($assertionData['IssueInstant'])) {
                $IssueInstant = $assertionData['IssueInstant'];
            }

            if (isset($assertionData['NotBefore'])) {
                $NotBefore = $assertionData['NotBefore'];
            }

            if (isset($assertionData['NotOnOrAfter'])) {
                $NotOnOrAfter = $assertionData['NotOnOrAfter'];
            }

            if (isset($assertionData['AuthnInstant'])) {
                $AuthnInstant = $assertionData['AuthnInstant'];
            }

            if (isset($assertionData['AuthnContextClassRef'])) {
                $AuthnContextClassRef = $assertionData['AuthnContextClassRef'];
            }

            if (isset($assertionData['NameIDFormat'])) {
                $NameIDFormat = $assertionData['NameIDFormat'];
            }

            if (isset($assertionData['NameID'])) {
                $NameID = $assertionData['NameID'];
            }
            if (isset($assertionData['NameQualifier'])) {
                $nameQualifier = 'NameQualifier="' . htmlspecialchars($assertionData['NameQualifier']) . '" ';
            }
            if (isset($assertionData['Address'])) {
                $clientAddress = 'Address="' . htmlspecialchars($assertionData['Address']) . '" ';
            }
            if (isset($assertionData['InResponseTo'])) {
                $inResponseTo = 'InResponseTo="' . htmlspecialchars($assertionData['InResponseTo']) . '" ';
            }
            if (isset($assertionData['Recipient'])) {
                $recipient = 'Recipient="' . htmlspecialchars($assertionData['Recipient']) . '" ';
            }

            if (isset($assertionData['Audience'])) {
                $audienceRestriction = '<saml2:AudienceRestriction>'
                  . '            <saml2:Audience>' . htmlspecialchars(
                      $assertionData['Audience']
                  ) . '</saml2:Audience>'
                  . '        </saml2:AudienceRestriction>';
            }

            $subject = '';
            if ($NameID !== '') {
                $subject = '<saml2:Subject>'
                  . '        <saml2:NameID Format="' . htmlspecialchars($NameIDFormat) . '" '
                  . '               ' . $nameQualifier . '>' . htmlspecialchars($NameID) . '</saml2:NameID>'
                  . '        <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
                  . '           <saml2:SubjectConfirmationData '
                  . '               ' . $clientAddress
                  . '               ' . $inResponseTo
                  . '               NotOnOrAfter="' . htmlspecialchars($NotOnOrAfter) . '" '
                  . '               ' . $recipient . '/>'
                  . '        </saml2:SubjectConfirmation>'
                  . '    </saml2:Subject>';
            }

            $attribs = '';
            foreach ($assertionData['attributes'] as $attr) {
                $values = '';
                foreach ($attr['values'] as $val) {
                    $values .= '    <saml2:AttributeValue '
                      // TODO: for the moment we don't set the data
                      // type (as eIDAs implementations seem to ignore
                      // it and SAML2 deems it as optional). Pass it
                      // on $attr['valueType'] if any (if there is
                      // more than one value, SAML2 says all must have
                      // the same type, so do it on the attribute
                      // section, not per value).
                      . '>'
                      . htmlspecialchars($val)
                      . '    </saml2:AttributeValue>';
                }

                $attribs .= '<saml2:Attribute '
                  . '    FriendlyName="' . $attr['friendlyName'] . '" '
                  . '    Name="' . $attr['name'] . '" '
                  . '    NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">'
                  . '    ' . $values
                  . '</saml2:Attribute>';
            }

            $attributeStatement = '';
            if ($attribs !== '') {
                $attributeStatement = '<saml2:AttributeStatement>'
                  . $attribs
                  . '</saml2:AttributeStatement>';
            }

            $assertion = '<saml2:Assertion '
              . 'ID="' . htmlspecialchars($id) . '" '
              . 'IssueInstant="' . htmlspecialchars($IssueInstant) . '" '
              . 'Version="2.0">'
              . '    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">' . htmlspecialchars(
                  $Issuer
              ) . '</saml2:Issuer>'
              . '    ' . $subject
              . '    <saml2:Conditions '
              . '        NotBefore="' . htmlspecialchars($NotBefore) . '" '
              . '        NotOnOrAfter="' . htmlspecialchars($NotOnOrAfter) . '">'
              . '        ' . $audienceRestriction
              . '    </saml2:Conditions>'
              . '    <saml2:AuthnStatement AuthnInstant="' . htmlspecialchars($AuthnInstant) . '">'
              . '        <saml2:AuthnContext>'
              . '            <saml2:AuthnContextClassRef>' . htmlspecialchars(
                  $AuthnContextClassRef
              ) . '</saml2:AuthnContextClassRef>'
              . '            <saml2:AuthnContextDecl/>'
              . '        </saml2:AuthnContext>'
              . '    </saml2:AuthnStatement>'
              . '    ' . $attributeStatement
              . '</saml2:Assertion>';
        }

        return $assertion;
    }

    /**
     * @param $status: status of the response, either raw (XML
     * string) or to be built (array in the shape of what we return when
     * parsing a response)
     * @param $assertions: array of assertions for the response, either raw (XML
     * string) or to be built (array in the shape of what we return when
     * parsing a response)
     * @return false|string
     * @throws Exception
     */
    public function generateStorkResponse(
        $status,
        $assertions,
        $rawStatus = true,
        $rawAssertions = true,
        $storkize = true
    ) {  // TODO probar

        $consent = $this->consent;
        $destination = $this->responseDestination;
        $inResponseTo = $this->inResponseTo;

        $issuer = $this->responseIssuer;

        //TODO For each assertion (if not repacked): Esperar array como el que genero yo en el parsing de la response. Así menos quebraderos. Si he de tocar algo, se toca sobre el array
        // issuer
        // subject: (pasar en un array tal cual lo genero al parsear)
        // Conditions:
        // authnStatemet:
        // attributes:

        $storkNamespaces = '';
        if ($this->mode === 0 || $storkize === true) { //eIDAS  // TODO check
            $storkNamespaces =
               'xmlns:stork="' . self::NS_STORK . '" '
              . 'xmlns:storkp="' . self::NS_STORKP . '" ';
        }
        $eIDASNamespaces = '';
        if ($this->mode === 1) { //eIDAS  // TODO check
            $eIDASNamespaces =
                           'xmlns:eidas="' . self::NS_EIDASATT . '" '
                          . 'xmlns:eidas-natural="' . self::NS_EIDASATT . '" ';
        }

        $RootTagOpen = '<?xml version="1.0" encoding="UTF-8"?>'
          . '<saml2p:Response '
          . 'xmlns:saml2p="' . self::NS_SAML2P . '" '
          . 'xmlns:ds="' . self::NS_XMLDSIG . '" '
          . 'xmlns:saml2="' . self::NS_SAML2 . '" '
          . $storkNamespaces
          . 'xmlns:xsi="' . self::NS_XSI . '" '
          . $eIDASNamespaces
          . 'xmlns:xs="' . self::NS_XMLSCH . '" '
          . 'Consent="' . htmlspecialchars($consent) . '" '
          . 'Destination="' . htmlspecialchars($destination) . '" '
          . 'ID="' . self::generateID() . '" '
          . 'InResponseTo="' . htmlspecialchars($inResponseTo) . '" '
          . 'IssueInstant="' . self::generateTimestamp() . '" '
          . 'Version="2.0">';

        self::debug('Setting response issuer.');
        $Issuer = '<saml2:Issuer '
          . 'Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">'
          . htmlspecialchars($issuer)
          . '</saml2:Issuer>';

        $assertionList = '';
        foreach ($assertions as $assertion) {
            $assertionList .= $this->generateAssertion(
                $assertion,
                $rawAssertions,
                $storkize
            );  // TODO verify that storkize works
        }

        $samlResponse = $RootTagOpen
          . $Issuer
          . $this->generateStatus($status, $rawStatus)
          . $assertionList
          . '</saml2p:Response>';

        if ($this->doCipher === true) {
            self::info('Ciphering the response assertions...');
            $samlResponse = $this->encryptAssertions($samlResponse);
        }

        $samlResponse = $this->calculateXMLDsig($samlResponse);

        return $samlResponse;
    }

    /**
     * Gets the issuer entityId from a Saml token
     *
     * @param $samlToken: string xml saml token string
     * @throws Exception
     */
    public function getIssuer($samlToken): string
    {
        if ($samlToken === null || $samlToken === '') {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Empty saml token.');
        }

        $samlTok = $this->parseXML($samlToken);

        return '' . $samlTok->children(self::NS_SAML2)->Issuer;
    }

    /**
     * Gets the providerName from a Saml token
     *
     * @param string $samlToken xml saml token string
     * @throws Exception
     */
    public function getProviderName($samlToken): string
    {
        if ($samlToken === null || $samlToken === '') {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Empty saml token.');
        }

        $samlTok = $this->parseXML($samlToken);

        return '' . $samlTok['ProviderName'];
    }

    public static function getFriendlyName($attributeName, $mode = 0)
    {
        if ($mode === 0) {
            $prefixLen = strlen(self::$AttrNamePrefix);
            if (substr($attributeName, 0, $prefixLen) === self::$AttrNamePrefix) {
                return substr($attributeName, $prefixLen);
            }
            return $attributeName;
        }
    }

    // *************** Stork Single Logout *******************  // TODO once eIDAS-clave3.0 is deployed, see if there's SSO and adapt

    /**
     * @param $spID: the stork id of the SP
     * @param $destination: endopint of the SLO service on the IdP
     * @param $returnTo: endpoint at the SP where the SLO response is expected.
     * @return false|string
     * @throws Exception
     */
    public function generateSLORequest($spID, $destination, $returnTo, $id = null)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($id !== null) {
            self::debug('ID provided. Overriding' . $this->ID . ' with ' . $id);
            $this->ID = $id;
        }
        self::debug('ID being actually used: ' . $this->ID);

        $issuer = '<saml:Issuer>'
          . htmlspecialchars($returnTo)
          . '</saml:Issuer>';

        $nameId = '<saml:NameID>' . htmlspecialchars($spID) . '</saml:NameID>';
        if ($this->mode === 1) {
            $nameId = '<saml:NameID'
                  . ' Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"'
                  . ' SPNameQualifier="' . htmlspecialchars($returnTo) . '"'
                  . '>' . htmlspecialchars($spID) . '</saml:NameID>';
        }

        $sloReq = '<?xml version="1.0" encoding="UTF-8"?>'
          . '<samlp:LogoutRequest'
          . ' xmlns:samlp="' . self::NS_SAML2P . '"'
          . ' xmlns:saml="' . self::NS_SAML2 . '"'
          . ' ID="' . htmlspecialchars($this->ID) . '"'
          . ' Version="2.0"'
          . ' IssueInstant="' . self::generateTimestamp() . '"'
          . ' Destination="' . htmlspecialchars($destination) . '"'
          . '>'
          . $issuer
          . $nameId
          . '</samlp:LogoutRequest>';

        $sloReq = $this->calculateXMLDsig($sloReq);

        return $sloReq;
    }

    public function validateSLOResponse($samlToken): bool
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($samlToken === null || $samlToken === '') {
            $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
        }

        self::debug('Parsing SLOresponse.');
        $samlResponse = $this->parseXML($samlToken);

        self::debug('Checking SLOresponse signature.');
        $this->validateXMLDSignature($samlToken);

        self::debug('Checking SLOresponse validity.');
        if (strtolower($samlResponse->getName()) !== 'logoutresponse') {
            $this->fail(__FUNCTION__, self::ERR_UNEXP_ROOT_NODE);
        }

        $this->inResponseTo = '' . $samlResponse['InResponseTo'];
        $this->responseDestination = '' . $samlResponse['Destination'];
        $this->responseIssuer = '' . $samlResponse->children(self::NS_SAML2)->Issuer;
        $this->responseNameId = '' . $samlResponse->children(self::NS_SAML2)->Assertion[0]->Subject->NameID;

        self::trace('inResponseTo:        ' . $this->inResponseTo);
        self::trace('responseDestination: ' . $this->responseDestination);
        self::trace('responseIssuer:      ' . $this->responseIssuer);

        if (! $this->inResponseTo || $this->inResponseTo === '') {
            $this->fail(__FUNCTION__, self::ERR_RESP_NO_REQ_ID);
        }
        if (! $this->responseDestination || $this->responseDestination === '') {
            $this->fail(__FUNCTION__, self::ERR_RESP_NO_DESTINATION);
        }
        if (! $this->responseIssuer || $this->responseIssuer === '') {
            $this->fail(__FUNCTION__, self::ERR_RESP_NO_ISSUER);
        }

        self::debug('Comparing with context values if set.');
        if ($this->requestId) {
            self::debug('Comparing with requestID.');
            if (trim($this->requestId) !== trim($this->inResponseTo)) {
                $this->fail(__FUNCTION__, self::ERR_UNEXP_REQ_ID, $this->requestId . ' != ' . $this->inResponseTo);
            }
        }
        if ($this->assertionConsumerUrl) {
            self::debug('Comparing with assertionConsumerURL.');
            if (trim($this->assertionConsumerUrl) !== trim($this->responseDestination)) {
                $this->fail(
                    __FUNCTION__,
                    self::ERR_UNEXP_DEST,
                    $this->assertionConsumerUrl . ' != ' . $this->responseDestination
                );
            }
        }
        if ($this->expectedIssuers) {
            foreach ($this->expectedIssuers as $expectedIssuer) {
                self::debug("Comparing with expected Issuer: ${expectedIssuer}");
                if (trim($expectedIssuer) === trim($this->responseIssuer)) {
                    $found = true;
                }
            }
            if (! $found) {
                $this->fail(__FUNCTION__, self::ERR_UNEXP_ISSUER, 'SLOresponse issuer: ' . $this->responseIssuer);
            }
        }

        self::debug('Parsing SLOresponse status.');
        self::parseStatus($samlResponse);

        $this->SAMLResponseToken = $samlToken;

        return self::isSuccess($aux);
    }

    public function validateLogoutRequest($logoutReqToken)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($logoutReqToken === null || $logoutReqToken === '') {
            $this->fail(__FUNCTION__, self::ERR_SLOREQ_EMPTY);
        }

        self::debug('Parsing SLO request.');
        $samlReq = $this->parseXML($logoutReqToken);

        self::debug('Checking SLO request validity.');
        if (strtolower($samlReq->getName()) !== 'logoutrequest') {
            $this->fail(__FUNCTION__, self::ERR_UNEXP_ROOT_NODE);
        }

        self::debug('Checking slorequest signature against: ' . print_r($this->trustedIssuers, true));
        $verified = false;
        foreach ($this->trustedIssuers as $trustedIssuer) {
            foreach ($trustedIssuer as $cert) {
                self::debug('Trying with: ' . $cert);
                if ($cert === null || $cert === '') {
                    continue;
                }
                self::debug('Chk1');
                if ($this->verifySignature($logoutReqToken, $cert)) {
                    self::trace('Cert validation successful');
                    $verified = true;
                    break;
                }
            }
        }
        if (! $verified) {
            $this->fail(__FUNCTION__, self::ERR_SIG_VERIF_FAIL);
        }

        $this->SLOReqToken = $logoutReqToken;
    }

    /**
     * @return array Returns an array with the important parameters of the received SLO request
     */
    public function getSloRequestData(): array
    {
        $ret = [];

        $samlReq = $this->parseXML($this->SLOReqToken);

        $ret['id'] = '' . $samlReq['ID'];
        $ret['destination'] = '' . $samlReq['Destination'];
        $ret['issuer'] = '' . $samlReq->children(self::NS_SAML2)->Issuer;
        $ret['nameId'] = '' . $samlReq->children(self::NS_SAML2)->NameID;

        return $ret;
    }

    public function generateSLOResponse($inResponseTo, $issuer, $statusInfo, $destination)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        $Issuer = '<saml2:Issuer '
          . 'Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">'
          . htmlspecialchars($issuer)
          . '</saml2:Issuer>';

        $Status = $this->generateStatus($statusInfo);

        $sloResp = '<?xml version="1.0" encoding="UTF-8"?>'
          . '<saml2p:LogoutResponse '
          . ' xmlns:saml2p="' . self::NS_SAML2P . '"'
          . ' xmlns:ds="' . self::NS_XMLDSIG . '"'
          . ' xmlns:saml2="' . self::NS_SAML2 . '"'
          . ' xmlns:stork="' . self::NS_STORK . '"'
          . ' xmlns:storkp="' . self::NS_STORKP . '"'
          . ' Consent="' . self::CNS_UNS . '"'
          . ' Destination="' . htmlspecialchars($destination) . '"'
          . ' ID="' . htmlspecialchars($this->ID) . '"'
          . ' InResponseTo="' . $inResponseTo . '"'
          . ' IssueInstant="' . self::generateTimestamp() . '"'
          . ' Version="2.0"'
          . '>'
          . $Issuer
          . $Status
          . '</saml2p:LogoutResponse>';

        self::debug('unsigned SLO response: ' . $sloResp);

        $sloResp = $this->calculateXMLDsig($sloResp);

        return $sloResp;
    }

    /**
     * Gets the nameID content from a SLO request.
     *
     * @param $samlToken
     * @throws Exception
     */
    public function getSloNameId($samlToken): string
    {
        if ($samlToken === null || $samlToken === '') {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Empty saml token.');
        }

        $samlTok = $this->parseXML($samlToken);

        return '' . $samlTok->children(self::NS_SAML2)->NameID;
    }

    /**
     * Set whether to, the key strength and certificate to cipher the assertions on the response.
     *
     * @param $encryptCert
     * @param bool $doCipher
     * @param string $keyAlgorithm
     * @throws Exception
     */
    public function setCipherParams($encryptCert, $doCipher = true, $keyAlgorithm = self::AES256_CBC)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        $this->encryptCert = $this->checkCert($encryptCert);
        $this->doCipher = $doCipher;
        $this->keyAlgorithm = $keyAlgorithm;
    }

    /**
     * Set whether to expect encrypted assertions and the private key to use to decrypt (should be the key linked to the
     * certificate trusted by the IdP, the one used to sign the requests)
     *
     * @param $decryptPrivateKey
     * @param bool $doDecipher
     * @param false $onlyEncrypted
     * @throws Exception
     */
    public function setDecipherParams($decryptPrivateKey, $doDecipher = true, $onlyEncrypted = false)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        $this->decryptPrivateKey = $this->checkKey($decryptPrivateKey);
        $this->doDecipher = $doDecipher;
        $this->onlyEncrypted = $onlyEncrypted;
    }

    /**
     * Switch to eIDAS mode
     */
    public function setEidasMode()
    {
        $this->mode = 1;
    }

    /**
     * Set eIDAS specific parameters (LoA is inferred from the QAA, but can set here too)
     *
     * @param string $spType
     * @param string $nameIdFormat
     * @param int $QAALevel
     * @throws Exception
     */
    public function setEidasRequestParams(
        $spType = self::EIDAS_SPTYPE_PUBLIC,
        $nameIdFormat = self::NAMEID_FORMAT_PERSISTENT,
        $QAALevel = 1
    ) {
        if ($spType !== self::EIDAS_SPTYPE_PUBLIC
      && $spType !== self::EIDAS_SPTYPE_PRIVATE) {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, "eIDAS SPType not valid: ${spType}");
        }

        if ($nameIdFormat !== self::NAMEID_FORMAT_PERSISTENT
      && $nameIdFormat !== self::NAMEID_FORMAT_TRANSIENT
      && $nameIdFormat !== self::NAMEID_FORMAT_UNSPECIFIED) {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, "eIDAS nameID format not valid: ${nameIdFormat}");
        }

        $this->spType = $spType;
        $this->nameIdFormat = $nameIdFormat;
        $this->QAALevel = $QAALevel;
    }

    /**
     * Will generate a metadata signed document that must be published at the URL stated in <issuer> of the SP
     *
     * @return false|string
     * @throws Exception
     */
    public function generateSPMetadata()
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        self::info('Generating metadata for the AuthnRequest');
        $metadata = '<?xml version="1.0" encoding="UTF-8"?>'
          . '<md:EntityDescriptor'
          . '    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"'
          . '    entityID="' . htmlspecialchars($this->Issuer) . '"'
          . '    validUntil="' . self::generateTimestamp(time() + (1 * 24 * 60 * 60)) . '">'
          . '  <md:SPSSODescriptor'
          . '      AuthnRequestsSigned="true" '
          . '      WantAssertionsSigned="true" '
          . '      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
          . '    <md:KeyDescriptor use="signing">'
          . '      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
          . '        <ds:X509Data>'
          . '          <ds:X509Certificate>' . self::implodeCert($this->signCert) . '</ds:X509Certificate>'
          . '        </ds:X509Data>'
          . '      </ds:KeyInfo>'
          . '    </md:KeyDescriptor>'
          . '    <md:KeyDescriptor use="encryption">'
          . '      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
          . '        <ds:X509Data>'
          . '          <ds:X509Certificate>' . self::implodeCert($this->signCert) . '</ds:X509Certificate>'
          . '        </ds:X509Data>'
          . '      </ds:KeyInfo>'
          . '    </md:KeyDescriptor>'
          . '    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>'
          . '    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>'
          . '    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>'
          . '    <md:AssertionConsumerService'
          . '        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"'
          . '        Location="' . htmlspecialchars($this->ReturnAddr) . '"'
          . '        index="0"'
          . '        isDefault="true"/>'
          . '  </md:SPSSODescriptor>'
          . '  <md:Organization>'
          . '    <md:OrganizationName xml:lang="en"/>'
          . '    <md:OrganizationDisplayName xml:lang="en"/>'
          . '    <md:OrganizationURL xml:lang="en"/>'
          . '  </md:Organization>'
          . '  <md:ContactPerson contactType="support"/>'
          . '  <md:ContactPerson contactType="technical"/>'
          . '</md:EntityDescriptor>';

        self::info('Signing metadata');
        $metadata = $this->calculateXMLDsig($metadata, true);

        return $metadata;
    }

    /**
     * Will generate a metadata signed document that must be published at the URL stated in <issuer> of the IDP
     *
     * @param string $SSOServiceURL
     * @return false|string
     * @throws Exception
     */
    public function generateIdPMetadata($SSOServiceURL = '')
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        self::info('Generating metadata for the IdP');

        $supportedAttributes = '';
        foreach (self::$eIdasAttributes as $FriendlyName => $Name) {
            $supportedAttributes .= '<saml2:Attribute'
              . ' xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"'
              . ' FriendlyName="' . $FriendlyName . '"'
              . ' Name="' . $Name . '"'
              . ' NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />';
        }

        $metadata = '<?xml version="1.0" encoding="UTF-8"?>'
          . '<md:EntityDescriptor'
          . '    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"'
          . '    entityID="' . htmlspecialchars($this->Issuer) . '"'
          . '    validUntil="' . self::generateTimestamp(time() + (1 * 24 * 60 * 60)) . '">'
          . '  <md:Extensions>'
          . '    <alg:DigestMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"'
          . '         Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384" />'
          . '    <alg:DigestMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"'
          . '         Algorithm="http://www.w3.org/2001/04/xmlenc#sha512" />'
          . '    <alg:DigestMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"'
          . '         Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />'
          . '    <alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"'
          . '         Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" />'
          . '    <alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"'
          . '         Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />'
          . '    <alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"'
          . '         Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" />'
          . '    <alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"'
          . '         Algorithm="http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1" />'
          . '  </md:Extensions>'
          . '  <md:IDPSSODescriptor'
          . '      WantAuthnRequestsSigned="true"'
          . '      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
          . '    <md:KeyDescriptor use="signing">'
          . '      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
          . '        <ds:X509Data>'
          . '          <ds:X509Certificate>' . self::implodeCert($this->signCert) . '</ds:X509Certificate>'
          . '        </ds:X509Data>'
          . '      </ds:KeyInfo>'
          . '    </md:KeyDescriptor>'
          . '    <md:KeyDescriptor use="encryption">'
          . '      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
          . '        <ds:X509Data>'
          . '          <ds:X509Certificate>' . self::implodeCert($this->signCert) . '</ds:X509Certificate>'
          . '        </ds:X509Data>'
          . '      </ds:KeyInfo>'
          . '      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes192-cbc" />'
          . '      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc" />'
          . '      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc" />'
          . '    </md:KeyDescriptor>'
          . '    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>'
          . '    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>'
          . '    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>'
          . '    <md:SingleSignOnService'
          . '        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"'
          . '        Location="' . $SSOServiceURL . '" />'
          . '    <md:SingleSignOnService'
          . '        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"'
          . '        Location="' . $SSOServiceURL . '" />'
          . $supportedAttributes
          . '  </md:IDPSSODescriptor>'
          . '  <md:Organization>'
          . '    <md:OrganizationName xml:lang="en"/>'
          . '    <md:OrganizationDisplayName xml:lang="en"/>'
          . '    <md:OrganizationURL xml:lang="en"/>'
          . '  </md:Organization>'
          . '  <md:ContactPerson contactType="support"/>'
          . '  <md:ContactPerson contactType="technical"/>'
          . '</md:EntityDescriptor>';

        self::info('Signing IdP metadata');
        $metadata = $this->calculateXMLDsig($metadata, true);

        return $metadata;
    }

    private static function log($content, $level)
    {
        if ($level < self::$logLevel) {
            return;
        }

        if (is_object($content) || is_array($content)) {
            $message = print_r($content, true);
        } else {
            $message = $content;
        }
        switch ($level) {
            case self::LOG_TRACE:
            case self::LOG_DEBUG:
                Logger::debug($message);
                break;
            case self::LOG_INFO:
                Logger::info($message);
                break;
            case self::LOG_WARN:
                Logger::warning($message);
                break;
            case self::LOG_ERROR:
                Logger::error($message);
                break;
            case self::LOG_CRITICAL:
                Logger::critical($message);
                break;
        }
    }

    private static function trace($message)
    {
        self::log($message, self::LOG_TRACE);
    }

    private static function debug($message)
    {
        self::log($message, self::LOG_DEBUG);
    }

    private static function info($message)
    {
        self::log($message, self::LOG_INFO);
    }

    private static function warn($message)
    {
        self::log($message, self::LOG_WARN);
    }

    private static function error($message)
    {
        self::log($message, self::LOG_ERROR);
    }

    private static function critical($message)
    {
        self::log($message, self::LOG_CRITICAL);
    }

    private function fail($func, $code, $additionalInfo = '')
    {
        $extra = '';
        if ($additionalInfo !== '') {
            $extra = ":\n" . $additionalInfo;
        }

        $lang = $this->defaultLang;
        if ($this->msgLang !== null && isset($this->ERR_MESSAGES[$this->msgLang])) {
            $lang = $this->msgLang;
        }

        self::critical("[Code ${code}] " . $func . '::' . $this->ERR_MESSAGES[$lang]["${code}"] . $extra);
        throw new Exception($func . '::' . $this->ERR_MESSAGES[$lang]["${code}"] . $extra, $code);
    }

    /**
     * Returns the xml document signed in enveloped mode
     *
     * objDig->AddReference: force_uri to force the URI="" attribute on signedinfo (required due to java sec bug)
     * overwrite to false avoid the ID overwrite. $doc->documentElement instead of $doc to target the root element, not
     * the document id_name to set the name of the ID field of the signed node (default 'Id', we need 'ID').
     *
     * @throws Exception
     */
    private function calculateXMLDsig($xml, $insertAhead = false)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        $doc = new DOMDocument();
        $doc->formatOutput = false;
        $doc->preserveWhiteSpace = false;
        $doc->loadXML($xml);

        self::debug('Parsed document to be signed.');

        $objDSig = new XMLSecurityDSig();
        $objDSig->setCanonicalMethod($this->c14nMethod);

        self::debug('Adding reference to root node.');
        $objDSig->addReference(
            $doc->documentElement,
            $this->digestMethod,
            ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', $this->c14nMethod],
            [
                'force_uri' => true,
                'overwrite' => false,
                'id_name' => 'ID',
            ]
        );

        self::debug('Loading signature key.');
        $objKey = new XMLSecurityKey($this->signKeyType, [
            'type' => 'private',
        ]);
        $objKey->loadKey($this->signKey, false);

        self::debug('Signing root node.');
        $objDSig->sign($objKey, $doc->documentElement);

        self::debug('Appending signature certificate.');
        $objDSig->add509Cert($this->signCert);

        if ($insertAhead === true) {
            $objDSig->appendSignature($doc->documentElement, true);
        } else {
            $statusnode = $doc->getElementsByTagName('Status')
                ->item(0);

            $extensions = $doc->getElementsByTagName('Extensions')
                ->item(0);

            $nextnode = $statusnode;
            if ($nextnode === null) {
                $nextnode = $extensions;
            }

            $objDSig->insertSignature($doc->documentElement, $nextnode);
        }

        self::debug('Marshalling signed document.');
        return $doc->saveXML();
    }

    private function checkDates($now, $NotBefore, $NotOnOrAfter)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        self::trace('Now:          ' . date('c', $now));
        self::trace('notBefore:    ' . $NotBefore);
        self::trace('notOnOrAfter: ' . $NotOnOrAfter);

        if ($NotBefore !== null && $NotBefore !== '') {
            if ($now < strtotime($NotBefore)) {
                $this->fail(
                    __FUNCTION__,
                    self::ERR_SAMLRESP_STILLNOTVALID,
                    'Now: ' . date('c', $now) . ". Not until: ${NotBefore}."
                );
            }
        }

        if ($NotOnOrAfter !== null && $NotOnOrAfter !== '') {
            if ($now >= strtotime($NotOnOrAfter)) {
                $this->fail(
                    __FUNCTION__,
                    self::ERR_SAMLRESP_EXPIRED,
                    'Now: ' . date('c', $now) . ". Not on or after: ${NotOnOrAfter}."
                );
            }
        }
    }

    /**
     * Parse the status node on the SamlResponse
     *
     * @param $samlResponse
     * @throws Exception
     */
    private function parseStatus($samlResponse)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        $status = $samlResponse->children(self::NS_SAML2P, false)->Status;

        if (! $status) {
            $this->fail(__FUNCTION__, self::ERR_SAMLRESP_NOSTATUS);
        }

        $statusInfo = [];
        $statusInfo['MainStatusCode'] = '' . $status->StatusCode->attributes()->Value;
        $statusInfo['SecondaryStatusCode'] = null;

        if ($status->StatusMessage) {
            $statusInfo['StatusMessage'] = '' . $status->StatusMessage;
        }

        if ($statusInfo['MainStatusCode'] === self::ST_SUCCESS) {
            $this->responseSuccess = true;
        } else {
            $this->responseSuccess = false;

            if ($status->StatusCode->StatusCode) {
                $statusInfo['SecondaryStatusCode'] = '' . $status->StatusCode->StatusCode->attributes()->Value;
            }
        }

        $this->responseStatus = $statusInfo;
    }

    /**
     * Parse and extract information from the assertion subject TODO see if namequalifier being absent is a problem
     *
     * @param $subject: SimpleXML object representing the Subject
     * @return array|string[]|null
     * @throws Exception
     */
    private function parseAssertionSubject($subject): ?array
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if (! $subject) {
            return null;
        }

        try {
            $subjectInfo = [
                'NameID' => '' . $subject->NameID,
                'NameFormat' => '' . $subject->NameID->attributes()->Format,
                'NameQualifier' => '' . $subject->NameID->attributes()->NameQualifier,
                'Method' => '' . $subject->SubjectConfirmation->attributes()->Method,
                'Address' => '' . $subject->SubjectConfirmation->SubjectConfirmationData->attributes()->Address,
                'InResponseTo' => '' . $subject->SubjectConfirmation->SubjectConfirmationData->attributes()->InResponseTo,
                'NotOnOrAfter' => '' . $subject->SubjectConfirmation->SubjectConfirmationData->attributes()->NotOnOrAfter,
                'NotBefore' => '' . $subject->SubjectConfirmation->SubjectConfirmationData->attributes()->NotBefore,
                'Recipient' => '' . $subject->SubjectConfirmation->SubjectConfirmationData->attributes()->Recipient,
            ];
            if ($subject->NameID->attributes()->NameQualifier) {
                $subjectInfo['NameQualifier'] = '' . $subject->NameID->attributes()->NameQualifier;
            }
        } catch (Exception $e) {
            $this->fail(__FUNCTION__, self::ERR_BAD_ASSERT_SUBJ, $e);
        }

        return $subjectInfo;
    }

    /**
     * Parse and extract information from the assertions
     *
     * @param $assertions: SimpleXML object representing the SamlResponse Assertion nodes
     * @throws Exception
     */
    private function parseAssertions($assertions)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');
        self::info('Number of assertions in response: ' . count($assertions));

        $this->responseAssertions = [];

        try {
            foreach ($assertions as $assertion) {
                $assertionID = '' . $assertion->attributes()->ID;
                if ($assertionID === '') {
                    $this->fail(__FUNCTION__, self::ERR_NO_ASSERT_ID);
                }

                self::debug('Assertion ID: ' . $assertionID);

                if (isset($this->responseAssertions[$assertionID])) {
                    $this->fail(__FUNCTION__, self::ERR_DUP_ASSERT_ID);
                }
                $assertionInfo = [];

                $assertionInfo['ID'] = $assertionID;
                $assertionInfo['IssueInstant'] = '' . $assertion->attributes()->IssueInstant;
                $assertionInfo['Issuer'] = '' . $assertion->Issuer;

                self::debug('Parsing issuer.');
                if ($assertionInfo['Issuer'] === '') {
                    $this->fail(__FUNCTION__, self::ERR_NO_ASSERT_ISSUER);
                }

                self::debug('Parsing subject.');
                $assertionInfo['Subject'] = self::parseAssertionSubject($assertion->Subject);

                self::debug('Parsing conditions.');
                $assertionInfo['Conditions'] = [
                    'NotBefore' => '' . $assertion->Conditions->attributes()->NotBefore,
                    'NotOnOrAfter' => '' . $assertion->Conditions->attributes()->NotOnOrAfter,
                    'OneTimeUse' => '' . (bool) $assertion->Conditions->OneTimeUse,
                    'Audience' => [],
                ];
                foreach ($assertion->Conditions->AudienceRestriction->Audience as $audience) {
                    $assertionInfo['Conditions']['Audience'][] = '' . $audience;
                }

                self::debug('Parsing Authentication Statement.');
                $assertionInfo['AuthnStatement'] = [
                    'AuthnInstant' => '' . $assertion->AuthnStatement->attributes()->AuthnInstant,
                    'SessionIndex' => '' . $assertion->AuthnStatement->attributes()->SessionIndex,
                ];
                if ($assertion->AuthnStatement->SubjectLocality) {
                    $assertionInfo['AuthnStatement']['LocalityAddress'] = '' . $assertion->AuthnStatement->SubjectLocality->attributes()->Address;
                    $assertionInfo['AuthnStatement']['LocalityDNSName'] = '' . $assertion->AuthnStatement->SubjectLocality->attributes()->DNSName;
                }

                if ($assertion->AuthnStatement->AuthnContext) {
                    if ($assertion->AuthnStatement->AuthnContext->AuthnContextClassRef) {
                        $assertionInfo['AuthnStatement']['AuthnContext'] = '' . $assertion->AuthnStatement->AuthnContext->AuthnContextClassRef;
                    }
                }

                self::debug('Parsing Attributes.');
                $assertionInfo['Attributes'] = $this->parseAssertionAttributes(
                    $assertion->AttributeStatement
                );  // TODO SEGUIR I have removed the self because it is not static!

                self::trace("Assertion SimpleXMLNode:\n" . print_r($assertion, true));
                self::trace("Assertion storkAuth inner Struct:\n" . print_r($assertionInfo, true));

                $this->responseAssertions[$assertionID] = $assertionInfo;
            }
        } catch (Exception $e) {
            $this->fail(__FUNCTION__, self::ERR_BAD_ASSERTION, $e);
        }
    }

    /**
     * Parses the attribute statement of an assertion. // $returnValueMeta: eIDAS has some xml attributes indicating the
     * type/language, etc. of each value. If true, values will be arrays and not strings, containing the value and its
     * metadata //Will return an array with the assertion data. 0n eIDAS, attribute //values have one more level of
     * depth: access as ['value']['value]
     *
     * @param $attributeStatement: SimpleXML object representing the attribute statement
     * @param false $returnValueMeta
     * @throws Exception
     */
    private function parseAssertionAttributes($attributeStatement, $returnValueMeta = false): array
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if (! $attributeStatement) {
            $this->fail(__FUNCTION__, self::ERR_ASSERT_NO_ATTRS);
        }

        $attrInfo = [];
        foreach ($attributeStatement->Attribute as $attr) {
            if ($this->mode === 0) {
                $attrname = preg_replace('|.+/(.+?)$|i', '\\1', $attr->attributes()->Name);
                $attrstatus = '' . $attr->attributes(self::NS_STORK, false)->AttributeStatus;
            }
            if ($this->mode === 1) {
                $attrname = '' . $attr->attributes()->FriendlyName;
                $attrstatus = null;
            }

            if (! $attrstatus) {
                $attrstatus = self::ATST_AVAIL;
            }

            self::debug('********MODE: ' . $this->mode);
            self::debug('Parsing Attribute: ' . $attr->attributes()->Name . " (${attrname})");

            $attribute = [
                'friendlyName' => $attrname,
                'Name' => '' . $attr->attributes()->Name,
                'NameFormat' => '' . $attr->attributes()->NameFormat,
                'AttributeStatus' => $attrstatus,
            ];

            if ($attrstatus === self::ATST_AVAIL) {
                self::debug("Attribute ${attrname} available.");

                $attribute['values'] = [];
                foreach ($attr->AttributeValue as $attrval) {
                    if ($this->mode === 0) {
                        if (count($attrval->children(self::NS_STORK)) <= 0) {
                            self::trace("Attribute ${attrname} is simple.");
                            $attribute['values'][] = '' . $attrval;
                        } else {
                            self::trace("Attribute ${attrname} is complex.");
                            $complexAttr = $attrval->xpath('*');
                            if ($complexAttr && count($complexAttr) > 0) {
                                $attrNode = new SimpleXMLElement('<stork:' . $attrname
                        . ' xmlns:stork="' . self::NS_STORK . '"></stork:' . $attrname . '>');
                                foreach ($complexAttr as $subattr) {
                                    $attrNode->addChild($subattr->getName(), '' . $subattr);
                                }
                                $attribute['values'][] = $attrNode->asXML();
                            }
                        }
                    }

                    if ($this->mode === 1) {
                        if ($returnValueMeta === true) {
                            $valueNode = [
                                // TODO  eye: check when you can do real tests. the prefix could change if there are multiple namespaces and would require searching for all of them or passing the namespace as is.
                                'value' => '' . $attrval,
                                'type' => '' . $attrval->attributes('xsi', true)->type,
                            ];

                            if ($attrval->attributes()->languageID) {
                                $valueNode['languageID'] = '' . $attrval->attributes()->languageID;
                            }

                            if ($attrval->attributes(self::NS_EIDASATT)->Transliterated) {
                                $valueNode['Transliterated'] = '' . $attrval->attributes(
                                    self::NS_EIDASATT
                                )->Transliterated;
                            }
                        } else {
                            $valueNode = '' . $attrval;
                        }

                        $attribute['values'][] = $valueNode;
                    }
                }
            } else {
                $attribute['values'] = null;
            }

            $attrInfo[] = $attribute;
        }
        self::trace('Attributes processed:' . print_r($attrInfo, true));
        return $attrInfo;
    }

    /**
     * Verifies the enveloped signature on an XML document, with the embedded certificate or optionally an externally
     * provided certificate.
     *
     * @param $data
     * @param string $externalKey
     * @throws Exception
     */
    private function verifySignature($data, $externalKey = ''): bool
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        self::debug('Parsing signed document.');
        $doc = new DOMDocument();
        if (! $doc->loadXML($data)) {
            $this->fail(__FUNCTION__, self::ERR_BAD_XML_SYNTAX);
        }

        self::debug('Instantiating xmlseclibs object.');
        $objXMLSecDSig = new XMLSecurityDSig();

        self::debug('Searching Signature node.');
        $objDSig = null;
        if ($doc !== null && ($doc instanceof DOMDocument)) {
            $xpath = new DOMXPath($doc);
            $xpath->registerNamespace('ds', self::NS_XMLDSIG);
            $query = '/*/ds:Signature';
            $nodeset = $xpath->query($query, $doc);
            $objDSig = $nodeset->item(0);
            if ($objDSig) {
                self::trace('Signature node found:' . $doc->saveXML($objDSig));
            }
            $objXMLSecDSig->sigNode = $objDSig;
        }

        if (! $objDSig) {
            $this->fail(__FUNCTION__, self::ERR_NO_SIGNATURE);
        }

        self::debug('Canonicalizing signedinfo.');
        $objXMLSecDSig->canonicalizeSignedInfo();

        $objXMLSecDSig->idKeys = self::$referenceIds;
        try {
            self::debug('Validating root node reference.');
            $retVal = $objXMLSecDSig->validateReference();
            if (! $retVal) {
                $this->fail(__FUNCTION__, self::ERR_REF_VALIDATION);
            }
        } catch (Exception $e) {
            $this->fail(__FUNCTION__, self::ERR_REF_VALIDATION, $e);
        }

        self::debug('Searching Keyinfo.');
        $objKey = $objXMLSecDSig->locateKey();
        if (! $objKey) {
            $this->fail(__FUNCTION__, self::ERR_MISSING_SIG_INFO);
        }

        self::debug('Loading embedded verification public key.');
        $objKeyInfo = null;
        try {
            $objKeyInfo = XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);
        } catch (Exception $e) {
            self::warn('No embedded key found. No keyinfo node.');
        }

        $algorithm = $objKey->getAlgorith();
        if (! in_array($algorithm, [
            XMLSecurityKey::RSA_1_5,
            XMLSecurityKey::RSA_SHA1,
            XMLSecurityKey::RSA_SHA256,
            XMLSecurityKey::RSA_SHA384,
            XMLSecurityKey::RSA_SHA512,
        ], true)) {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Unsupported signing algorithm.');
        }

        $extKey = new XMLSecurityKey($algorithm, [
            'type' => 'public',
        ]);

        if ($externalKey === null || $externalKey === '') {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Missing external validation key.');
        }

        self::debug('Loading external verification public key material.');
        $extKey->loadKey($externalKey);

        self::trace('Storing embedded key.');
        $this->signingCert = $objKeyInfo->getX509Certificate();

        if ($extKey->key === null) {
            $this->fail(__FUNCTION__, self::ERR_BAD_PUBKEY_CERT);
            return false;
        }

        self::debug('Verifying signature with external key.');
        $verified = false;
        if ($objXMLSecDSig->verify($extKey) === 1) {
            self::debug('Success.');
            $verified = true;
        } else {
            self::debug('Failure.');
        }

        return $verified;
    }

    /**
     * Validate SamlResponseToken against all trusted issuer certificates.
     *
     * @param $xml
     * @throws Exception
     */
    private function validateXMLDSignature($xml): bool
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($xml === null) {
            $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
        }

        self::debug('Starting external validation [].');
        $validated = false;
        foreach ($this->trustedCerts as $cert) {
            if ($this->verifySignature($xml, $cert)) {
                self::debug('Validated.');
                $validated = true;
                break;
            }
        }

        if (! $validated) {
            self::trace('External validation failure.');
            $this->fail(__FUNCTION__, self::ERR_SIG_VERIF_FAIL);
        }

        return true;
    }

    private function parseXML($xmlStr): SimpleXMLElement
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($xmlStr === null || $xmlStr === '') {
            $this->fail(__FUNCTION__, self::ERR_SAMLRESP_BADXML, 'empty string');
        }

        try {
            @$xmlObj = new SimpleXMLElement($xmlStr);

            if ($xmlObj === null) {
                $this->fail(__FUNCTION__, self::ERR_SAMLRESP_BADXML, 'object is null');
            }
        } catch (Exception $e) {
            $this->fail(__FUNCTION__, self::ERR_SAMLRESP_BADXML, $e);
        }

        return $xmlObj;
    }

    private function parseScoping($samlReq): array
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($samlReq === null) {
            $this->fail(__FUNCTION__, self::ERR_BAD_PARAMETER, 'samlReq object is null');
        }

        $idpList = [];
        $idpEntries = $samlReq->children(self::NS_SAML2P, false)->Scoping->IDPList->IDPEntry;
        if ($idpEntries !== null) {
            foreach ($idpEntries as $idpEntry) {
                $idpList[] = '' . $idpEntry->attributes()->ProviderID;
            }
        }
        return $idpList;
    }

    /**
     * Receives the plain unsigned response xml and the certificate of the recipient SP
     *
     * @param $samlToken
     * @return false|string
     * @throws Exception
     */
    private function encryptAssertions($samlToken)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($samlToken === null || $samlToken === '') {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Empty saml token.');
        }

        if ($this->encryptCert === null || $this->encryptCert === '') {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Recipient certificate for ciphering not set or empty.');
        }

        $doc = new DOMDocument();
        if (! $doc->loadXML($samlToken)) {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Bad XML in input saml token.');
        }

        $key = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, [
            'type' => 'public',
        ]);
        $key->loadKey($this->encryptCert);

        $assertions = $doc->getElementsByTagName('Assertion');
        self::debug('Found assertions to cipher: ' . $assertions->length);
        while ($assertions->length > 0) {
            $assertion = $assertions->item(0);

            $enc = new XMLSecEnc();
            $enc->setNode($assertion);
            $enc->type = XMLSecEnc::Element;

            self::debug('Generating symmetric key (' . $this->keyAlgorithm . ')...');
            $symmetricKey = new XMLSecurityKey($this->keyAlgorithm);
            $symmetricKey->generateSessionKey();

            self::debug('Encrypting symmetric key with public key...');
            $enc->encryptKey($key, $symmetricKey);

            self::debug('Encrypting assertion with symmetric key...');
            $encData = $enc->encryptNode($symmetricKey, false);

            $encData2 = $doc->importNode($encData, true);

            $encAssertion = $doc->createElement('saml2:EncryptedAssertion');

            $encAssertion->appendChild($encData2);

            self::debug('Replacing plain assertion with encrypted one...');
            $assertion->parentNode->replaceChild($encAssertion, $assertion);

            $assertions = $doc->getElementsByTagName('Assertion');
        }

        return $doc->saveXML();
    }

    /**
     * Receives a DomElement object and a xmlsec key and returns a decrypted DomElement. Doesn't perform any checks on
     * the decrypted data. If symmetric key was badly decrypted, it will return trash.
     *
     * @return DOMDocument|DOMElement|string
     * @throws Exception
     */
    private function decryptXMLNode(DOMElement $encryptedData, XMLSecurityKey $decryptKey)
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        $enc = new XMLSecEnc();
        $enc->setNode($encryptedData);
        $enc->type = $encryptedData->getAttribute('Type');

        self::debug('Locating encrypted symmetric key...');
        $symmetricKey = $enc->locateKey($encryptedData);
        if (! $symmetricKey) {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Could not locate key algorithm in encrypted data.');
        }

        self::debug('Locating ciphering algorithm...');
        $symmetricKeyInfo = $enc->locateKeyInfo($symmetricKey);
        if (! $symmetricKeyInfo) {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Could not locate <dsig:KeyInfo> for the encrypted key.');
        }

        if (! $symmetricKeyInfo->isEncrypted) {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Symmetric key not encrypted. Must be encrypted.');
        }

        $decryptKeyAlgo = $decryptKey->getAlgorith();
        $symKeyInfoAlgo = $symmetricKeyInfo->getAlgorith();
        if ($symKeyInfoAlgo === XMLSecurityKey::RSA_OAEP_MGF1P
      && ($decryptKeyAlgo === XMLSecurityKey::RSA_1_5
      || $decryptKeyAlgo === XMLSecurityKey::RSA_SHA1
      || $decryptKeyAlgo === XMLSecurityKey::RSA_SHA512)) {
            $decryptKeyAlgo = XMLSecurityKey::RSA_OAEP_MGF1P;
        }

        if ($decryptKeyAlgo !== $symKeyInfoAlgo) {
            $this->fail(
                __FUNCTION__,
                self::ERR_GENERIC,
                "Key used to encrypt (${symKeyInfoAlgo}) and to decrypt (${decryptKeyAlgo}) don't match"
            );
        }

        $encKey = $symmetricKeyInfo->encryptedCtx;
        self::debug('Loading RSA key to the encrypted key context...');
        $symmetricKeyInfo->key = $decryptKey->key;

        $keySize = $symmetricKey->getSymmetricKeySize();
        if ($keySize === null) {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, "Can't guess key size to check proper decryption");
        }

        try {
            self::debug('Decrypting symmetric key...');
            $key = $encKey->decryptKey($symmetricKeyInfo);
            if (strlen($key) !== $keySize) {
                $this->fail(
                    __FUNCTION__,
                    self::ERR_GENERIC,
                    'Unexpected key size (' . (strlen(
                        $key
                    ) * 8) . 'bits) for encryption algorithm: ' . var_export($symmetricKey->type)
                );
            }
        } catch (Exception $e) {
            self::debug('Failed to decrypt symmetric key');

            $encryptedKey = $encKey->getCipherValue();
            $pkey = openssl_pkey_get_details($symmetricKeyInfo->key);
            $pkey = sha1(serialize($pkey), true);
            $key = sha1($encryptedKey . $pkey, true);
            if (strlen($key) > $keySize) {
                $key = substr($key, 0, $keySize);
            } elseif (strlen($key) < $keySize) {
                $key = str_pad($key, $keySize);
            }
        }

        $symmetricKey->key = $key;

        self::debug('Decrypting data with symmetric key (if succeeded in decrypting it. Rubbish otherwise)');
        $decrypted = $enc->decryptNode($symmetricKey, false);

        return $decrypted;
    }

    /**
     * Receives a saml response token and returns a simpleXML object of the response but replacing any
     * encryptedAssertion by its decrypted counterpart.
     *
     * @param $samlToken
     * @throws Exception
     */
    private function decryptAssertions($samlToken): SimpleXMLElement
    {
        self::debug(__CLASS__ . '.' . __FUNCTION__ . '()');

        if ($samlToken === null || $samlToken === '') {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Empty saml token.');
        }

        if ($this->decryptPrivateKey === null || $this->decryptPrivateKey === '') {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Private key for deciphering not set or empty.');
        }

        self::debug(
            'Loading decryption key...'
        );  // TODO get the key type from the  <ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod> --->  as it is my key, I know I use this algorithm
        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, [
            'type' => 'private',
        ]);
        $objKey->loadKey($this->decryptPrivateKey, false);

        $doc = new DOMDocument();
        if (! $doc->loadXML($samlToken)) {
            $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Bad XML in input saml token.');
        }

        if ($this->onlyEncrypted === true) {
            self::debug('Searching for plain assertions to delete...');
            $assertions = $doc->getElementsByTagName('Assertion');
            self::debug('Found plain assertions: ' . $assertions->length);
            while ($assertions->length > 0) {
                $assertion = $assertions->item(0);

                self::debug('Removing plain assertion...');
                $assertion->parentNode->removeChild($assertion);

                $assertions = $doc->getElementsByTagName('Assertion');
            }
        }

        $assertions = $doc->getElementsByTagName('EncryptedAssertion');
        self::debug('Found assertions to decipher: ' . $assertions->length);
        while ($assertions->length > 0) {
            self::debug('Decrypting assertion...');
            $encAssertion = $assertions->item(0);

            $encData = $encAssertion->getElementsByTagName('EncryptedData');
            if (is_array($encData)) {
                $encData = $encData[0];
            }
            if ($encData instanceof DOMNodeList) {
                $encData = $encData->item(0);
            }
            if ($encData === null) {
                $this->fail(__FUNCTION__, self::ERR_GENERIC, 'No encrypted data node found.');
            }

            $assertion = $this->decryptXMLNode(
                $encData,
                $objKey
            );  // TODO looks like i'm decrypting with rsa private key
            if ($assertion === null) {
                $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Decrypted content is null.');
            }

            $xml = '<root '
              . 'xmlns:saml2p="' . self::NS_SAML2P . '" '
              . 'xmlns:ds="' . self::NS_XMLDSIG . '" '
              . 'xmlns:saml2="' . self::NS_SAML2 . '" '
              . 'xmlns:stork="' . self::NS_STORK . '" '
              . 'xmlns:storkp="' . self::NS_STORKP . '" '
              . 'xmlns:xsi="' . self::NS_XSI . '" >'
              . $assertion
              . '</root>';

            self::debug('Parsing decrypted assertion...');
            $newDoc = new DOMDocument();
            if (! $newDoc->loadXML($xml)) {
                $this->fail(
                    __FUNCTION__,
                    self::ERR_GENERIC,
                    'Error parsing decrypted XML. Possibly Bad symmetric key.'
                );
            }

            $decryptedElement = $newDoc->firstChild->firstChild;
            if ($decryptedElement === null) {
                $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Decrypted content is empty.');
            }

            if (! ($decryptedElement instanceof DOMElement)) {
                $this->fail(__FUNCTION__, self::ERR_GENERIC, 'Decrypted element is not a DOMElement.');
            }

            self::debug('Replacing encrypted assertion with plain one...');
            $f = $doc->createDocumentFragment();
            $f->appendXML($xml);

            $encAssertion->parentNode->replaceChild($f->firstChild->firstChild, $encAssertion);

            $assertions = $doc->getElementsByTagName('EncryptedAssertion');
        }

        return $this->parseXML($doc->saveXML());
    }
}


/**
 * Class claveAuth Wrapper class to simplify integration of clave1.0 (Stork) authentication
 */
class claveAuth
{
    public const LOG_TRACE = 0;

    public const LOG_DEBUG = 1;

    public const LOG_INFO = 2;

    public const LOG_WARN = 3;

    public const LOG_ERROR = 4;

    public const LOG_CRITICAL = 5;

    private $conf;

    private $claveSP;

    private $attributes;

    private static $logLevels = [
        self::LOG_TRACE => 'TRACE',
        self::LOG_DEBUG => 'DEBUG',
        self::LOG_INFO => 'INFO',
        self::LOG_WARN => 'WARN',
        self::LOG_ERROR => 'ERROR',
        self::LOG_CRITICAL => 'CRITICAL',
    ];

    private static $logLevel = self::LOG_TRACE;

    private static $logFile = '/tmp/storkLog2';

    private static $logToFile = true;

    private static $logToStdout = false;

    public function __construct($configFile)
    {
        $this->conf = self::getConfigFromFile($configFile);

        $this->claveSP = new SPlib();

        $this->claveSP->forceAuthn();

        $this->claveSP->setSignatureKeyParams($this->conf['signCert'], $this->conf['signKey'], SPlib::RSA_SHA256);

        $this->claveSP->setSignatureParams(SPlib::SHA256, SPlib::EXC_C14N);

        $this->claveSP->setServiceProviderParams(
            $this->conf['SPname'],
            $this->conf['Issuer'],
            self::full_url($_SERVER)
        );

        $this->claveSP->setSPLocationParams(
            $this->conf['SPCountry'],
            $this->conf['SPsector'],
            $this->conf['SPinstitution'],
            $this->conf['SPapp']
        );

        $this->claveSP->setSPVidpParams($this->conf['SpId'], $this->conf['CitizenCountry']);

        $this->claveSP->setSTORKParams(
            $this->conf['endpoint'],
            $this->conf['QAA'],
            $this->conf['sectorShare'],
            $this->conf['crossSectorShare'],
            $this->conf['crossBorderShare']
        );

        foreach ($this->conf['attributesToRequest'] as $attr) {
            $this->claveSP->addRequestAttribute($attr);
        }

        $this->attributes = [];
    }

    /**
     * @return bool: Returns true if authn succeeded, false if failed, redirects if new authn
     */
    public function authenticate(): bool
    {
        self::debug('**Entra en authenticate');

        if (! array_key_exists('SAMLResponse', $_REQUEST)) {
            self::debug('**do_auth');
            $this->do_Authenticate();
        }
        self::debug('**coming back');
        return $this->handleResponse($_REQUEST['SAMLResponse']);
    }

    /**
     * We transform the attrs to make them compatible with the PoA
     */
    public function getAttributes(): array
    {
        self::debug('**attrs::' . print_r($this->attributes, true));

        $ret = [];
        foreach ($this->attributes as $name => $values) {
            $ret[$name] = $values[0];
        }

        self::debug('**attrs2::' . print_r($ret, true));

        $ret['eIdentifier'] = explode('/', $this->attributes['eIdentifier'][0])[2];

        self::debug('**attrs3::' . print_r($ret, true));

        return $ret;
    }

    /**
     * Returns true if logout succeeded, false if failed, redirects if new logout
     */
    public function logout(): bool
    {
        if (! array_key_exists('samlResponseLogout', $_REQUEST)) {
            $this->do_Logout();
        }

        return $this->handleLogoutResponse($_REQUEST['samlResponseLogout']);
    }

    private static function log($content, $level)
    {
        if ($level < self::$logLevel) {
            return;
        }

        if (is_object($content) || is_array($content)) {
            $message = print_r($content, true);
        } else {
            $message = $content;
        }
        switch ($level) {
            case self::LOG_TRACE:
            case self::LOG_DEBUG:
                Logger::debug($message);
                break;
            case self::LOG_INFO:
                Logger::info($message);
                break;
            case self::LOG_WARN:
                Logger::warning($message);
                break;
            case self::LOG_ERROR:
                Logger::error($message);
                break;
            case self::LOG_CRITICAL:
                Logger::critical($message);
                break;
        }
    }

    private static function trace($message)
    {
        self::log($message, self::LOG_TRACE);
    }

    private static function debug($message)
    {
        self::log($message, self::LOG_DEBUG);
    }

    private static function info($message)
    {
        self::log($message, self::LOG_INFO);
    }

    private static function warn($message)
    {
        self::log($message, self::LOG_WARN);
    }

    private static function error($message)
    {
        self::log($message, self::LOG_ERROR);
    }

    private static function critical($message)
    {
        self::log($message, self::LOG_CRITICAL);
    }

    private function do_Logout()
    {
        $id = SPlib::generateID();

        $req = $this->claveSP->generateSLORequest(
            $this->conf['Issuer'],
            $this->conf['sloEndpoint'],
            self::full_url($_SERVER),
            $id
        );
        $req = base64_encode($req);

        //Save data in session for the comeback
        session_start();
        $_SESSION['storkdemoSPphp']['slorequestId'] = $id;
        $_SESSION['storkdemoSPphp']['sloreturnPage'] = self::full_url($_SERVER);

        $this->redirectLogout($req, $this->conf['sloEndpoint']);
    }

    private function handleLogoutResponse($response): bool
    {
        $resp = base64_decode($response, true);

        $claveSP = new SPlib();

        $claveSP->addTrustedCert($this->conf['validateCert']);

        session_start();

        $claveSP->setValidationContext(
            $_SESSION['storkdemoSPphp']['slorequestId'],
            $_SESSION['storkdemoSPphp']['sloreturnPage']
        );

        if ($claveSP->validateSLOResponse($resp)) {
            return true;
        }

        return false;
    }

    private function handleResponse($response): bool
    {
        $resp = base64_decode($response, true);

        $claveSP = new SPlib();

        $claveSP->addTrustedCert($this->conf['validateCert']);

        session_start();

        $claveSP->setValidationContext($_SESSION['claveLib']['requestId'], $_SESSION['claveLib']['returnPage']);

        $claveSP->setDecipherParams($this->conf['signKey']);

        $claveSP->validateStorkResponse($resp);

        $errInfo = '';
        if (! $claveSP->isSuccess($errInfo)) {
            return false;
        }

        $this->attributes = $claveSP->getAttributes();
        return true;
    }

    private function do_Authenticate()
    {
        $req = base64_encode($this->claveSP->generateStorkAuthRequest());

        session_start();
        $_SESSION['claveLib']['requestId'] = $this->claveSP->getRequestId();
        $_SESSION['claveLib']['returnPage'] = self::full_url($_SERVER);

        $forcedIdP = '';
        $idpList = '';
        $excludedIdPList = '';
        $allowLegalPerson = '';

        if ($this->conf['forcedIdP'] !== null) {
            $forcedIdP = '<input type="hidden" name="forcedIdP" value="' . $this->conf['forcedIdP'] . '" />';
        }
        if ($this->conf['idpList'] !== null) {
            $idpList = '<input type="hidden" name="idpList" value="' . $this->conf['idpList'] . '" />';
        }
        if ($this->conf['excludedIdPList'] !== null) {
            $excludedIdPList = '<input type="hidden" name="excludedIdPList" value="' . $this->conf['excludedIdPList'] . '" />';
        }
        if ($this->conf['allowLegalPerson'] !== null) {
            $allowLegalPerson = '<input type="hidden" name="allowLegalPerson" value="' . $this->conf['allowLegalPerson'] . '" />';
        }

        $this->redirectLogin(
            $req,
            $this->conf['endpoint'],
            $forcedIdP,
            $idpList,
            $excludedIdPList,
            $allowLegalPerson
        );
    }

    private function redirectLogin(
        $req,
        $endpoint,
        $forcedIdP = '',
        $idpList = '',
        $excludedIdPList = '',
        $allowLegalPerson = ''
    ) {
        self::redirect('SAMLRequest', $req, $endpoint, $forcedIdP, $idpList, $excludedIdPList, $allowLegalPerson);
    }

    private function redirectLogout(
        $req,
        $endpoint,
        $forcedIdP = '',
        $idpList = '',
        $excludedIdPList = '',
        $allowLegalPerson = ''
    ) {
        self::redirect(
            'samlRequestLogout',
            $req,
            $endpoint,
            $forcedIdP,
            $idpList,
            $excludedIdPList,
            $allowLegalPerson
        );
    }

    private static function redirect(
        $postParam,
        $req,
        $endpoint,
        $forcedIdP = '',
        $idpList = '',
        $excludedIdPList = '',
        $allowLegalPerson = ''
    ) {
        echo '
<html>
  <body onload="document.forms[0].submit();">
	   <form name="redirectForm" method="post" action="' . $endpoint . '">
		    <input type="hidden" name="' . $postParam . '" value="' . $req . "\" />
            ${forcedIdP}
            ${idpList}
            ${excludedIdPList}
            ${allowLegalPerson}
	   </form>
	 </body>
</html>
";
        exit(0);
    }

    /**
     * Don't use _once in file or the global variable might get unset.
     *
     * @param $file
     * @throws Exception
     */
    private static function getConfigFromFile($file): array
    {
        try {
            require($file);
        } catch (Exception $e) {
            throw new Exception('Clave config file ' . $file . ' not found.');
        }

        if (! isset($clave_config)) {
            throw new Exception('$clave_config global variable not found in ' . $file);
        }

        if (! is_array($clave_config)) {
            throw new Exception('$clave_config global variable not an array in ' . $file);
        }

        return $clave_config;
    }

    private static function url_origin($s, $use_forwarded_host = false): string
    {
        $ssl = (! empty($s['HTTPS']) && $s['HTTPS'] === 'on');
        $sp = strtolower($s['SERVER_PROTOCOL']);
        $protocol = substr($sp, 0, strpos($sp, '/')) . (($ssl) ? 's' : '');
        $port = $s['SERVER_PORT'];
        $port = ((! $ssl && $port === '80') || ($ssl && $port === '443')) ? '' : ':' . $port;
        $host = ($use_forwarded_host && isset($s['HTTP_X_FORWARDED_HOST'])) ? $s['HTTP_X_FORWARDED_HOST'] : ($s['HTTP_HOST'] ?? null);
        $host = $host ?? $s['SERVER_NAME'] . $port;
        return $protocol . '://' . $host;
    }

    private static function full_url($s, $use_forwarded_host = false): string
    {
        return self::url_origin($s, $use_forwarded_host) . $s['REQUEST_URI'];
    }
}
