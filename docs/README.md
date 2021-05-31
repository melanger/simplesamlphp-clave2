Stork single logout (SPlib.php) has some differences with the standard saml logout:

    Only HTTP-POST binding, and always signed
    
    As no NameID is used to keep session info, nameid type is
    unspecified and content is the ProviderName of the logout
    requesting SP (the value that is used on the authnReq to match
    the cert on their trust store)
    
    POST param is not the standard "SAMLRequest". Instead you MUST
    use "samlRequestLogout"
    
    In a similar fashion, the repsonse must not be expected at
    "SAMLResponse" but at "samlResponseLogout"
    
    The content of the issuer field must not be the EntityID of the
    issuer. Instead, as STORK does not use Metadata transfer from SP
    to IdP, here the SingleLogout endpoint URL of the SP must be
    specified.
