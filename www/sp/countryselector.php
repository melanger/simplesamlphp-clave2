<?php

/**
 * Country selector interface for eIDAS
 */

$claveConfig = SimpleSAML\Module\clave\Tools::getMetadataSet('__DYNAMIC:1__', 'clave-idp-hosted');
SimpleSAML\Logger::debug('Clave Idp hosted metadata: ' . print_r($claveConfig, true));


$hostedSP = $claveConfig->getString('hostedSP', null);
if ($hostedSP === null) {
    throw new SimpleSAML\Error\Exception('No clave hosted SP configuration defined in clave bridge configuration.');
}
$claveSP = SimpleSAML\Module\clave\Tools::getMetadataSet($hostedSP, 'clave-sp-hosted');
SimpleSAML\Logger::debug('Clave SP hosted metadata: ' . print_r($claveSP, true));


$countries = $claveSP->getArray('countries', []);




$returnURL = SimpleSAML\Utils\HTTP::checkURLAllowed($_GET['return']);
$returnIdParam = 'country';

$countryLines = '';
foreach ($countries as $countryCode => $countryName) {
    $countryLines .= '<option value="' . $countryCode . '">' . $countryName . '</option>';
}


$page = '<html lang="es">'
    . '  <body>'
    . '    <form action="' . $returnURL . '" method="POST">'
    . '      Seleccione su país de orígen:<br/>'
    . '      <br/>'
    . '      <select name="' . $returnIdParam . '">'
    . $countryLines
    . '      </select>'
    . '      <br/>'
    . '      <br/>'
    . '      <input type="submit" value="Continuar">'
    . '    </form>'
    . '  </body>'
    . '</html>';


echo $page;






//TODO multilanguage

//TODO include ssphp template header and footer

// TODO implement all html in the module as templates (see if the other modules redirects use the standard calls)
