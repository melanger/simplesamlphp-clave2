<?php
/**
 * Clave IdP for simpleSAMLphp. [DEPRECATED]
 */


SimpleSAML\Logger::debug('Call to Clave bridge IdP side [old endpoint]');

SimpleSAML\Utils\HTTP::submitPOSTData(SimpleSAML\Module::getModuleURL('clave/idp/SSOService.php'), $_POST);
die();
