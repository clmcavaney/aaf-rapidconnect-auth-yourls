<?php
// PROD
define('AAF_RAPIDCONNECT_KEY', '<your KEY which is generated when you register an app with AAF Rapid Connect>');
// Will be something like
// https://rapid.test.aaf.edu.au/jwt/authnrequest/research/<hash value>
define('AAF_RAPIDCONNECT_AUTH_URL', 'https://rapid.aaf.edu.au/jwt/authnrequest/<provided when you register your service>');
define('AAF_RAPIDCONNECT_ISSUER', 'https://rapid.aaf.edu.au');


// DEV
// define('AAF_RAPIDCONNECT_KEY', '<your KEY which is generated when you register an app with AAF Rapid Connect>');
// define('AAF_RAPIDCONNECT_AUTH_URL', 'https://rapid.test.aaf.edu.au/jwt/authnrequest/<provided when you register your service>');
// define('AAF_RAPIDCONNECT_ISSUER', 'https://rapid.test.aaf.edu.au');


define('AAF_RAPIDCONNECT_AUDIENCE', '<URL provided when you register your service>');

// Attributes for Rapid Connect are shown on this page: https://rapid.aaf.edu.au/developers
define('AAF_ATTRIBUTE_USER', 'mail');
