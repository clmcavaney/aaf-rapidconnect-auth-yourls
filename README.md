Heavily based on the Google Auth Yourls (https://github.com/8thwall/google-auth-yourls)

You will need to specify the following defined variables in your config.php file:

```
define('AAF_RAPIDCONNECT_KEY', '<your KEY which is generated when you register an app with AAF Rapid Connect>');
define('AAF_RAPIDCONNECT_AUTH_URL', 'https://rapid.test.aaf.edu.au/jwt/authnrequest/<provided when you register your service>');
define('AAF_RAPIDCONNECT_ISSUER', 'https://rapid.test.aaf.edu.au');
define('AAF_RAPIDCONNECT_AUDIENCE', '<URL provided when you register your service>');
```

*** FURTHER DOCUMENTATION REQUIRED HERE ***
