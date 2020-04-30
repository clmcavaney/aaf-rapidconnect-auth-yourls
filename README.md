Heavily based on the Google Auth Yourls (https://github.com/8thwall/google-auth-yourls)

### Installation
1. Download this repo and extract the whole folder into `YOURLS/user/plugins`
2. `cd` to the directory you just created
3. Edit the config.php file in that directory (see below)

At this point users will be able login, but their roles won't be defined.
For that another plugin is required - [YOURLS-AuthMgrPlus](https://github.com/joshp23/YOURLS-AuthMgrPlus)

Configuration
-------------
You will need to specify the following defined variables in the config.php file of that plugins directory:

```
define('AAF_RAPIDCONNECT_KEY', '<your KEY which is generated when you register an app with AAF Rapid Connect>');
define('AAF_RAPIDCONNECT_AUTH_URL', 'https://rapid.test.aaf.edu.au/jwt/authnrequest/<provided when you register your service>');
define('AAF_RAPIDCONNECT_ISSUER', 'https://rapid.test.aaf.edu.au');
define('AAF_RAPIDCONNECT_AUDIENCE', '<URL provided when you register your service>');
```

To generate these head to AAF's Rapid Connect registration service - https://rapid.test.aaf.edu.au/

License
-------
Copyright 2017 Christopher McAvaney
