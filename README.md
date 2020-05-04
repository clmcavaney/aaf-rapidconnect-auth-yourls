Heavily based on the Google Auth Yourls (https://github.com/8thwall/google-auth-yourls)

### Installation
1. Download this repo and extract the whole folder into `YOURLS/user/plugins`
2. Head to the "Manage Plugins" -> "AAF Rapid Connect options" menu item
3. Fill in the details (see Configuration below) and submit to store they in the database

At this point users will be able login, but their roles won't be defined.
For that another plugin is required - [YOURLS-AuthMgrPlus](https://github.com/joshp23/YOURLS-AuthMgrPlus)

**NOTE** If you already have YOURLS-AuthMgrPlus enabled, you will need to give your default authentication username administrator rights so that you can access the plugins pages to configure the AAF Rapid Connect plugin.  Once that is configured you can remove the default user from the YOURLS-AuthMgrPlus administrator role (not 100% necessary - but keeps things clean).

Configuration
-------------
You will need to specify the following values in the plugins options page for AAF Rapid Connect.

```
AAF Rapid Connect Key - your KEY which you generated when you register an app with AAF Rapid Connect
AAF Rapid Connect Auth URL - given to you when the service is registered 
AAF Rapid Connect Issuer - https://rapid.test.aaf.edu.au or https://rapid.aaf.edu.au
AAF Rapid Connect Audience - URL provided when you register your service
AAF User Attribute - usually 'mail'
```

To generate these head to AAF's Rapid Connect registration service - https://rapid.test.aaf.edu.au/

License
-------
Copyright 2017 Christopher McAvaney
