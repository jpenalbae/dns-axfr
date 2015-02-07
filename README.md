# dns-axfr

dns-axfr is a node.js module which extends dns core module to add support for AXFR type queries. It can be useful for pentesting tasks, automating recursive zone transfers, etc...

The following type of records are supported:
* A
* CNAME
* SOA
* MX
* NS
* TXT

## Usage

### resolveAxfr(server, zone, callback)
```javascript
var dns = require('dns-axfr');
var util = require('util');

dns.resolveAxfr('dns01.acme.com', 'acme.com', function(err, addr) {
    if (err) {
        console.error('Error ocurred: ' + addr + ' (' + err + ')');
        return;
    }

    console.log(util.inspect(addr));
});
```


As it extends the core dns module, you can access the original module without "requiring" it again:
```javascript
var dns = require('dns-axfr');
var util = require('util');

/* Extended function */
dns.resolveAxfr('dns01.acme.com', 'acme.com', function(err, addr) {
    if (err) throw err;
    console.log(util.inspect(addr));
});

/* Original dns module function */
dns.resolve4('www.google.com', function (err, addresses) {
  if (err) throw err;
  console.log(util.inspect(addresses));
});
```

