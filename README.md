# dns-axfr

dns-axfr is a node.js module which extends dns core module to add support for AXFR type queries. It can be useful for pentesting tasks, automating recursive zone transfers, etc...

The following type of records are supported:

- A
- CNAME
- SOA
- MX
- NS
- TXT
- AAAA
- SPF
- SRV
- PTR

## Usage

In order to perform an AXFR query use `resolveAxfr()`

### resolveAxfr(server, zone, callback)

```javascript
var dns = require("dns-axfr");
var util = require("util");

dns.resolveAxfr("dns01.acme.com", "acme.com", function (err, addr) {
  if (err) {
    console.error("Error ocurred: " + addr + " (" + err + ")");
    return;
  }

  console.log(util.inspect(addr));
});
```

Reverse lookup example

```javascript
var dns = require("dns-axfr");
var util = require("util");

dns.resolveAxfr("dns01.acme.com", "0.0.10.in-addr.arpa", function (err, addr) {
  if (err) {
    console.error("Error ocurred: " + addr + " (" + err + ")");
    return;
  }

  console.log(util.inspect(addr));
});
```

If you need to setup a timeout for the request use `resolveAxfrTimeout()` and set the desired timeout in milliseconds.

### resolveAxfrTimeout(timeout)

```javascript
var dns = require("dns-axfr");
var util = require("util");

dns.resolveAxfrTimeout(1000);

dns.resolveAxfr("dns01.acme.com", "acme.com", function (err, addr) {
  if (err) {
    console.error("Error ocurred: " + addr + " (" + err + ")");
    return;
  }

  console.log(util.inspect(addr));
});
```

As this module extends the core dns module, you can access the original module without "requiring" it again:

```javascript
var dns = require("dns-axfr");
var util = require("util");

/* Extended function */
dns.resolveAxfr("dns01.acme.com", "acme.com", function (err, addr) {
  if (err) throw err;
  console.log(util.inspect(addr));
});

/* Original dns module function */
dns.resolve4("www.google.com", function (err, addresses) {
  if (err) throw err;
  console.log(util.inspect(addresses));
});
```

## Sample results

Forward lookup example

```javascript
{
    questions: [
        {
            name: 'acme.es.',
            type: 'AXFR'
        }
    ],
    answers: [
        {
            name: 'acme.es.',
            type: 'SOA',
            ttl: 21600,
            dns: 'ns1.acme.es.',
            mail: 'root.ns1.acme.es.',
            serial: 2015012401,
            refresInterval: 14400,
            retryInterval: 7200,
            expireLimit: 2592000,
            minTTL: 28800
        },
        {
            name: 'acme.es.',
            type: 'A',
            ttl: 21600,
            a: '127.0.2.22'
        },
        {
            name: 'acme.es.',
            type: 'NS',
            ttl: 21600,
            ns: 'ns1.acme.es.'
        },
        {
            name: 'acme.es.',
            type: 'NS',
            ttl: 21600,
            ns: 'ns2.acme.es.'
        },
        {
            name: 'subdomain.acme.es.',
            type: 'NS',
            ttl: 21600,
            ns: 'ns1.acme.es.'
        },
        {
            name: 'subdomain.acme.es.',
            type: 'NS',
            ttl: 21600,
            ns: 'ns2.acme.es.'
        },
        {
            name: 'ns1.acme.es.',
            type: 'A',
            ttl: 21600,
            a: '127.0.2.69'
        },
        {
            name: 'ns2.acme.es.',
            type: 'A',
            ttl: 21600,
            a: '127.0.2.70'
        },
        {
            name: 'test.acme.es.',
            type: 'CNAME',
            ttl: 21600,
            cname: 'www.acme.com.'
        },
        {
            name: 'www.acme.es.',
            type: 'A',
            ttl: 21600,
            a: '127.0.2.22'
        }
    ]
}
```

Reverse lookup example

```javascript
{
    questions: [
        {
            name: '0.0.10.in-addr.arpa.',
            type: 'AXFR'
        }
    ],
    answers: [
        {
            name: '0.0.10.in-addr.arpa.',
            type: 'SOA',
            ttl: 21600,
            dns: 'ns1.acme.es.',
            mail: 'root.ns1.acme.es.',
            serial: 2015012401,
            refresInterval: 14400,
            retryInterval: 7200,
            expireLimit: 2592000,
            minTTL: 28800
        },
        {
            name: '1.0.0.10.in-addr.arpa.',
            type: 'PTR',
            ttl: 21600,
            dns: 'gateway.acme.es.'
        },
        {
            name: '2.0.0.10.in-addr.arpa.',
            type: 'PTR',
            ttl: 21600,
            dns: 'ns1.acme.es.'
        }
    ]
}
```
