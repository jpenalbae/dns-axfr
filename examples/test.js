var dns = require('../');
var util = require('util');

dns.resolveAxfr('dns01.acme.com', 'acme.com', function(err, addr) {
    if (err) {
        console.error('Error ocurred: ' + err);
        return;
    }

    console.log(util.inspect(addr));
});