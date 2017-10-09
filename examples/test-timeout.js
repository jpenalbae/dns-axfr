var dns = require('../');
var util = require('util');

dns.resolveAxfrTimeout(1000);

dns.resolveAxfr('192.168.23.1', 'acme.com', function(err, addr) {
    if (err) {
        console.error('Error ocurred: ' + addr + ' (' + err + ')');
        return;
    }

    console.log(util.inspect(addr));
});
