var dns = require('dns');
var net = require('net');


var axfrReqProloge = 
    "\x00\x00" +        /* Size */
    "\x00\x00" +        /* Transaction ID */
    "\x00\x20" +        /* Flags: Standard Query */
    "\x00\x01" +        /* Number of questions */
    "\x00\x00" +        /* Number of answers */
    "\x00\x00" +        /* Number of Authority RRs */
    "\x00\x00";         /* Number of Aditional RRs */

var axfrReqEpiloge =
    "\x00" +            /* End of name */
    "\x00\xfc" +        /* Type: AXFR */
    "\x00\x01";         /* Class: IN */


function inet_ntoa(num){
    var nbuffer = new ArrayBuffer(4);
    var ndv = new DataView(nbuffer);
    ndv.setUint32(0, num);

    var a = new Array();
    for(var i = 0; i < 4; i++){
        a[i] = ndv.getUint8(i);
    }
    return a.join('.');
}


function decompressLabel(data, offset) {
    var res = { len: 0, name: '' };
    var loffset = offset;
    var tmpoff = 0;

    while (data[loffset] != 0x00) {

        /* Check for pointers */
        if ((data[loffset] & 0xc0) == 0xc0) {
            var newoffset = data.readUInt16BE(loffset) & 0x3FFF;
            var label = decompressLabel(data, (newoffset + 2));
            res.name += label.name;
            loffset += 1;
            break;

        /* Normal label */
        } else {
            tmpoff = loffset + 1;
            res.name += data.toString('utf8', tmpoff, (tmpoff + data[loffset]));
            res.name += '.';
            loffset += data[loffset] + 1;
        }
    }

    res.next = loffset + 1;
    //console.log(res.name);

    return res;
}


function parseResponse(response) {

    var offset = 14;
    var entry, tentry = {};
    var table = [];
    var rclass, rlen;
    var len = response.readUInt16BE(0);

    var result = { questions: [], answers: [] };

    /* Check for valid length */
    if (response.length != (len + 2))
        return -1;

    /* Check for query response packet */
    if ((response[4] & 0x80) != 0x80)
        return -2;

    /* Check for error code */
    if ((response[5] & 0x0F) != 0)
        return -3;

    var questions = response.readUInt16BE(6);
    var answers = response.readUInt16BE(8);
    var authRRs = response.readUInt16BE(10);
    var aditRRs = response.readUInt16BE(12);

    /* Parse queries */
    for (var x = 0; x < questions; x++) {
        entry = decompressLabel(response, offset);
        
        result.questions.push({
            name: entry.name,
            type: 'AXFR'
        });

        /* Skip type and class (4 bytes) */
        offset = entry.next + 4;
    };

    /* Parse answers */
    for (var x = 0; x < answers; x++) {
        entry = tentry = {};

        /* Parse entry label */
        entry = decompressLabel(response, offset);
        offset = entry.next;
        entry.name = entry.name;

        /* Get fields after label */
        entry.type = response.readUInt16BE(offset);
        rclass = response.readUInt16BE(offset+2);
        entry.ttl = response.readUInt32BE(offset+4);
        rlen = response.readUInt16BE(offset+8);

        /* Skip classes != INET */
        if (rclass != 0x01) {
            offset += rlen + 10;
            continue;
        }

        /* Parse answer rdata */
        switch (entry.type) {
            /* A Record */
            case 0x01:
                entry.type = 'A';
                entry.a = inet_ntoa(response.readUInt32BE(offset+10));
                break;

            /* NS Record */
            case 0x02:
                entry.type = 'NS';
                entry.ns = decompressLabel(response, (offset + 10)).name;
                break;

            /* CNAME Record */
            case 0x05:
                entry.type = 'CNAME';
                entry.cname = decompressLabel(response, (offset + 10)).name;
                break;

            /* SOA Record */
            case 0x06:
                entry.type = 'SOA';
                tentry = decompressLabel(response, (offset + 10));
                entry.dns = tentry.name;
                tentry = decompressLabel(response, (tentry.next));
                entry.mail = tentry.name;
                entry.serial = response.readUInt32BE(tentry.next);
                entry.refresInterval = response.readUInt32BE(tentry.next+4);
                entry.retryInterval = response.readUInt32BE(tentry.next+8);
                entry.expireLimit = response.readUInt32BE(tentry.next+12);
                entry.minTTL = response.readUInt32BE(tentry.next+16);
                break;

            /* MX Record */
            case 0x0f:
                entry.type = 'MX';
                entry.pref = response.readUInt16BE(offset+10);
                entry.mx = decompressLabel(response, (offset + 12)).name;
                break;

            /* TXT Record */
            case 0x10:
                entry.type = 'TXT';
                len = response[offset+10];
                entry.txt = response.toString('utf8', offset+11, offset+11+len);
                break;
        }

        result.answers.push(entry);
        offset += rlen + 10;
    };
    
    return result;
}


dns.resolveAxfr = function(server, domain, callback) {

    var buffers = [];
    var split = domain.split('.');

    /* Build the request */
    buffers.push(new Buffer(axfrReqProloge, 'binary'));
    split.forEach(function(elem) {
        var label = new Buffer('\00' + elem, 'utf8');
        label.writeUInt8(elem.length, 0);
        buffers.push(label);
    });
    buffers.push(new Buffer(axfrReqEpiloge, 'binary'));
    var buffer = Buffer.concat(buffers);

    /* Set size and transaction ID */
    buffer.writeUInt16BE(buffer.length - 2, 0);
    buffer.writeUInt16BE(Math.floor((Math.random() * 65535) + 1) , 2);

    /* Connect and send request */
    var socket = net.connect(53, server, function(arguments) {
        socket.write(buffer.toString('binary'), 'binary');
    });

    /* Parse response */
    socket.on('data', function(data) {
        var res = parseResponse(data);
        socket.end();

        if (typeof res === 'object')
            callback(0, res);
        else
            callback(res, "Error on response");
    });

    socket.on('error', function() {
        callback(-4, "Error connecting");
    });

};

module.exports = dns;
