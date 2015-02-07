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
    var entry, tentry, tchild = {};
    var table = [];
    var rclass, ttl, rlen, ip, pref, txt;
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

    /*
    console.log('questions: ' + questions);
    console.log('answers: ' + answers);
    console.log('authRRs: ' + authRRs);
    console.log('aditRRs: ' + aditRRs); */


    /* Parse queries */
    for (var x = 0; x < questions; x++) {
        entry = decompressLabel(response, offset);
        //console.log('entry: ' + entry.name);
        
        result.questions.push({
            name: entry.name,
            type: 'AXFR'
        });

        /* Skip type and class (4 bytes) */
        offset = entry.next + 4;
    };

    /* Parse answers */
    for (var x = 0; x < answers; x++) {
        entry = decompressLabel(response, offset);
        //console.log('[+] entry: ' + entry.name);
        offset = entry.next;

        tentry = tchild = {};
        tentry.name = entry.name;

        //console.log('offset2: ' + offset);

        tentry.type = response.readUInt16BE(offset);
        rclass = response.readUInt16BE(offset+2);
        ttl = response.readUInt32BE(offset+4);
        rlen = response.readUInt16BE(offset+8);

        //console.log('tentry.len: ' + tentry.rlen);


        /* Skip classes != INET */
        if (rclass != 0x01) {
            offset += rlen + 10;
            continue;
        }

        /* Parse answer rdata */
        switch (tentry.type) {
            /* A Record */
            case 0x01:
                tentry.type = 'A';
                tentry.a = inet_ntoa(response.readUInt32BE(offset+10));
                //console.log('  - A: ' + inet_ntoa(ip));
                break;

            /* NS Record */
            case 0x02:
                tentry.type = 'NS';
                tentry.ns = decompressLabel(response, (offset + 10)).name;
                //console.log('  - NS: ' + entry.name);
                break;

            /* CNAME Record */
            case 0x05:
                tentry.type = 'CNAME';
                tentry.cname = decompressLabel(response, (offset + 10)).name;
                //console.log('  - CNAME: ' + entry.name);
                break;

            /* SOA Record */
            case 0x06:
                tentry.type = 'SOA';
                tchild = decompressLabel(response, (offset + 10));
                tentry.dns = tchild.name;
                tchild = decompressLabel(response, (tchild.next));
                tentry.mail = tchild.name;
                tentry.serial = response.readUInt32BE(tchild.next);
                tentry.refresInterval = response.readUInt32BE(tchild.next+4);
                tentry.retryInterval = response.readUInt32BE(tchild.next+8);
                tentry.expireLimit = response.readUInt32BE(tchild.next+12);
                tentry.minTTL = response.readUInt32BE(tchild.next+16);
                break;

            /* MX Record */
            case 0x0f:
                tentry.type = 'MX';
                tentry.pref = response.readUInt16BE(offset+10);
                tentry.mx = decompressLabel(response, (offset + 12)).name;
                //console.log('  - MX ' + pref  + ': ' + entry.name);
                break;

            /* TXT Record */
            case 0x10:
                tentry.type = 'TXT';
                len = response[offset+10];
                tentry.txt = response.toString('utf8', offset+11, offset+11+len);
                //console.log('  - TXT: ' + txt);
                break;
        }

        result.answers.push(tentry);


        offset += rlen + 10;
        

        //console.log('new offset: ' + offset);
    };

    //console.log('offset: ' + offset);
    //var temp = response.slice(offset, offset + 8);
    //console.log(util.inspect(temp));

    //console.log(util.inspect(result));
    //console.log('ok');
    
    return result;
}


dns.resolveAxfr = function(server, domain, callback) {

    var buffers = [];
    var split = domain.split('.');

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

    var socket = net.connect(53, server, function(arguments) {
        //console.log("Connected")
        socket.write(buffer.toString('binary'), 'binary');
    });

    socket.on('data', function(data) {
        //console.log(util.inspect(data));
        //console.log(data.toString());
        var res = parseResponse(data);
        socket.end();

        if (typeof res === 'object')
            callback(0, res);
        else
            callback(res, null);
    });

    /*
    socket.on('end', function() {
        console.log("Connection closed");
    }); */

    //console.log(util.inspect(buffer));
    //console.log(util.inspect(buffers));

};

module.exports = dns;
