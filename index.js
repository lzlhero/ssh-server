require('events').EventEmitter.prototype._maxListeners = Infinity;
var fs = require('fs');
var crypto = require('crypto');
var net = require('net');
var inspect = require('util').inspect;
var buffersEqual = require('buffer-equal-constant-time');
var ssh2 = require('ssh2');
var utils = ssh2.utils;
const debug = true;

function consoleLog(...arg) {
	if (debug) {
		console.log(...arg);
	}
}

function setupErrorHandlers(src, dest) {
	setupCorrectBreakDown(src, dest);
	setupCorrectBreakDown(dest, src);
}

function setupCorrectBreakDown(src, dest) {
	src.on('error', function (e) {
		if (e.code !== 'ECONNRESET' && e.code !== 'EPIPE') {
			consoleLog('proxy error: ' + e.code + ' ' + e.address + ':' + e.port);
		}
		src.destroy();
		dest.destroy();
	});  
}

// get the user's public key
var pubKey = utils.genPublicKey(utils.parseKey(fs.readFileSync('id_rsa.pub')));
// create the ssh server
new ssh2.Server({
	hostKeys: [fs.readFileSync('host.key')]
}, function(client) {
	consoleLog('client: connected');

	// authentication
	client
	.on('authentication', function(ctx) {
		if (ctx.method === 'publickey'
			&& ctx.key.algo === pubKey.fulltype
			&& ctx.username === 'lewis'
			&& buffersEqual(ctx.key.data, pubKey.public)) {
			if (ctx.signature) {
				var verifier = crypto.createVerify(ctx.sigAlgo);
				verifier.update(ctx.blob);
				if (verifier.verify(pubKey.publicOrig, ctx.signature)) {

					consoleLog('auth: user/key verified ok');
					ctx.accept();
				}
				// public key failed
				else {
					consoleLog('auth: public key failed');
					ctx.reject();
				}
			} else {
				// if no signature present, that means the client is just checking
				// the validity of the given public key
				consoleLog('auth: client is checking public key');
				ctx.accept();
			}
		}
		// authentication begin
		else {
			consoleLog('auth: begin');
			ctx.reject();
		}
	})
	.on('ready', function() {

		client
		.on('session', function(accept, reject) {
			var session = accept();
			session
			.once('pty', function(accept, reject, info) {
				consoleLog('session: pty');
			})
			.once('env', function(accept, reject, info) {
				consoleLog('session: env');
			})
			.once('window-change', function(accept, reject, info) {
				consoleLog('session: window-change');
			})
			// ssh shell session
			.once('shell', function(accept, reject) {
				consoleLog('session: shell');
				var stream = accept();
				stream.write('ssh shell is not supported.\n\r');
				stream.exit(0);
				stream.end();
			})
			// ssh exec session
			.once('exec', function(accept, reject, info) {
				consoleLog('session: exec: ' + inspect(info.command));
				var stream = accept();
				stream.write('ssh exec is not supported.\n\r');
				stream.exit(0);
				stream.end();
			});
		})
		// ssh socks5 proxy
		.on('tcpip', function(accept, reject, info) {
			var down = accept();
			var up = net.createConnection(info.destPort, info.destIP, function() {
				down.pipe(up).pipe(down);
				consoleLog('proxy: ' + info.destIP + ':' + info.destPort);
			});

			setupErrorHandlers(up, down);
		});
	})
	.on('error', function(e) {
		consoleLog('cliient: error ' + e);
	})
	.on('end', function() {
		consoleLog('client: disconnected');
	});
}).listen(3022, '0.0.0.0', function() {
	consoleLog('Listening on ' + this.address().address + ':' + this.address().port);
});
