function generateOIDInfoHref(oid, content) {
	var a = document.createElement("a");
	a.appendChild(document.createTextNode(content));
	a.setAttribute("href", "http://www.oid-info.com/cgi-bin/display?tree="
			+ encodeURIComponent(oid));
	a.setAttribute("title", oid);
	a.setAttribute("target", "_blank");
	return a;
}

function createHeader(content) {
	var h = document.createElement("h1");
	h.appendChild(document.createTextNode(content));
	return h;
}

function events() {
	var domain = document.getElementById('domain').value;
	var port = document.getElementById('port').value;

	if (port.trim() == "") {
		port = 443;
	}

	var iplist = new Array();

	var handleMessage = function(container, stream, msg) {
		// var message = JSON.parse(e.data);
		var text = document.createTextNode(msg);
		var node = document.createElement("div");
		node.appendChild(text);
		container.appendChild(node);
	};

	var handleError = function(container, stream, msg) {
		stream.close();
		handleMessage(container, stream, "error");
	};

	function hostInfoToURL(hostinfo, base) {
		if (base === undefined) {
			base = "/test.event"
		}
		return base + '?domain=' + encodeURIComponent(hostinfo.domain)
				+ (hostinfo.ip ? '&ip=' + encodeURIComponent(hostinfo.ip) : '')
				+ '&port=' + encodeURIComponent(hostinfo.port);
	}

	function Stream(c, url) {
		this.getTargetContainer = function() {
			return c;
		}

		var stream = new EventSource(url);
		var streamSelf = this;
		this.registerEvent = function(name, handler) {
			stream.addEventListener(name, function(event) {
				handler(streamSelf.getTargetContainer(), stream, event);
			});
		};

		this.registerEvent("open", function(container, stream, event) {
			// handleMessage(container, stream, "Stream started!");
		});

		this.registerEvent("message", function(container, stream, event) {
			// handleMessage(container, stream, event.data);
		});

		this.registerEvent("eof", function(container, stream, event) {
			stream.close();
			// handleMessage(container, stream, "Stream finished!");
		});
	}

	function HostIP(c, hostinfo) {
		var domain = hostinfo.domain;
		var port = hostinfo.port;
		var ip = hostinfo.ip;

		var url = hostInfoToURL(hostinfo);
		var stream = new Stream(c, url);

		var stack = new Array();
		stack.push({
			fs : c
		});

		stream.getTargetContainer = function() {
			return stack[stack.length - 1].fs;
		}; // Overriding...

		var isRunning = document.createElement("span");
		(function() { // generate Legend
			var legend = document.createElement("legend");
			legend.setAttribute("class", "host-legend");
			legend.appendChild(document.createTextNode(ip));
			var hr = document.createElement("a");
			hr.setAttribute("href", hostInfoToURL(hostinfo, "/test.txt"));
			hr.setAttribute("target", "_blank");
			hr.appendChild(document.createTextNode("raw"));
			legend.appendChild(hr);
			isRunning.appendChild(document.createTextNode("*"));
			isRunning.style.backgroundColor = '#FF0';
			legend.appendChild(isRunning);
			c.appendChild(legend);
		})();

		stream.registerEvent("open", function(container, stream, event) {
			isRunning.style.backgroundColor = '#F00';
		});
		stream.registerEvent("eof", function(container, stream, event) {
			console.log("ending");
			isRunning.style.backgroundColor = '#0F0';
		});
		stream.registerEvent("enter", function(c, s, e) {
			return;
			var fs = document.createElement("fieldset");
			var legend = document.createElement("legend");
			var legendT = document.createTextNode(e.data);
			legend.appendChild(legendT);
			fs.appendChild(legend);
			c.appendChild(fs);

			stack.push({
				fs : fs,
				leg : legend,
				legT : legendT
			});
		});

		stream.registerEvent("exit", function(c, s, e) {
			return;
			var frame = stack.pop();

			var legT = document.createTextNode(e.data);
			frame.leg.removeChild(frame.legT);
			frame.leg.appendChild(legT);
		});
		(function() {
			function appendX500Name(elem, name, desc) {
				var div = document.createElement("div");
				div.setAttribute("class", "x500name");
				div.appendChild(document.createTextNode(desc));
				for (rdn in name) {
					var span = document.createElement("span");
					span.setAttribute("class", "rdn");
					for (ava in name[rdn]) {
						var avaspan = document.createElement("span");
						avaspan.setAttribute("class", "ava");
						var lookup = dnOIDs[ava];
						if (lookup === undefined) {
							lookup = ava;
						}
						var keySpan = document.createElement("span");
						keySpan.appendChild(generateOIDInfoHref(ava, lookup));

						var valSpan = document.createElement("span");
						valSpan.appendChild(document.createTextNode(name[rdn][ava]));

						avaspan.appendChild(keySpan);
						avaspan.appendChild(document.createTextNode(": "));
						avaspan.appendChild(valSpan);
						span.appendChild(avaspan);
					}
					div.appendChild(span);
				}
				elem.appendChild(div);
			}

			var certificates = document.createElement("div");
			certificates.appendChild(createHeader("Certificates"));
			var certificateLookup = {};
			stream.registerEvent("certificate", function(c, s, e) {
				var certificate = JSON.parse(e.data);
				var certificateElem = document.createElement("div");
				certificateElem.setAttribute("class", "certificate");
				certificateElem.textContent = "#" + certificate.index + " ";

				{ // the ^{pem}-link
					var raw = document.createElement("a");
					raw.appendChild(document.createTextNode("pem"));
					raw.setAttribute("class", "rawcert");
					raw.setAttribute("href", "data:text/plain;base64,"
							+ btoa(certificate.data));
					raw.setAttribute("target", "_blank");
					certificateElem.appendChild(raw);
				}

				appendX500Name(certificateElem, certificate.subject, "Subject: ");
				appendX500Name(certificateElem, certificate.issuer, "Issuer: ");

				certificateLookup[certificate.index] = certificateElem;

				certificates.appendChild(certificateElem);
			});
			stream.registerEvent("certkey", function(c, s, e) {
				var certificate = JSON.parse(e.data);
				var validitySpan = document.createElement("div");
				validitySpan.appendChild(document.createTextNode(certificate.type + ":"
						+ certificate.size));

				certificateLookup[certificate.index].appendChild(validitySpan);
			});
			stream.registerEvent("certvalidity", function(c, s, e) {
				var certificate = JSON.parse(e.data);
				var validitySpan = document.createElement("div");
				validitySpan.appendChild(document.createTextNode(certificate.start
						+ " => " + certificate.end));

				certificateLookup[certificate.index].appendChild(validitySpan);
			});
			c.appendChild(certificates);
		})();
		(function() { // register SSL Feats
			var bugs = document.createElement("div");
			var table = document.createElement("table");
			table.setAttribute("class", "extTable");
			function addElem(name, callback) {
				var tr = document.createElement("tr");
				var td = document.createElement("td");
				td.appendChild(document.createTextNode(name));
				tr.appendChild(td);
				stream.registerEvent(name, function(c, s, e) {
					var r = document.createElement("td");
					r.textContent = callback(JSON.parse(e.data));
					tr.appendChild(r);
				});
				table.appendChild(tr);
			}
			bugs.appendChild(table);
			addElem("renegotiation", function(renego) {
				return renego.secure_renego;
			});
			addElem("heartbeat", function(heartbeat) {
				return heartbeat.heartbeat + ", test results ... beat: "
						+ heartbeat.test.heartbeat + ", bleed: "
						+ heartbeat.test.heartbleed;
			});
			addElem("sni", function(sni) {
				return sni.sni;
			});
			addElem("compression", function(compression) {
				return compression.supported + " test results ... accept: "
						+ compression.accepted;
			});
			c.appendChild(bugs);
		})();
		(function() { // register Cipher preference
			var certificateObservations = document.createElement("div");
			c.appendChild(certificateObservations);

			var cipherPreferenceW = document.createElement("div");
			cipherPreferenceW.appendChild(document
					.createTextNode("Server has cipher preference: "));
			var cipherPreference = document.createElement("span");
			cipherPreference.appendChild(document.createTextNode("unknown"));
			cipherPreferenceW.appendChild(cipherPreference);
			certificateObservations.appendChild(cipherPreferenceW);
			var tab = document.createElement("table");
			tab.setAttribute("class", "cipherTable")
			certificateObservations.appendChild(tab);

			stream.registerEvent("cipherpref", function(c, s, e) {
				var cipherpref = JSON.parse(e.data);
				cipherPreference.textContent = cipherpref.cipherpref;
			});
			stream.registerEvent("cipher", function(c, s, e) {
				var cipher = JSON.parse(e.data);
				var tr = document.createElement("tr");
				if (tab.childNodes.length == 0) {
					var header = document.createElement("tr");
					for ( var key in cipher) {
						var td = document.createElement("th");
						td.appendChild(document.createTextNode(key));
						header.appendChild(td);
					}
					tab.appendChild(header)
				}
				for ( var key in cipher) {
					var td = document.createElement("td");
					td.appendChild(document.createTextNode(cipher[key]));
					tr.appendChild(td);
				}
				tab.appendChild(tr);
			});
		})();
	}

	var container = document.getElementById('output');

	var url = hostInfoToURL({
		domain : domain,
		port : port
	});

	var stream = new Stream(container, url);

	stream.registerEvent("hostip", function(c, s, e) {
		var hostInfo = JSON.parse(e.data);

		var node = document.createElement("fieldset");
		c.appendChild(node);

		var stream = new HostIP(node, hostInfo);
	});

}
