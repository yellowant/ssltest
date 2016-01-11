function abbrevHash(hash) {
	if (hash.length <= 32) {
		return hash;
	}

	return hash.substring(0, 16) + "..." + hash.substring(hash.length - 16);
}

function onLoadHook() {
	if (window.location.hash !== undefined) {
		var hash = window.location.hash;

		if (hash.substring(0, 3) === "#d=") {
			var spec = hash.substring(3, hash.length);
			var parts = spec.split(":", 2);

			document.getElementById("domain").value = parts[0];

			if (parts[1] !== undefined) {
				document.getElementById("port").value = parts[1];
			}

			events();
		}
	}
}

function createASN1JS(name, data) {
	var asn1js = document.createElement("a");

	asn1js.appendChild(document.createTextNode(name));
	asn1js.setAttribute("class", "rawcert");
	asn1js.setAttribute("href", "http://lapo.it/asn1js/#" + data);
	asn1js.setAttribute("target", "_blank");

	return asn1js;
}

function generateOIDInfoHref(oid, dict) {
	var content = dict[oid];

	if (content === undefined) {
		content = oid;
	}

	var a = document.createElement("a");
	a.appendChild(document.createTextNode(content));
	a.setAttribute("href", "http://www.oid-info.com/cgi-bin/display?tree=" + encodeURIComponent(oid));
	a.setAttribute("title", oid);
	a.setAttribute("target", "_blank");
	return a;
}

function createHeader(content) {
	var h = document.createElement("h1");
	h.appendChild(document.createTextNode(content));
	return h;
}

function hrefjump(e) {
	var body = document.getElementsByTagName("body")[0];
	var target = document.getElementById(this.getAttribute("href").substring(1));
	var left = 0;
	var top = 0;

	var watch = target;

	while (watch !== body) {
		left += watch.offsetLeft;
		top += watch.offsetTop;
		watch = watch.offsetParent;
	}

	window.scroll(left, top - 55)
	return false;
}

function newAnchor(name, anchor) {
	var a = document.createElement("a");
	a.appendChild(document.createTextNode(name));
	a.setAttribute("href", anchor);
	a.onclick = hrefjump;
	return a;
}

var idcounter = 0;

function TrustDisplay() {
	var trusts = {};
	var trustGroup = {};

	var elem = document.createElement("div");
	elem.setAttribute("class", "enumeration");

	this.render = function() {
		return elem;
	};

	this.add = function(trust) {
		var str = trust.split("_");

		if (trustGroup[str[0]] === undefined) {
			var span = document.createElement("span");
			span.appendChild(document.createTextNode(str[0]));
			span.setAttribute("class", "trust trust-" + str[0]);
			elem.appendChild(span);
			span.setAttribute("title", trust);

			trustGroup[str[0]] = {
				span : span,
				title : trust
			};
		} else {
			trustGroup[str[0]].title += ", " + trust;
			trustGroup[str[0]].span.setAttribute("title", trustGroup[str[0]].title);
		}

		trusts[trust] = "yes";
	};
}

function events() {
	var overview = new (function() {
		var outline = document.getElementById("outline");
		var ui = document.createElement("ul");
		outline.appendChild(ui);
		this.addTest = function(hostname, port, ip, anchor) {
			var li = document.createElement("li");
			var span = document.createElement("span");
			var name = newAnchor(hostname + ":" + port, anchor);

			name.appendChild(document.createElement("br"));
			name.appendChild(document.createTextNode("(" + ip + ")"));
			li.appendChild(name);
			li.appendChild(span);
			ui.appendChild(li);

			return span;
		};
	})();

	document.getElementById('domain').blur();
	document.getElementById('port').blur();

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
			base = "/server.event"
		}

		return base +
			'?domain=' + encodeURIComponent(hostinfo.domain) +
			(hostinfo.ip ? '&ip=' + encodeURIComponent(hostinfo.ip) : '') +
			'&port=' + encodeURIComponent(hostinfo.port);
	}

	function Stream(c, url) {
		this.getTargetContainer = function() {
			return c;
		}

		var stream = new EventSource(url);
		var streamSelf = this;
		var registerEvent = function(name, handler) {
			stream.addEventListener(name, function(event) {
				handler(streamSelf.getTargetContainer(), stream, event);
			});
		};
		this.registerEvent = registerEvent;

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

		this.addStatusIndicator = function(isRunning){
			var i = new StatusIndicator(isRunning);

			registerEvent("open", function(container, stream, event) {
				i.open();
			});

			registerEvent("eof", function(container, stream, event) {
				i.close();
			});
		}
	}

	function StatusIndicator(isRunning, hide){
		var c = document.createTextNode("*");
		isRunning.appendChild(c);
		isRunning.style.backgroundColor = '#FF0';
		this.open = function() {
			isRunning.style.backgroundColor = '#F00';
		};

		this.close = function () {
			if(hide !== undefined){
				isRunning.removeChild(c);
			}
			isRunning.style.backgroundColor = '#0F0';
		};
	}

	function HostIP(c, hostinfo, idbase) {
		var domain = hostinfo.domain;
		var port = hostinfo.port;
		var ip = hostinfo.ip;
		c.setAttribute("id", idbase + "-main");
		var isRunning2 = overview.addTest(domain, port, ip, "#" + idbase + "-main");

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
			hr.setAttribute("href", hostInfoToURL(hostinfo, "/server.txt"));
			hr.setAttribute("target", "_blank");
			hr.appendChild(document.createTextNode("raw"));
			legend.appendChild(hr);
			stream.addStatusIndicator(isRunning);
			legend.appendChild(isRunning);
			c.appendChild(legend);
		})();
		stream.addStatusIndicator(isRunning2);

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

		var certsModule = new (function() {
			var certificates = document.createElement("div");
			certificates.appendChild(createHeader("Certificates"));

			var certificateLookup = {};

			this.refData = function(hash) {
				var cert = certificateLookup[hash];

				if (cert === undefined) {
					cert = {
						updates : [],
						ctr : 0,
						hash : hash
					};

					var str = new Stream(cert, "/cert.event?fp=" + hash);
					cert.stream = str;
					cert.updated = function() {
						for (var i = 0; i < cert.ctr; i++) {
							cert.updates[i](cert);
						}
					}

					cert.addUpdate = function(func) {
						func(cert);
						cert.updates[cert.ctr++] = func;
					}

					certificateLookup[hash] = cert;
					registerOn(str);
				}

				var txt = document.createTextNode("");
				cert.addUpdate(function(cert) {
					var name = abbrevHash(hash);
					if (cert !== undefined && cert.dn !== undefined) {
						name = cert.dn["2.5.4.3"]; // "CN"
						if (name == undefined) {
							name = cert.dn["2.5.4.10"]; // "O"
						}
					}
					txt.data = name;
				});

				return [ txt, "#" + idbase + "cert-" + hash ];
			};

			var refData = this.refData;
			this.reference = function(hash) {
				var ref = refData(hash);

				var a = document.createElement("a");
				a.appendChild(ref[0]);
				a.setAttribute("href", ref[1]);
				a.onclick = hrefjump;
				return a;
			}

			this.setKeyClass = function(hash, elem, clazz) {
				certificateLookup[hash].addUpdate(function(c) {
					if (c.key === undefined) {
						return;
					}

					var type = c.key.type;
					var size = c.key.size;

					elem.setAttribute("data-type", type);
					elem.setAttribute("data-value", size);
					elem.setAttribute("title", type + ":" + size);

					calculateSymmeq(type, size, elem, clazz);
				});
			}

			this.rateSig = function(hash, elem) {
				certificateLookup[hash].addUpdate(function(c) {
					if (c.key === undefined) {
						return;
					}

					var sig0 = sigOIDs[c.key.sig];
					var sig = sig0.split("WITH");

					elem.style.stroke = rater.colorizeFG(rater.rateSignature(sig[0], sig[1]));
					elem.setAttribute("title", sig0);
				});
			}

			function appendX500Name(div, name) {
				var res = {};

				div.setAttribute("class", "x500name");

				for (rdn in name) {
					var span = document.createElement("span");
					span.setAttribute("class", "rdn");

					for (ava in name[rdn]) {
						res[ava] = name[rdn][ava];

						var avaspan = document.createElement("span");
						avaspan.setAttribute("class", "ava");

						var keySpan = document.createElement("span");
						keySpan.appendChild(generateOIDInfoHref(ava, dnOIDs));

						var valSpan = document.createElement("span");
						var val = name[rdn][ava];
						if (val === null) {
							valSpan.setAttribute("class", "unknownVal");
							valSpan.appendChild(document.createTextNode("<unknown>"));
						} else {
							valSpan.appendChild(document.createTextNode(val));
						}

						avaspan.appendChild(keySpan);
						avaspan.appendChild(document.createTextNode(": "));
						avaspan.appendChild(valSpan);
						span.appendChild(avaspan);
					}

					div.appendChild(span);
				}

				return res;
			}

			var registerOn = function(stream) {
				stream.registerEvent("certificate", function(c, s, e) {
					var certificate = JSON.parse(e.data);
					var certificateElem = document.createElement("div");

					var certTable = document.createElement("table");
					certTable.setAttribute("class", "certTable")

					certificateElem.appendChild(certTable);

					var keys = {
						id : "id",
						subj : "Subject",
						issuer : "Issuer",
						key : "Key",
						from : "Valid From",
						to : "Valid To",
						sig : "Signature"
					};

					var optKeys = {
						sans : "SubjectAltNames"
					}

					var tds = {};

					for ( var i in keys) {
						var tr = document.createElement("tr");
						var k = document.createElement("td");
						k.appendChild(document.createTextNode(keys[i]))
						tr.appendChild(k);

						var v = document.createElement("td");
						tr.appendChild(v);

						certTable.appendChild(tr);

						tds[i] = v;
					}

					var getTD = function(name){
						if(tds[name] === undefined){
							var tr = document.createElement("tr");
							var k = document.createElement("td");
							k.appendChild(document.createTextNode(optKeys[name]))
							tr.appendChild(k);

							var v = document.createElement("td");
							tr.appendChild(v);

							certTable.appendChild(tr);

							tds[name] = v;
						}

						return tds[name];
					}

					certificateElem.setAttribute("id", idbase + "cert-" + c.hash);
					certificateElem.setAttribute("class", "certificate");

					var idspan = document.createElement("span");
					idspan.appendChild(document.createTextNode(abbrevHash(c.hash)))
					idspan.setAttribute("title", c.hash);
					tds.id.appendChild(idspan);

					{ // the ^{pem}-link
						var raw = document.createElement("a");
						raw.appendChild(document.createTextNode("pem"));
						raw.setAttribute("class", "rawcert");
						raw.setAttribute("href", "data:text/plain;base64," + btoa(certificate.data));
						raw.setAttribute("target", "_blank");
						tds.id.appendChild(raw);

						tds.id.appendChild(createASN1JS("asn1.js", certificate.data));

						var raw = document.createElement("a");
						raw.appendChild(document.createTextNode("raw"));
						raw.setAttribute("class", "rawcert");
						raw.setAttribute("href", "/cert.txt?fp=" + c.hash);
						raw.setAttribute("target", "_blank");
						tds.id.appendChild(raw);
					}

					var isRunning = document.createElement("span");
					stream.addStatusIndicator(isRunning);
					tds.id.appendChild(isRunning);

					var name = appendX500Name(tds.subj, certificate.subject);

					appendX500Name(tds.issuer, certificate.issuer);

					c.elem = certificateElem;
					c.dn = name;
					c.tab = tds;
					c.tabObj = certTable;
					c.data = certificate;
					c.getTD = getTD;
					c.crl = {};

					certificates.appendChild(certificateElem);

					c.updated();
				});

				stream.registerEvent("certSANs", function(c, s, e) {
					var certificate = JSON.parse(e.data);
					var validitySpan = document.createElement("div");

					if (certificate.value === "undefined") {
						return;
					}

					for (var san in certificate.value) {
						var val = certificate.value[san];
						var div = document.createElement("div");

						if (val.type == 2) {
							div.appendChild(document.createTextNode("DNS: "));
							div.appendChild(document.createTextNode(val.value));
						} else if (val.type == 4) {
							div.appendChild(document.createTextNode("DirectoryName: "));
							appendX500Name(div, val.value);
						}

						c.getTD("sans").appendChild(div);
					}

					c.updated();
				});

				stream.registerEvent("certkey", function(c, s, e) {
					var certificate = JSON.parse(e.data);
					var validitySpan = document.createElement("div");
					c.tab.key.appendChild(document.createTextNode(certificate.type + ":" + certificate.size + " (" + certificate.pkhash.substring(0, 8) + ")"));
					c.tab.sig.appendChild(generateOIDInfoHref(certificate.sig, sigOIDs));
					c.key = certificate;
					c.updated();
				});

				stream.registerEvent("certvalidity", function(c, s, e) {
					var certificate = JSON.parse(e.data);
					c.tab.from.appendChild(document.createTextNode(certificate.start));
					c.tab.to.appendChild(document.createTextNode(certificate.end));
					c.updated();
				});

				stream.registerEvent("authorityInfoAccess", function(c, s, e) {
					var dt = JSON.parse(e.data);

					var tr = document.createElement("tr");

					var key = document.createElement("td");
					key.appendChild(document.createTextNode("Autority Info Access"));
					tr.appendChild(key);

					var value = document.createElement("td");
					value.appendChild(generateOIDInfoHref(dt.type, AIAOIDs));
					value.appendChild(document.createTextNode(": "));
					value.appendChild(newAnchor(dt.loc, dt.loc));
					tr.appendChild(value);

					c.ocsp = value;
					c.tabObj.appendChild(tr);
				});

				stream.registerEvent("crl", function(c, s, e) {
					var dt = JSON.parse(e.data);

					var tr = document.createElement("tr");

					var key = document.createElement("td");
					key.appendChild(document.createTextNode("Certificate Revocation List"));
					tr.appendChild(key);

					var value = document.createElement("td");
					value.appendChild(newAnchor(dt.url, dt.url));
					var runner = document.createElement("span");
					value.appendChild(runner);
					tr.appendChild(value);

					c.crl[dt.url] = {td: value, i: new StatusIndicator(runner, true)};
					c.tabObj.appendChild(tr);
				});

				stream.registerEvent("crlstatus", function(c, s, e) {
					var dt = JSON.parse(e.data);
					if(dt.result !== undefined) {
						c.crl[dt.url].td.appendChild(document.createTextNode(": " + dt.result));
					}
					if(dt.state == "downloading"){
						c.crl[dt.url].i.open();
					}
					if(dt.state == "done"){
						c.crl[dt.url].i.close();
					}
				});

				stream.registerEvent("OCSP", function(c, s, e) {
					var dt = JSON.parse(e.data);

					if (c.ocsp === undefined) {
						return;
					}

					c.ocsp.appendChild(document.createTextNode(", result: " + dt.state));
					c.ocsp.appendChild(createASN1JS("req", dt.request));
					c.ocsp.appendChild(createASN1JS("resp", dt.response));
				});
			};

			c.appendChild(certificates);
		})();

		var chainModule = new (function() {
			var chains = document.createElement("div");
			var ChainGraphics = function() {
				var trustGraph = {};
				var first = "";
				var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
				svg.style.width = "100%";

				this.render = function() {
					return svg;
				};

				var update = function() {
					svg.innerHTML = "";
					var lines = document.createElementNS("http://www.w3.org/2000/svg", "g");
					svg.appendChild(lines);

					var order = {};
					order[first] = 0;
					var found = {};
					found[first] = 'y';
					var set = {};
					set[first] = 'y';

					var ctr = 1;
					var len = 1;
					var maxheight = 1;
					var positions = {};

					while (len > 0) {
						var next = {};
						len = 0;

						var height = 0;

						for (key in set) {
							var x = 115 + (ctr - 1) * 270;
							var y = 63 + (height++) * 170;

							var rect = document.createElementNS("http://www.w3.org/2000/svg", "ellipse");
							rect.setAttribute("cx", x);
							rect.setAttribute("cy", y);
							rect.setAttribute("rx", "110");
							rect.setAttribute("ry", "40");
							rect.setAttribute("style", "stroke: black; stroke-width: 3px");
							certsModule.setKeyClass(key, rect, "cert-trust");
							svg.appendChild(rect);

							var ref = certsModule.refData(key);

							var anc = document.createElementNS("http://www.w3.org/2000/svg", "a");
							anc.setAttributeNS("http://www.w3.org/1999/xlink", "href", ref[1]);
							anc.onclick = hrefjump;

							var text = document.createElementNS("http://www.w3.org/2000/svg", "text");
							text.setAttribute("x", x);
							text.setAttribute("y", y);
							text.setAttribute("style", "fill: black; text-anchor: middle; dominant-baseline: middle");
							text.appendChild(ref[0]);
							anc.appendChild(text);
							svg.appendChild(anc);

							positions[key] = [ x, y ];

							for (target in trustGraph[key]) {
								if (found[target] !== undefined || target === "undefined") {
									continue;
								}

								found[target] = 'y';
								next[target] = 'y';
								order[target] = ctr;

								len++;
							}
						}

						maxheight = Math.max(maxheight, height);
						set = next;
						ctr++;
					}

					svg.style.height = maxheight * 170 + "px";

					for (key in trustGraph) {
						for (i in trustGraph[key]) {
							if (i === "undefined") {
								continue;
							}

							var line = document.createElementNS("http://www.w3.org/2000/svg", "line");
							line.setAttribute("x1", positions[key][0]);
							line.setAttribute("y1", positions[key][1]);
							line.setAttribute("x2", positions[i][0]);
							line.setAttribute("y2", positions[i][1]);
							line.setAttribute("style", "stroke-width:2px");
							certsModule.rateSig(key, line);
							lines.appendChild(line);
						}
					}
				};

				this.add = function(chain) {
					first = chain.certs[0];

					for ( var i in chain.certs) {
						var cert = chain.certs[i];

						if (trustGraph[cert] === undefined) {
							trustGraph[cert] = {};
						}

						(trustGraph[cert])[chain.certs[(i | 0) + 1]] = 'y';
					}

					update();
				};
			};

			var chainObjs = {};

			stream.registerEvent("chain", function(c, s, e) {
				var chain = JSON.parse(e.data);
				var chainElem = document.createElement("div");

				for ( var i in chain.content) {
					chainElem.appendChild(certsModule.reference(chain.content[i]));
					chainElem.appendChild(document.createTextNode(", "));
				}

				var graphics = new ChainGraphics();
				chainObjs[chain.id] = {
					elem : chainElem,
					graphics : graphics
				};

				chains.appendChild(graphics.render());
				chains.appendChild(chainElem);
			});

			stream.registerEvent("trustChain", function(c, s, e) {
				var chain = JSON.parse(e.data);

				var trustChain = document.createElement("div");
				trustChain.setAttribute("class", "trust-chain");

				var stores = new TrustDisplay();
				for ( var i in chain.stores) {
					stores.add(chain.stores[i]);
				}

				var certs = document.createElement("div");
				certs.setAttribute("class", "enumeration");

				for ( var i in chain.certs) {
					certs.appendChild(certsModule.reference(chain.certs[i]));
				}

				trustChain.appendChild(certs);
				trustChain.appendChild(stores.render());

				chainObjs[chain.chainId].elem.appendChild(trustChain);
				chainObjs[chain.chainId].graphics.add(chain);
			});

			chains.appendChild(createHeader("Chains"));
			c.appendChild(chains);
		})();

		var sslExtModule = new (function() { // register SSL Feats
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
				return heartbeat.heartbeat + ", test results ... beat: " + heartbeat.test.heartbeat + ", bleed: " + heartbeat.test.heartbleed;
			});
			addElem("sni", function(sni) {
				return sni.sni;
			});
			addElem("compression", function(compression) {
				return compression.supported + " test results ... accept: " + compression.accepted;
			});

			c.appendChild(bugs);
		})();

		(function() { // register Cipher preference
			var certificateObservations = document.createElement("div");
			c.appendChild(certificateObservations);

			var cipherPreferenceW = document.createElement("div");
			cipherPreferenceW.appendChild(document.createTextNode("Server has cipher preference: "));

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
				tr.setAttribute("id", idbase + "cipher-" + cipher.cipherid);

				if (tab.childNodes.length == 0) {
					var header = document.createElement("tr");

					for ( var key in cipher) {
						var td = document.createElement("th");
						td.appendChild(document.createTextNode(key));
						header.appendChild(td);
					}

					tab.appendChild(header)
				}

				if (cipher.encbsize === 0) {
					cipher.encbsize = "Stream";
					cipher.mode = "Stream";
				}

				for ( var key in cipher) {
					var td = document.createElement("td");
					td.setAttribute("data-value", key === "kexsize" ? cipher[key].size : cipher[key]);

					var sfx = "size";
					isEnc = "enc" === key.substring(0, 3) ? 1 : 0;

					if (key.indexOf(sfx, key.length - sfx.length) !== -1) {
						td.setAttribute("data-type", cipher[key.substring(0, key.length - sfx.length - isEnc) + "type"]);
					}

					td.setAttribute("class", "cipher-" + key);

					if (key === "kexsize" || key == "authsize") {
						var sizeval = key === "kexsize" ? cipher[key].size : cipher[key];

						calculateSymmeq(cipher[key.substring(0, key.length - 4) + "type"], sizeval, td, "cipher-" + key);
					}

					if (key === "kexsize") {
						td.appendChild(document.createTextNode(cipher[key].size));

						if (cipher[key].weak !== undefined) {
							var e = document.createElement("sup")
							e.appendChild(document.createTextNode("w"));
							td.appendChild(e);
						}

						if (cipher[key].name !== undefined) {
							var e = document.createElement("sup")
							e.setAttribute("title", cipher[key].name);
							e.appendChild(document.createTextNode("k"));
							td.appendChild(e);
						}

						if (cipher[key].safeprime !== undefined) {
							var e = document.createElement("sup")
							e.appendChild(document.createTextNode("s"));
							td.appendChild(e);
						}

						if (cipher[key].prime !== undefined) {
							var e = document.createElement("sup")
							e.appendChild(document.createTextNode("p"));
							td.appendChild(e);
						}
					} else {
						td.appendChild(document.createTextNode(cipher[key]));
					}

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

		var stream = new HostIP(node, hostInfo, "obj-" + (idcounter++) + "-");
	});

	stream.registerEvent("streamID", function(c, s, e) {
		var hostInfo = JSON.parse(e.data);

		window.location.hash = "#d=" + hostInfo.host + ":" + hostInfo.proto + "-" + hostInfo.port;
	});
}
