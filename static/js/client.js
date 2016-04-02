function abbrevHash(hash) {
	if (hash.length <= 32) {
		return hash;
	}

	return hash.substring(0, 16) + "..." + hash.substring(hash.length - 16);
}

document.addEventListener('DOMContentLoaded', function() {
	var reqform = document.getElementById("reqform");
	reqform.onsubmit = function() {
		events();
		return false;
	};

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
}, false);

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

function errorSign(error){
	var span = document.createElement("span");
	span.setAttribute("title", error);
	span.setAttribute("class", "error-sign");
	span.appendChild(document.createTextNode("\u26A0"));
	return span;
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
		var c2 = document.createElement("span");

		var url = hostInfoToURL(hostinfo);
		var stream = new Stream(c, url);

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

		var certsModule = new (function() {
			var certificates = document.createElement("div");
			certificates.appendChild(createHeader("Certificates"));

			var certificateLookup = {};

			function ref0(hash){
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
				return cert;
			}
			
			this.refData = function(hash, node) {
				var cert = ref0(hash);

				var txt = node;
				if(txt == null) txt = document.createTextNode("");
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
				ref0(hash).addUpdate(function(c) {
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
			};

			this.rateSig = function(hash, elem) {
				ref0(hash).addUpdate(function(c) {
					if (c.key === undefined) {
						return;
					}

					var sig0 = sigOIDs[c.key.sig];
					var sig = sig0.split("WITH");

					elem.setAttribute("stroke-width", rater.widthize(rater.rateSignature(sig[0], sig[1])));
					//elem.setAttribute("title", sig0);
				});
			};

			var appendX500Name = function(div, name) {
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
					value.appendChild(document.createTextNode(" "));
					tr.appendChild(value);

					c.crl[dt.url] = {td: value, i: new StatusIndicator(runner, true)};
					c.tabObj.appendChild(tr);
				});

				stream.registerEvent("crlstatus", function(c, s, e) {
					var dt = JSON.parse(e.data);
					if(dt.result !== undefined) {
						c.crl[dt.url].td.appendChild(document.createTextNode("result: "+ dt.result));
					}
					if(dt.state == "downloading"){
						c.crl[dt.url].i.open();
					}
					if(dt.state == "done"){
						c.crl[dt.url].i.close();
					}
				});

				stream.registerEvent("crldata", function(c, s, e) {
					var dt = JSON.parse(e.data);
					c.crl[dt.url].td.setAttribute("title", dt.size + " bytes, " + dt.entries + " entries, valid " + dt.thisUpdate + " to " + dt.nextUpdate);
				});

				stream.registerEvent("crlValidity", function(c, s, e) {
					var dt = JSON.parse(e.data);
					c.crl[dt.url].td.appendChild(errorSign(dt.status));
				});

				stream.registerEvent("OCSP", function(c, s, e) {
					var dt = JSON.parse(e.data);

					if (c.ocsp === undefined) {
						return;
					}

					c.ocsp.appendChild(document.createTextNode(", result: " + dt.state));
					if(dt.request !== null) {
						c.ocsp.appendChild(createASN1JS("req", dt.request));
					}
					if(dt.response !== null) {
						c.ocsp.appendChild(createASN1JS("resp", dt.response));
					}
				});
			};

			c.appendChild(certificates);
		})();

		var chainModule = new (function() {
			var chains = document.createElement("div");
			var ChainGraphics = function() {
				var width = 800, height = 500;

				var force = d3.layout.force().size([width, height]);

				var svg = null;
				var nodeI = 0;
				var edgeI = 0;
				var nodeIdx = {};
				var nodes = [];
				var edges = [];

				var edgeId = {};

				this.render = function(tgt) {
					svg = d3.select(tgt).append("svg")
						.attr("width", width)
						.attr("height", height);
					svg.append("g").attr("class","links");
					svg.append("svg:defs").selectAll("marker")
						.data(["mark"])
						.enter().append("svg:marker")
						.attr("id", "markerid")
						.attr("viewBox", "0 -5 10 10")
						.attr("refX", 10)
						.attr("refY", 0)
						.attr("markerWidth", 15)
						.attr("markerHeight", 15)
						.attr("orient", "auto")
						.attr("markerUnits", "userSpaceOnUse")
						.append("svg:path")
						.attr("d", "M10,-5L0,0L10,5");
					update();
				};

				var update = function() {
					if(svg==null) return;
					force
						.nodes(nodes)
						.links(edges)
						.linkStrength(0.125)
						.linkDistance(25)
						.charge(-2000)
						.gravity(0.1)
						.start();

					var link = svg.select(".links").selectAll(".link")
						.data(edges);
					link.enter().append("line")
						.attr("marker-start", "url(#markerid)")
						.each(function(d) {
							d.node = this;
							certsModule.rateSig(d.source.name, this);
						});
					link.exit().remove();

					var node = svg.selectAll(".node")
						.data(nodes);
					node.exit().remove();
					var g = node.enter().append("g").attr("class", "node");

					g.append("circle")
						.attr("r", 30)
						.each(function(d) {
							d.node = this;
							certsModule.setKeyClass(d.name,this,"cert-trust")
						});
//						.each(function(d){d.node = this;});

					g.call(force.drag);
					g.append("a").append("text")
						.each(function(d) {
							var a = certsModule.reference(d.name);
							var t = a.firstChild;
							a.removeChild(t);

							this.appendChild(t);
							this.parentNode.setAttributeNS("http://www.w3.org/1999/xlink", "href", a.getAttribute("href"));
						});

					force.on("tick", function() {
						link
							.each(function(d) {
								function sq(v) {
									return v*v;
								};
								d.len = Math.sqrt(sq(d.source.x-d.target.x)+sq(d.source.y-d.target.y));
							})
							.attr("x1", function(d) { return d.source.x + (d.target.x - d.source.x)*(45/d.len); })
							.attr("y1", function(d) { return d.source.y + (d.target.y - d.source.y)*(45/d.len); })
							.attr("x2", function(d) { return d.target.x - (d.target.x - d.source.x)*(30/d.len); })
							.attr("y2", function(d) { return d.target.y - (d.target.y - d.source.y)*(30/d.len); });

						node.attr("transform", function(d) { return "translate("+d.x+","+d.y+")"; });
					});
				};

				function getNode(id){
					if(nodeIdx[id] === undefined) {
						var nd = {"name": id, "dgr": 0, "out":{}};
						nodeIdx[id] = nodeI;
						nodes[nodeI++] = nd;
					}

					return nodeIdx[id];
				}

				function add(src, dest, type){
					var k = src+"<->"+dest;
					var n1 = nodes[getNode(src)];
					if(edgeId[k] === undefined) {
						edgeId[k] = edgeI;
						var e = {"source":getNode(src), "target":getNode(dest), "type":{}};
						n1.out[n1.dgr++] = e;
						edges[edgeI++] = e;
						e.type[type]="y";
					} else {
						var e = edges[edgeId[k]];
						n1.out[n1.dgr++] = e;
						e.type[type] = "y";
						var w1 = "";
						for(i in e.type){
							w1 += i+", "
						}
						e.node.setAttribute("title", w1);
					}

					update();
					var e = edges[edgeId[k]];
					e.node.setAttribute("title", (function(d){var w1 = ""; for(i in d.type){w1 += i+", "};console.log(d.type);return w1;})(e));
					e.node.setAttribute("class", (function(d){var w1 = "link"; for(i in d.type){w1 += " "+i};return w1;})(e));
				}
				this.addEdge = add;
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

				graphics.render(chains);
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
				//chainObjs[chain.chainId].graphics.add(chain);
			});

			stream.registerEvent("trustEdge", function(c, s, e) {
				var chain = JSON.parse(e.data);

				chainObjs[chain.chainId].graphics.addEdge(chain.from, chain.to, chain.type);
			});

			chains.appendChild(createHeader("Chains"));
			c.appendChild(chains);
		})();

		var sslExtModule = new (function() { // register SSL Feats
			var bugs = document.createElement("div");

			var table = document.createElement("table");
			table.setAttribute("class", "extTable");

			bugs.appendChild(table);

			stream.registerEvent("extensions", function(c, s, e) {
				var ext = JSON.parse(e.data);
				for(extId in ext){
					var tr = document.createElement("tr");
					var td = document.createElement("td");
					if(TLSExts[extId] !== undefined){
						var span = document.createElement("span");
						span.appendChild(document.createTextNode(TLSExts[extId]));
						span.setAttribute("title", "0x"+(extId|0).toString(16));
						td.appendChild(span);
					}else{
						td.appendChild(document.createTextNode(extId));
					}
					tr.appendChild(td);
					td = document.createElement("td");
					if(ext[extId].illegal == "yes"){
						td.appendChild(errorSign("Server must not send this extension"));
					}
					if(ext[extId].sent == "no"){
						td.appendChild(document.createTextNode(" not sent by server"));
					}
					tr.appendChild(td);
					var td = document.createElement("td");
					if(TLSExts[extId] == "heartbeat"){
						td.appendChild(document.createTextNode(" heartbeat: "+ext[extId].tested.heartbeat+" heartbleed: "+ext[extId].tested.heartbleed));
					}
					tr.appendChild(td);

					table.appendChild(tr);
				}
				// TODO test compression?
				/*if(ext.result == "yes"){
					r.appendChild(errorSign("Server sent illegal extensions"));
					r.appendChild(document.createTextNode("yes"));
				}else{
					r.textContent = "none";
				}*/
			});
			stream.registerEvent("compression", function(c, s, e) {
				var ext = JSON.parse(e.data);
				var tr = document.createElement("tr");
				var td = document.createElement("td");
				if(ext.accepted=="no"){
					td.appendChild(document.createTextNode("compression: no"));
				}else{
					td.appendChild(document.createTextNode("compression: yes"));
					td.appendChild(errorSign("TLS compression can make you vulnerable to different attacks."));
				}
				tr.appendChild(td);
				table.appendChild(tr);
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
		stream.registerEvent("error", function(c0, s, e) {
			var msg = JSON.parse(e.data);
			if(msg.message == "connection failed"){
				var j = 0;
				var toRemove = [];
				for(var i = 0; i < c.childNodes.length; i++){
					if(c.childNodes[i].tagName == "DIV"){
						toRemove[j++] = c.childNodes[i];
					}
				}
				console.log(toRemove);
				for(i in toRemove){
					c.removeChild(toRemove[i]);
				}
				c.appendChild(document.createTextNode("connection failed, no TLS could be reached"));
			}
		});
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
