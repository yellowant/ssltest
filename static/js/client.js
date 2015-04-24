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

	function hostInfoToURL(hostinfo) {
		return hostinfo.ip ? '/test.event?domain='
				+ encodeURIComponent(hostinfo.domain) + '&ip='
				+ encodeURIComponent(hostinfo.ip) + '&port='
				+ encodeURIComponent(hostinfo.port) : '/test.event?domain='
				+ encodeURIComponent(hostinfo.domain) + '&port='
				+ encodeURIComponent(hostinfo.port);
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

		var legend = document.createElement("legend");
		legend.appendChild(document.createTextNode(ip));
		var isRunning = document.createElement("span");
		isRunning.appendChild(document.createTextNode("?"));
		isRunning.style.backgroundColor = '#FF0';
		legend.appendChild(isRunning);
		c.appendChild(legend);

		stream.registerEvent("open", function(container, stream, event) {
			isRunning.style.backgroundColor = '#F00';
		});
		stream.registerEvent("eof", function(container, stream, event) {
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
		{
			var certificates = document.createElement("div");
			stream.registerEvent("certificate", function(c, s, e) {
				var certificate = JSON.parse(e.data);
				var certificateElem = document.createElement("div");
				certificateElem.textContent = certificate.index + "-> "
						+ certificate.subject;
				certificates.appendChild(certificateElem);
			});
			c.appendChild(certificates);
		}
		{
      var bugs = document.createElement("div");
      var table = document.createElement("table");
      table.setAttribute("class", "extTable");
      function addElem(name, callback){
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
      addElem("renegotiation", function(renego){return renego.secure_renego;});
      addElem("heartbeat", function(heartbeat){return heartbeat.heartbeat+", test results ... beat: "+heartbeat.test.heartbeat+", bleed: "+heartbeat.test.heartbleed;});
      addElem("sni", function(sni){return sni.sni;});
      addElem("compression", function(compression){return compression.supported+" test results ... accept: "+compression.accepted;});
			c.appendChild(bugs);
		}
		{
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
		}
	}
	;

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
