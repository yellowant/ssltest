function events(){
	var domain = document.getElementById('domain').value;
	var port = document.getElementById('port').value;

	if(port.trim() == "") {
		port = 443;
	}

	var iplist = new Array();

	var handleMessage = function (container, stream, msg) {
		//var message = JSON.parse(e.data);
		var text = document.createTextNode(msg);
		var node = document.createElement("div");
		node.appendChild(text);
		container.appendChild(node);
	};

	var handleError = function (container, stream, msg) {
		stream.close();
		handleMessage(container, stream, "error");
	};

	function hostInfoToURL(hostinfo) {
		return hostinfo.ip ?
			'/test.event?domain='+encodeURIComponent(hostinfo.domain)+
			'&ip='+encodeURIComponent(hostinfo.ip)+
			'&port='+encodeURIComponent(hostinfo.port)
			:
			'/test.event?domain='+encodeURIComponent(hostinfo.domain)+
			'&port='+encodeURIComponent(hostinfo.port)
			;
	}

	function Stream(_container, _url) {
		var c = _container;
		var url = _url;

		var stream = new EventSource(url);

		function registerEvent(name, handler) {
			stream.addEventListener(name, function (event) {
				handler(container, stream, event);
			});
		};

		registerEvent("open", function (container, stream, event) {
			handleMessage(container, stream, "Stream started!");
		});

		registerEvent("message", function (container, stream, event) {
			handleMessage(container, stream, event.data);
		});

		registerEvent("eof", function (container, stream, event) {
			stream.close();
			handleMessage(container, stream, "Stream finished!");
		});
	}

	function HostIP(_container, _hostinfo) {
		var c = _container;

		var domain = _hostinfo.domain;
		var port = _hostinfo.port;
		var ip = _hostinfo.ip;

		var url = hostInfoToURL( hostinfo );
		var stream = new Stream(c, url);

		var stack = new Array();
		stack.push({fs: current});

		stream.registerEvent("enter", function (c, s, e) {
			var fs = document.createElement("fieldset");
			var legend = document.createElement("legend");
			var legendT = document.createTextNode(e.data);
			legend.appendChild(legendT);
			fs.appendChild(legend);
			current.appendChild(fs);

			stack.push( { fs:fs, leg:legend, legT:legendT} );
			current = fs;
		});

		stream.registerEvent("exit", function (c, s, e) {
			var frame = stack.pop();
			current = stack[stack.length-1].fs;

			var legT = document.createTextNode(e.data);
			frame.leg.removeChild(frame.legT);
			frame.leg.appendChild(legT);
		});
	};

	var container = document.getElementById('output');

	var url = hostInfoToURL( { domain: domain, port: port } );

	var stream = new Stream(container, url);

	stream.registerEvent("hostip", function (c, s, e) {
		var hostInfo = JSON.parse(e.data);

		var text = document.createTextNode(e.data);
		var node = document.createElement("div");
		node.appendChild(text);
		c.appendChild(node);

		var stream = new HostIP( node, hostInfo );
	});

}
