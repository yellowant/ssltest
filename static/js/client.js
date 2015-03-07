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

	var container = document.getElementById('output');

	var url = '/test.event?domain='+encodeURIComponent(domain)+'&port='+encodeURIComponent(port);

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

	function HostIP(_container, _domain, _port, _ip) {
		var domain = _domain;
		var port = _port;
		var ip = _ip;
		var c = _container;

		var url = '/test.event?domain='+encodeURIComponent(domain)+'&ip='+encodeURIComponent(ip)+'&port='+encodeURIComponent(port);
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

		stream.registerEvent("exit", function (e) {
			var frame = stack.pop();
			current = stack[stack.length-1].fs;

			var legT = document.createTextNode(e.data);
			frame.leg.removeChild(frame.legT);
			frame.leg.appendChild(legT);
		});
	};

	var stream = new Stream(container, url);

}
