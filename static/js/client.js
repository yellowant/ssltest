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

	function Stream(c, url) {
		this.getTargetContainer = function(){
			return c;
		}

		var stream = new EventSource(url);
		var streamSelf = this;
		this.registerEvent = function(name, handler) {
			stream.addEventListener(name, function (event) {
				handler(streamSelf.getTargetContainer(), stream, event);
			});
		};

		this.registerEvent("open", function (container, stream, event) {
			handleMessage(container, stream, "Stream started!");
		});

		this.registerEvent("message", function (container, stream, event) {
			handleMessage(container, stream, event.data);
		});

		this.registerEvent("eof", function (container, stream, event) {
			stream.close();
			handleMessage(container, stream, "Stream finished!");
		});
	}

	function HostIP(c, hostinfo) {
		var domain = hostinfo.domain;
		var port = hostinfo.port;
		var ip = hostinfo.ip;

		var url = hostInfoToURL( hostinfo );
		var stream = new Stream(c, url);

		var stack = new Array();
		stack.push({fs: c});
		
		stream.getTargetContainer = function(){
			return stack[stack.length-1].fs;
		}; // Overriding...

		stream.registerEvent("enter", function (c, s, e) {
			var fs = document.createElement("fieldset");
			var legend = document.createElement("legend");
			var legendT = document.createTextNode(e.data);
			legend.appendChild(legendT);
			fs.appendChild(legend);
			c.appendChild(fs);

			stack.push( { fs:fs, leg:legend, legT:legendT} );
		});

		stream.registerEvent("exit", function (c, s, e) {
			var frame = stack.pop();

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

		var node = document.createElement("fieldset");
		var legend = document.createElement("legend");
		var legendT = document.createTextNode(hostInfo.ip);
		legend.appendChild(legendT);
		node.appendChild(legend);
		c.appendChild(node);
		
		var stream = new HostIP( node, hostInfo );
	});

}
