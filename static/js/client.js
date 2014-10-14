function events(){
	var domain = document.getElementById('domain').value;
	var port = document.getElementById('port').value;

	var url = '/test.event?domain='+encodeURIComponent(domain)+'&port='+encodeURIComponent(port);

	var jsonStream = new EventSource(url);

	jsonStream.onmessage = function (e) {
		//var message = JSON.parse(e.data);
		var text = document.createTextNode(e.data);
		var ele = document.createElement("div");
		ele.appendChild(text)
		current.appendChild(ele);
	};

	jsonStream.addEventListener("end", function (e) {
		jsonStream.close();jsonStream.onmessage({data:"finished"});
	});

	var stack = new Array();
	var current = document.getElementById('output'); stack.push({fs: current});

	jsonStream.addEventListener("enter", function (e) {
		var fs = document.createElement("fieldset");
		var legend = document.createElement("legend");
		var legendT = document.createTextNode(e.data);
		legend.appendChild(legendT); fs.appendChild(legend);current.appendChild(fs);
		stack.push({fs:fs,leg:legend, legT: legendT}); current = fs;
	});

	jsonStream.addEventListener("exit", function (e) {
		var frame = stack.pop(); current = stack[stack.length-1].fs;
		var legT = document.createTextNode(e.data);
		frame.leg.removeChild(frame.legT);
		frame.leg.appendChild(legT);
	});

	jsonStream.onerror = function (){
		jsonStream.close();
		jsonStream.onmessage({data:"error"});
	}
}
