function calculateSymmeq(type, sizeval, elem, clazz){
	var sizeclass = "unknown";
	if ((type === "ECDSA")
			|| (type === "ECDH")) {
		sizeval /= 2;
	} else if ((type === "RSA")
			|| (type === "DSA")
			|| (type === "DH")) {
		sizeval = 1.1875 * Math.sqrt(sizeval) + 4.45 * Math.pow(sizeval, 1 / 3);
	} else {
		sizeval = -1;
	}

	if (sizeval === 0) {
		sizeclass = "none";
	} else if (sizeval >= 256) {
		sizeclass = "256";
	} else if (sizeval >= 224) {
		sizeclass = "224";
	} else if (sizeval >= 192) {
		sizeclass = "192";
	} else if (sizeval >= 160) {
		sizeclass = "160";
	} else if (sizeval >= 128) {
		sizeclass = "128";
	} else if (sizeval >= 112) {
		sizeclass = "112";
	} else if (sizeval >= 96) {
		sizeclass = "96";
	} else if (sizeval >= 80) {
		sizeclass = "80";
	} else if (sizeval >= 64) {
		sizeclass = "64";
	} else if (sizeval >= 40) {
		sizeclass = "40";
	} else if (sizeval > 0) {
		sizeclass = "40less";
	}
	
	elem.setAttribute("class", clazz + " symmeq-"
			+ sizeclass);
}


function Rater() {
	var colorsbg = [ "#ff6666", "#ff8888", "#ffaaaa", "#ffcccc", "#ffdddd",
			"#ffeedd", "#ffffdd", "#f7ffdd", "#eeffdd", "#ddffdd", "#ccffcc" ];
	var colorsfg = [ "#ee2222", "#dd3333", "#dd5522", "#dd8822", "#ddaa00",
			"#eedd00", "#aadd00", "#66cc00", "#44aa00", "#228800", "#007700" ];
	this.generateText = function(){
		var root = document.createElement("div");
		for (var i in colorsbg) {
			var span = document.createElement("dav");
			span.setAttribute("style", "background-color: " + colorsbg[i]);
			span.style.width="100px";
			span.style.height="100px";
			span.appendChild(document.createTextNode("a"));
			root.appendChild(span);
		}
		for (var i in colorsfg) {
			var span = document.createElement("dav");
			span.appendChild(document.createTextNode("a"));
			span.setAttribute("style", "color: " + colorsfg[i]);
			span.style.width="100px";
			span.style.height="100px";
			root.appendChild(span);
		}
		return root;
	}
	this.rateSignature = function(hash, alg) {
		if (hash == "MD5") {
			return 0;
		} else if (hash == "SHA1") {
			return 0.4;
		} else if (hash == "SHA256") {
			return 0.8;
		} else if (hash == "SHA384") {
			return 0.9;
		} else if (hash == "SHA512") {
			return 1;
		} else {
			return -1;
		}
	};
	this.colorize = function(val) {
		var idx = Math.floor(val * (colorsbg.length - 1));
		return colorsbg[idx];
	};
	this.colorizeFG = function(val) {
		var idx = Math.floor(val * (colorsfg.length - 1));
		return colorsfg[idx];
	};
	this.widthize = function(val) {
		return 2 + val * 8;
	};
}
var rater = new Rater();