<html><head><title>Shibboleth SP Redirecting</title>
<?php
	$memcache = memcache_connect('localhost', 11211);

	if ($memcache) 
	{
		parse_str($_SERVER['QUERY_STRING'], $_params);
		$attrs = explode("+", $_params['attrs']);
		for($a=0;$a<count($attrs);$a++) 
		{
			$memcache->set($_SERVER['Shib-Session-ID'].".".$attrs[$a], $_SERVER[$attrs[$a]]);
		}
	}
	else {
		echo "Connection to memcached failed";
	}
?>
<script language="javascript" type="text/javascript">
function getURLParameter(name) {
  return decodeURIComponent((new RegExp('[?|&]' + name + '=' + '([^&;]+?)(&|#|;|$)').exec(location.search)||[,""])[1].replace(/\+/g, '%20'))||null
}
var target=getURLParameter('target');
window.location.href = target;
</script>
</head>
<body>
</body>
</html>
