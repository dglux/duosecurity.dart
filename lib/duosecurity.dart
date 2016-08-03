library duosecurity;

import "dart:convert";

import "package:crypto/crypto.dart" as crypto;
import "package:convert/convert.dart" as convert;

String _getHMac(String key, String val) {  
  crypto.Hmac mac = new crypto.Hmac(crypto.sha1, UTF8.encode((key)));
  var bytes = mac.convert(UTF8.encode(val)).bytes;
  
  return convert.hex.encode(bytes);
}

String _signVals(String key, String vals, String prefix, int expire) {
  num exp = (new DateTime.now().millisecondsSinceEpoch / 1000).round() + expire;

  String val = "$vals|$exp";
  String b64 = BASE64.encode(UTF8.encode(val));
  String cookie = "$prefix|$b64";

  return "$cookie|${_getHMac(key, cookie)}";
}

String _parseVals(String key, String val, String prefix, String ikey) {
  num ts = (new DateTime.now().millisecondsSinceEpoch / 1000).round();

  List<String> parts = val.split("|");
  if (parts.length != 3) {
    return null;
  }

  String uPrefix = parts[0];
  String uB64 = parts[1];
  String uSig = parts[2];

  String sig = _getHMac(key, "$uPrefix|$uB64");

  if (_getHMac(key, sig) != _getHMac(key, uSig))
    return null;

  if (uPrefix != prefix)
    return null;

  List<String> cookieParts = UTF8.decode(BASE64.decode(uB64)).split("|");
  if (cookieParts.length != 3)
    return null;

  String user = cookieParts[0];
  String uikey = cookieParts[1];
  String exp = cookieParts[2];

  if (uikey != ikey)
    return null;

  if (ts >= int.parse(exp))
    return null;

  return user;
}

/**
 * Signs a login request to be passed onto Duo Security. Returns a Duo
 * signature.
 *
 * ikey is an integration key.
 * skey is a secret key.
 * akey is an application security key.
 * username.
 */
String signRequest(String ikey, String skey, String akey, String username) {
  String vals = "$username|$ikey";

  var duoSig = _signVals(skey, vals, "TX", 300);
  var appSig = _signVals(akey, vals, "APP", 3600);

  return "$duoSig:$appSig";
}

/**
 * Verifies a response from Duo Security. Will return a [String] containing the
 * username if the response is valid, and null otherwise.
 *
 * ikey is an integration key.
 * skey is a secret key.
 * akey is an application security key.
 * sigResponse is the signature response from Duo.
 */
String verifyResponse(String ikey, String skey, String akey, String sigResponse) {
  List<String> parts = sigResponse.split(":");
  if (parts.length != 2)
    return null;

  String authSig = parts[0];
  String appSig = parts[1];
  String authUser = _parseVals(skey, authSig, "AUTH", ikey);
  String appUser = _parseVals(akey, appSig, "APP", ikey);

  if (authUser != appUser)
    return null;

  return authUser;
}
