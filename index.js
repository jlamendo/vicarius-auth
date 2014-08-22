var hat = require('hat');
var Basic = require('hapi-auth-basic');


String.prototype.toHex = function() {
  return parseInt(new Buffer(this).toString('hex'), 16);
}

var ConfDB = (function() {
  var _ = require('underscore');
  var fs = require('fs');

  if (!fs.existsSync + process.env['VICARIUS_DIR'] + '/config/custom.json') {
    fs.writeFileSync(process.env['VICARIUS_DIR'] + '/config/custom.json', fs.readFileSync(process.env['VICARIUS_DIR'] + '/config/default.json').toString());
  }
  var fileName = process.env['VICARIUS_DIR'] + '/config/custom.json'

  return function(dataDir) {
    var _this = this;
    this.data = require(fileName);
    this.save = function(newConf) {
      if (!_this.data) _this.data = require(fileName) || {};
      _this.data = _.extend(_this.data, newConf);
      fs.writeFileSync(fileName, JSON.stringify(_this.data))
      return _this.data;
    }
  }
})();

var Secure = function() {
  var _this = this;
  this.setChallengedValue = function(challengedValue) {
    challengedValue = new Buffer(challengedValue).toString('hex');
    _this.challengedValue = parseInt(challengedValue, 16);
  }
  this.compare = function(compareValue, challengedValue) {
    if (!challengedValue) {
      challengedValue = _this.challengedValue;
    } else {
      challengedValue = challengedValue.toHex();
    }
    compareValue = new Buffer(compareValue).toString('hex');
    compareValue = parseInt(compareValue, 16);
    return ((challengedValue ^ compareValue) == true)
  }
}
var Auth = function(confDB) {
  var _this = this;
  if (!confDB) {
    _this.confDB = new ConfDB();
  }
  // Retrieve hex representation of authtoken from config
  _this.username = _this.confDB.data.user.username;
  _this.secure = new Secure();
  _this.secure.setChallengedValue(_this.confDB.data.user.authToken);
  this.validateMiddleWare = function(request, reply, cb) {
    if (_this.secure.compare(request.params.authToken)) {
      return cb(request, reply);
    } else reply().code(401)
  }
  this.cycleToken = function() {
    var newConf = _this.confDB.data;
    newConf.user.authToken = hat(64);
    _this.secure.setChallengedValue(newConf.user.authToken);
    _this.confDB.save(newConf);
    return newConf.user.authToken;
  }
}



var auth = new Auth()

var validate = function(username, password, callback) {
  if (auth.secure.compare(username, auth.username)) {
    if (auth.secure.compare(password)) {
      return callback(err, true, {
        username: username
      });
    }
  }
  return callback(null, false);
};

module.exports = function(server) {
  server.pack.register(Basic, function(err) {
    if (err) throw err;
    server.auth.strategy('token', 'basic', true, {
      validateFunc: validate,
    });
  });
  return auth;
}



