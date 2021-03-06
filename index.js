var hat = require('hat');
var vicariusAuth = require('./hapi-auth-vicarius');


var ConfDB = (function() {
  var _ = require('underscore');
  var fs = require('fs');

  if (!fs.existsSync(process.env['VICARIUS_DIR'] + '/config/custom.json')) {
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
      _this.challengedValue = challengedValue;
    }
    this.compare = function(compareValue, challengedValue) {
      if (!challengedValue) {
        challengedValue = _this.challengedValue;
      }
      compareValue = String(compareValue);
      challengedValue = String(challengedValue);
      if (compareValue.length !== challengedValue.length) {
        return false;
      }
      var result = 0;
      for (var i = 0; i < compareValue.length; ++i) {
        result |= compareValue.charCodeAt(i) ^ challengedValue.charCodeAt(i);
      }
      return result === 0;
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
        newConf.user.authToken = hat();
        _this.secure.setChallengedValue(newConf.user.authToken);
        _this.confDB.save(newConf);
        return newConf.user.authToken;
      }
    }

    var auth = new Auth()

    var validate = function(token, callback) {
      if (auth.secure.compare(token)) {
        return callback(null, true, {
          username: auth.username
        });
      }
      return callback(null, false);
    };

    module.exports = function(server) {
      server.pack.register(vicariusAuth, function(err) {
        if (err) throw err;
        server.auth.strategy('authToken', 'vicariusAuth', true, {
          validateFunc: validate,
        });
      });
      return auth;
    }