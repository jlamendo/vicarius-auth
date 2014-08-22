// Load modules

var Boom = require('boom');
var Hoek = require('hoek');


// Declare internals

var internals = {};


exports.register = function (plugin, options, next) {

    plugin.auth.scheme('vicariusAuth', internals.implementation);
    next();
};


exports.register.attributes = {
    pkg: require('./package.json')
};


internals.implementation = function (server, options) {

    Hoek.assert(options, 'Missing vicariusAuth auth strategy options');
    Hoek.assert(typeof options.validateFunc === 'function', 'options.validateFunc must be a valid function in vicariusAuth scheme');

    var settings = Hoek.clone(options);

    var scheme = {
        authenticate: function (request, reply) {
    var token;
    try{
        if(request.query.authToken !== undefined) {
        token = request.params.authToken;
        } else if(request.query.authToken !== undefined) {
            token = request.query.authToken;
        }else if (request.headers['X-Vicarius-Auth'] !== undefined){
           token = request.headers['X-Vicarius-Auth'];
        }
        if(token.length<=9) throw token;
    } catch(e){
        return reply(Boom.badImplementation(e), { log: { tags: 'credentials' } });
    }
            settings.validateFunc(token, function (err, isValid, credentials) {

                credentials = credentials || null;

                if (err) {
                    return reply(err, { credentials: credentials, log: { tags: ['auth', 'vicariusAuth'], data: err } });
                }

                if (!isValid) {
                    return reply(Boom.unauthorized('Bad username or password', 'vicariusAuth'), { credentials: credentials });
                }

                if (!credentials ||
                    typeof credentials !== 'object') {

                    return reply(Boom.badImplementation('Bad credentials object received for vicariusAuth auth validation'), { log: { tags: 'credentials' } });
                }

                // Authenticated

                return reply(null, { credentials: credentials });
            });
        }
    };

    return scheme;
};


