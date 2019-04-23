const winston = require('winston');
const fluentTransport = require('fluent-logger').support.winstonTransport();

var Logger = function() {
    const winstonConfig = {
      host: 'localhost',
      port: 24224,
      timeout: 3.0,
      requireAckResponse: true // Add this option to wait response from Fluentd certainly
    };   
      this.logger = winston.createLogger({
        transports: [new fluentTransport('dlpfilter', winstonConfig), new (winston.transports.Console)()]
    });

    this.logger.on('logging', (transport, level, message, meta) => {
      if (meta.end && transport.sender && transport.sender.end) {
        transport.sender.end();
      }
    });
};

Logger.prototype.info = function (string, cb) {
        this.logger.info(string);
        cb(string);
};

module.exports.Logger = Logger;
