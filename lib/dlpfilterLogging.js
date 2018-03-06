/**
 * Copyright 2017, Google, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

// Imports the Google Cloud Data Loss Prevention library
const DLP = require('@google-cloud/dlp');
var winston = require('winston');
var fluentTransport = require('fluent-logger').support.winstonTransport();

var DlpLogger = function (){
    // Instantiates a client
    this.dlp = new DLP.DlpServiceClient();

    // The string to replace sensitive data with
    this.replaceString = 'REDACTED';

    // The minimum likelihood required before redacting a match
    this.minLikelihood = 'LIKELIHOOD_UNSPECIFIED';

    // The infoTypes of information to redact
    this.infoTypes = [{ name: 'US_MALE_NAME' }, { name: 'US_FEMALE_NAME' }, {name: 'EMAIL_ADDRESS'}];

    var winstonConfig = {
      host: 'localhost',
      port: 24224,
      timeout: 3.0,
      requireAckResponse: true // Add this option to wait response from Fluentd certainly
    };
        
    this.logger = new (winston.Logger)({
        transports: [new fluentTransport('dlpfilter', winstonConfig), new (winston.transports.Console)()]
    });

    this.logger.on('logging', (transport, level, message, meta) => {
      if (meta.end && transport.sender && transport.sender.end) {
        transport.sender.end();
      }
    });
};

DlpLogger.prototype.info = function(string,cb){
    const items = [{type: 'text/plain', value: string}];

    const replaceConfigs = this.infoTypes.map(infoType => {
      return {
        infoType: infoType,
        replaceWith: this.replaceString,
      };
    });

    const request = {
      inspectConfig: {
        infoTypes: this.infoTypes,
        minLikelihood: this.minLikelihood,
      },
      items: items,
      replaceConfigs: replaceConfigs,
    };

  this.dlp
        .redactContent(request)
        .then(body => {
            const results = body[0].items[0].value;
            this.logger.info(results);
            cb(results);
        })
        .catch(err => {
            cb(`Error in redactString: ${err.message || err}`);
        });    
};

module.exports.DlpLogger = DlpLogger;
