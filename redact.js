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


// The project ID to run the API call under
  const callingProjectId = process.env.GCLOUD_PROJECT;

  // The path to a local file to inspect. Can be a JPG or PNG image file.
   const filepath = 'resources/';

  // The minimum likelihood required before redacting a match
   const minLikelihood = 'LIKELIHOOD_UNSPECIFIED';

  // The infoTypes of information to redact
   const infoTypes = [{ name: 'EMAIL_ADDRESS' }, 
   {name: 'PHONE_NUMBER' },
   {name: 'AMERICAN_BANKERS_CUSIP_ID'},
   {name: 'AUSTRALIA_MEDICARE_NUMBER'},
   {name: 'AUSTRALIA_TAX_FILE_NUMBER'},
   {name: 'BRAZIL_CPF_NUMBER'},
   {name: 'CANADA_BC_PHN'},
   {name: 'CANADA_DRIVERS_LICENSE_NUMBER'},
   {name: 'CANADA_OHIP'},
   {name: 'CANADA_PASSPORT'},
   {name: 'CANADA_QUEBEC_HIN'},
   {name: 'CANADA_SOCIAL_INSURANCE_NUMBER'},
   {name: 'CHINA_PASSPORT'},
   {name: 'CREDIT_CARD_NUMBER'},
   {name: 'EMAIL_ADDRESS'},
   {name: 'ETHNIC_GROUP'},
   {name: 'FEMALE_NAME'},
   {name: 'FIRST_NAME'},
   {name: 'FRANCE_CNI'},
   {name: 'FRANCE_NIR'},
   {name: 'FRANCE_PASSPORT'},
   {name: 'GCP_CREDENTIALS'},
   {name: 'GERMANY_PASSPORT'},
   {name: 'IBAN_CODE'},
   {name: 'IMEI_HARDWARE_ID'},
   {name: 'INDIA_PAN_INDIVIDUAL'},
   {name: 'IP_ADDRESS'},
   {name: 'JAPAN_INDIVIDUAL_NUMBER'},
   {name: 'JAPAN_PASSPORT'},
   {name: 'KOREA_PASSPORT'},
   {name: 'KOREA_RRN'},
   {name: 'LAST_NAME'},
   {name: 'MAC_ADDRESS_LOCAL'},
   {name: 'MAC_ADDRESS'},
   {name: 'MALE_NAME'},
   {name: 'MEXICO_CURP_NUMBER'},
   {name: 'MEXICO_PASSPORT'},
   {name: 'NETHERLANDS_BSN_NUMBER'},
   {name: 'PHONE_NUMBER'},
   {name: 'SPAIN_NIE_NUMBER'},
   {name: 'SPAIN_NIF_NUMBER'},
   {name: 'SPAIN_PASSPORT'},
   {name: 'SWIFT_CODE'},
   {name: 'UK_DRIVERS_LICENSE_NUMBER'},
   {name: 'UK_NATIONAL_HEALTH_SERVICE_NUMBER'},
   {name: 'UK_NATIONAL_INSURANCE_NUMBER'},
   {name: 'UK_PASSPORT'},
   {name: 'UK_TAXPAYER_REFERENCE'},
   {name: 'US_ADOPTION_TAXPAYER_IDENTIFICATION_NUMBER'},
   {name: 'US_BANK_ROUTING_MICR'},
   {name: 'US_DEA_NUMBER'},
   {name: 'US_DRIVERS_LICENSE_NUMBER'},
   {name: 'US_HEALTHCARE_NPI'},
   {name: 'US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER'},
   {name: 'US_PASSPORT'},
   {name: 'US_PREPARER_TAXPAYER_IDENTIFICATION_NUMBER'},
   {name: 'US_SOCIAL_SECURITY_NUMBER'},
   {name: 'US_TOLLFREE_PHONE_NUMBER'},
   {name: 'US_VEHICLE_IDENTIFICATION_NUMBER'},
   {name: 'US_STATE'},
   {name: 'FDA_CODE'},
   {name: 'ICD9_CODE'},
   {name: 'ICD10_CODE'},
   {name: 'US_EMPLOYER_IDENTIFICATION_NUMBER'},
   {name: 'LOCATION'},
   {name: 'DATE'},
   {name: 'DATE_OF_BIRTH'},
   {name: 'TIME'},
   {name: 'PERSON_NAME'},
   {name: 'AGE'},
   {name: 'GENDER'},
   {name: 'ARGENTINA_DNI_NUMBER'},
   {name: 'CHILE_CDI_NUMBER'},
   {name: 'COLOMBIA_CDC_NUMBER'},
   {name: 'NETHERLANDS_PASSPORT'},
   {name: 'PARAGUAY_CIC_NUMBER'},
   {name: 'PERU_DNI_NUMBER'},
   {name: 'PORTUGAL_CDC_NUMBER'},
   {name: 'URUGUAY_CDI_NUMBER'},
   {name: 'VENEZUELA_CDI_NUMBER'},
 ];

  // The local path to save the resulting image to.
   const outputPath = 'result.png';


async function redactText(callingProjectId, string, minLikelihood, infoTypes) {
  // [START dlp_redact_text]
  // Imports the Google Cloud Data Loss Prevention library
  const DLP = require('@google-cloud/dlp');

  // Instantiates a client
  const dlp = new DLP.DlpServiceClient();

  // Construct transformation config which replaces sensitive info with its info type.
  // E.g., "Her email is xxx@example.com" => "Her email is [EMAIL_ADDRESS]"
  const replaceWithInfoTypeTransformation = {
    primitiveTransformation: {
      replaceWithInfoTypeConfig: {},
    },
  };

  // Construct redaction request
  const request = {
    parent: dlp.projectPath(callingProjectId),
    item: {
      value: string,
    },
    deidentifyConfig: {
      infoTypeTransformations: {
        transformations: [replaceWithInfoTypeTransformation],
      },
    },
    inspectConfig: {
      minLikelihood: minLikelihood,
      infoTypes: infoTypes,
    },
  };

  // Run string redaction
  try {
    const [response] = await dlp.deidentifyContent(request);
    const resultString = response.item.value;
    console.log(`Redacted text: ${resultString}`);
  } catch (err) {
    console.log(`Error in deidentifyContent: ${err.message || err}`);
  }

  // [END dlp_redact_text]
}

async function redactImage(
  callingProjectId,
  filepath,
  minLikelihood,
  infoTypes,
  outputPath
) {
  // [START dlp_redact_image]
  // Imports the Google Cloud Data Loss Prevention library
  const DLP = require('@google-cloud/dlp');

  // Imports required Node.js libraries
  const mime = require('mime');
  const fs = require('fs');

  // Instantiates a client
  const dlp = new DLP.DlpServiceClient();

  // The project ID to run the API call under
  // const callingProjectId = process.env.GCLOUD_PROJECT;

  // The path to a local file to inspect. Can be a JPG or PNG image file.
  // const filepath = 'path/to/image.png';

  // The minimum likelihood required before redacting a match
  // const minLikelihood = 'LIKELIHOOD_UNSPECIFIED';

  // The infoTypes of information to redact
  // const infoTypes = [{ name: 'EMAIL_ADDRESS' }, { name: 'PHONE_NUMBER' }];

  // The local path to save the resulting image to.
  // const outputPath = 'result.png';

  const imageRedactionConfigs = infoTypes.map(infoType => {
    return {infoType: infoType};
  });

  // Load image
  const fileTypeConstant =
    ['image/jpeg', 'image/bmp', 'image/png', 'image/svg'].indexOf(
      mime.getType(filepath)
    ) + 1;
  const fileBytes = Buffer.from(fs.readFileSync(filepath)).toString('base64');

  // Construct image redaction request
  const request = {
    parent: dlp.projectPath(callingProjectId),
    byteItem: {
      type: fileTypeConstant,
      data: fileBytes,
    },
    inspectConfig: {
      minLikelihood: minLikelihood,
      infoTypes: infoTypes,
    },
    imageRedactionConfigs: imageRedactionConfigs,
  };

  // Run image redaction request
  try {
    const [response] = await dlp.redactImage(request);
    const image = response.redactedImage;
    fs.writeFileSync(outputPath, image);
    console.log(`Saved image redaction results to path: ${outputPath}`);
  } catch (err) {
    console.log(`Error in redactImage: ${err.message || err}`);
  }

  // [END dlp_redact_image]
}
