# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Sample app that uses the Data Loss Prevent API to redact the contents of
an image file."""

from __future__ import print_function

import argparse
# [START dlp_redact_image]
import mimetypes
# [END dlp_redact_image]
import os
# Import the client library
import google.cloud.dlp

# [START dlp_redact_image]

def redact_DocumentTypes(project, filename, output_filename, mime_type=None):
    """Uses the Data Loss Prevention API to redact protected data in an image.
    Args:
        project: The Google Cloud project id to use as a parent resource.
        filename: The path to the file to inspect.
        output_filename: The path to which the redacted image will be written.
        info_types: A list of strings representing info types to look for.
            A full list of info type categories can be fetched from the API.
        min_likelihood: A string representing the minimum likelihood threshold
            that constitutes a match. One of: 'LIKELIHOOD_UNSPECIFIED',
            'VERY_UNLIKELY', 'UNLIKELY', 'POSSIBLE', 'LIKELY', 'VERY_LIKELY'.
        mime_type: The MIME type of the file. If not specified, the type is
            inferred via the Python standard library's mimetypes module.
    Returns:
        None; the response from the API is printed to the terminal.
    """
   

    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "kubernetes-e9dc8af4883c.json"

    # Instantiate a client.
    dlp = google.cloud.dlp.DlpServiceClient()

    # Prepare info_types by converting the list of strings into a list of
    # dictionaries (protos are also accepted).
    #  info_types = [{'name': info_type} for info_type in info_types]

    # Prepare image_redaction_configs, a list of dictionaries. Each dictionary
    # contains an info_type and optionally the color used for the replacement.
    # The color is omitted in this sample, so the default (black) will be used.
    image_redaction_configs = []

    # if info_types is not None:
    #     for info_type in info_types:
    #         image_redaction_configs.append({'info_type': info_type})

    # Construct the configuration dictionary. Keys which are None may
    # optionally be omitted entirely.
    # inspect_config = {
    #     'min_likelihood': min_likelihood,
    #     'info_types': info_types,
    # }

    # If mime_type is not specified, guess it from the filename.
    if mime_type is None:
        mime_guess = mimetypes.MimeTypes().guess_type(filename)
        mime_type = mime_guess[0] or 'application/octet-stream'

    # Select the content type index from the list of supported types.
    supported_content_types = {
        None: 0,  # "Unspecified"
        'image/jpeg': 1,
        'image/bmp': 2,
        'image/png': 3,
        'image/svg': 4,
        'text/plain': 5,
    }
    content_type_index = supported_content_types.get(mime_type, 0)

    # Construct the byte_item, containing the file's byte data.
    with open(filename, mode='rb') as f:
        a = f.read()
        byte_item = {'type': content_type_index, 'data': a}

    print(byte_item)
    # Convert the project id into a full resource id.
    parent = dlp.project_path(project)

    # Call the API.
    # response = dlp.redact_image(
    #     parent, inspect_config=inspect_config,
    #     image_redaction_configs=image_redaction_configs,
    #     byte_item=byte_item)

    deidentify_config = {
            "info_type_transformations": {
                "transformations": [
                    {
                       "primitive_transformation": {
                            "replace_config": {
                                "new_value": {
                                    "string_value": "[XXXXXXXXXXXX]"
                                }
                            }
                        }
                    }
                ]
            }
        }


    inspect_config = {
    "info_types":[
      {
        "name":"ALL_BASIC"
      }
    ]
    }


    item = {
        "byte_item": byte_item
    }
    response = dlp.deidentify_content(parent, inspect_config=inspect_config, deidentify_config=deidentify_config, item=item)
    print(response.item.byte_item.data)
    # Write out the results.
    with open(output_filename, mode='wb') as f:
        f.write(response.item.byte_item.data)
    print('Written')
    # print("Wrote {byte_count} to {filename}".format(
    #     byte_count=len(response.redacted_image), filename=output_filename))

def redact_imageTypes(project,filename,output_filename,info_types,min_likelihood=None,mime_type=None):

   # os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "kubernetes-e9dc8af4883c.json"

    # Prepare info_types by converting the list of strings into a list of
    # dictionaries (protos are also accepted).
    info_types = [
      {
        "name":"ALL_BASIC"
      }]

    # Prepare image_redaction_configs, a list of dictionaries. Each dictionary
    # contains an info_type and optionally the color used for the replacement.
    # The color is omitted in this sample, so the default (black) will be used.
    image_redaction_configs = []

    if info_types is not None:
        for info_type in info_types:
            image_redaction_configs.append({'info_type': info_type})

    # Construct the configuration dictionary. Keys which are None may
    # optionally be omitted entirely.
    inspect_config = {
        'min_likelihood': min_likelihood,
        'info_types': info_types
    }

    # If mime_type is not specified, guess it from the filename.
    if mime_type is None:
        mime_guess = mimetypes.MimeTypes().guess_type(filename)
        mime_type = mime_guess[0] or 'application/octet-stream'

    # Select the content type index from the list of supported types.
    supported_content_types = {
        None: 0,  # "Unspecified"
        'image/jpeg': 1,
        'image/bmp': 2,
        'image/png': 3,
        'image/svg': 4,
        'text/plain': 5,
    }
    content_type_index = supported_content_types.get(mime_type, 0)

    # Construct the byte_item, containing the file's byte data.
    with open(filename, mode='rb') as f:
        a = f.read()
        byte_item = {'type': content_type_index, 'data': a}

    print(byte_item)
    # Convert the project id into a full resource id.
    parent = dlp.project_path(project)

    Call the API.
    response = dlp.redact_image(
        parent, inspect_config=inspect_config,
        image_redaction_configs=image_redaction_configs,
        byte_item=byte_item)

    
    # Write out the results.
    with open(output_filename, mode='wb') as f:
        f.write(response.item.byte_item.data)
    print('Written')
    # print("Wrote {byte_count} to {filename}".format(
    #     byte_count=len(response.redacted_image), filename=output_filename))
# [END dlp_redact_image]


if __name__ == '__main__':
  redact_DocumentTypes('kubernetes-218409', '/home/saikrishnam/resources/dlp.txt', '/home/saikrishnam/resources/dlpopt.txt')
  redact_imageTypes('kubernetes-218409','/home/saikrishnam/dlpfiler/resources/test.png','/home/saikrishnam/resources/dlp-output.png',info_type)


#     default_project = os.environ.get('GCLOUD_PROJECT')
#     parser = argparse.ArgumentParser(description=__doc__)
